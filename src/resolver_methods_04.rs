impl Resolver {
    fn take_udp_socket(&self, server: SocketAddr) -> Result<UdpSocket, ResolveError> {
        let pooled = {
            let mut sockets = self
                .udp_sockets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sockets.get_mut(&server).and_then(Vec::pop)
        };

        let socket = if let Some(socket) = pooled {
            socket
        } else {
            let bind_address = if server.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            let socket = UdpSocket::bind(bind_address)?;
            socket.connect(server)?;
            let _ = native::enable_udp_fragment_size(socket.as_raw_fd(), server.is_ipv6());
            socket
        };

        socket.set_read_timeout(Some(self.config.query_timeout))?;
        socket.set_write_timeout(Some(self.config.query_timeout))?;
        Ok(socket)
    }

    fn recycle_udp_socket(&self, server: SocketAddr, socket: UdpSocket) {
        let mut sockets = self
            .udp_sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pool = sockets.entry(server).or_default();
        if pool.len() < UDP_POOL_PER_SERVER_MAX {
            pool.push(socket);
        }
    }

    fn exchange_udp(
        &self,
        server: SocketAddr,
        query: &[u8],
    ) -> Result<(Vec<u8>, u32), ResolveError> {
        let socket = self.take_udp_socket(server)?;
        let result = (|| {
            if socket.send(query)? != query.len() {
                return Err(ResolveError::Protocol("short UDP send"));
            }

            let started = Instant::now();
            let mut response = vec![0; usize::from(u16::MAX)];
            loop {
                let Some(remaining) = self.config.query_timeout.checked_sub(started.elapsed()) else {
                    return Err(
                        io::Error::new(io::ErrorKind::TimedOut, "DNS UDP query timed out").into(),
                    );
                };
                if remaining.is_zero() {
                    return Err(
                        io::Error::new(io::ErrorKind::TimedOut, "DNS UDP query timed out").into(),
                    );
                }
                socket.set_read_timeout(Some(remaining))?;
                let (length, fragment_size) = native::udp_recv(socket.as_raw_fd(), &mut response)?;
                if response_matches(query, &response[..length]).is_err() {
                    continue;
                }
                response.truncate(length);
                return Ok((response, fragment_size));
            }
        })();

        if result.is_ok() {
            self.recycle_udp_socket(server, socket);
        }
        result
    }

    fn udp_path_mtu(&self, server: SocketAddr) -> Option<u32> {
        let socket = self.take_udp_socket(server).ok()?;
        let result = native::udp_path_mtu(socket.as_raw_fd(), server.is_ipv6()).ok();
        self.recycle_udp_socket(server, socket);
        result
    }

    fn new_tcp_stream(&self, server: SocketAddr) -> Result<TcpStream, ResolveError> {
        let stream = TcpStream::connect_timeout(&server, self.config.query_timeout)?;
        stream.set_read_timeout(Some(self.config.query_timeout))?;
        stream.set_write_timeout(Some(self.config.query_timeout))?;
        Ok(stream)
    }

    fn take_tcp_stream(&self, server: SocketAddr) -> Result<(TcpStream, bool), ResolveError> {
        let pooled = {
            let mut streams = self
                .tcp_streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            streams.get_mut(&server).and_then(Vec::pop)
        };
        let reused = pooled.is_some();
        let stream = match pooled {
            Some(stream) => stream,
            None => self.new_tcp_stream(server)?,
        };
        stream.set_read_timeout(Some(self.config.query_timeout))?;
        stream.set_write_timeout(Some(self.config.query_timeout))?;
        Ok((stream, reused))
    }

    fn recycle_tcp_stream(&self, server: SocketAddr, stream: TcpStream) {
        let mut streams = self
            .tcp_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pool = streams.entry(server).or_default();
        if pool.len() < TCP_POOL_PER_SERVER_MAX {
            pool.push(stream);
        }
    }

    fn exchange_tcp_stream(
        stream: &mut TcpStream,
        query: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let query_length = u16::try_from(query.len())
            .map_err(|_| ResolveError::Protocol("DNS query exceeds the TCP frame limit"))?;
        stream.write_all(&query_length.to_be_bytes())?;
        stream.write_all(query)?;

        let mut length = [0; 2];
        stream.read_exact(&mut length)?;
        let length = usize::from(u16::from_be_bytes(length));
        if length < wire::DNS_HEADER_LEN {
            return Err(ResolveError::Protocol("short DNS-over-TCP frame"));
        }
        let mut response = vec![0; length];
        stream.read_exact(&mut response)?;
        response_matches(query, &response)?;
        Ok(response)
    }

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolveError> {
        let (mut stream, reused) = self.take_tcp_stream(server)?;
        let result = Self::exchange_tcp_stream(&mut stream, query);
        if result.is_ok() {
            self.recycle_tcp_stream(server, stream);
            return result;
        }
        if !reused {
            return result;
        }

        let mut fresh = self.new_tcp_stream(server)?;
        let result = Self::exchange_tcp_stream(&mut fresh, query);
        if result.is_ok() {
            self.recycle_tcp_stream(server, fresh);
        }
        result
    }

    pub fn lookup_name(&self, name: &str, family: i32) -> Result<NameLookup, ResolveError> {
        self.lookup_name_on_link(name, family, None)
    }

    pub fn lookup_name_on_link(
        &self,
        name: &str,
        family: i32,
        ifindex: Option<i32>,
    ) -> Result<NameLookup, ResolveError> {
        let types: &[u16] = match family {
            0 => &[TYPE_A, TYPE_AAAA],
            2 => &[TYPE_A],
            10 => &[TYPE_AAAA],
            _ => return Err(ResolveError::UnsupportedFamily(family)),
        };
        if self.has_local_name(name, types)? {
            return self.lookup_name_exact(name, types, ifindex);
        }

        let domains = self.search_domains(ifindex)?;
        let candidates =
            lookup_candidates(name, &domains, self.config.resolve_unicast_single_label);
        let mut last_error = None;
        for candidate in candidates {
            match self.lookup_name_exact(&candidate, types, ifindex) {
                Ok(result) => return Ok(result),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(ResolveError::NoSuchResourceRecord))
    }

    fn has_local_name(&self, name: &str, types: &[u16]) -> Result<bool, ResolveError> {
        let hosts = self.hosts();
        for &rr_type in types {
            let query = make_query(name, rr_type, 0)?;
            let question = first_question(&query)?;
            if hosts.lookup(&question).is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
