{
        validate(query, false)?;
        let header = Header::parse(query)?;
        let question = first_question(query)?;
        if let Some(ifindex) = ifindex.filter(|value| *value < 0) {
            return Err(LinkError::InvalidIfindex(ifindex).into());
        }
        self.counters.transactions.fetch_add(1, Ordering::Relaxed);

        if mode == QueryMode::Full {
            if let Some(response) =
                crate::static_records::answer(self.config.read_static_records, query)?
            {
                self.counters.local_answers.fetch_add(1, Ordering::Relaxed);
                return Ok(response);
            }
            if let Some(records) = self.hosts().lookup(&question) {
                self.counters.local_answers.fetch_add(1, Ordering::Relaxed);
                return Ok(local_response(query, &records, 0)?);
            }
        }

        let route_generation = self.routing_generation.load(Ordering::Acquire);
        let route = route_cache_id(route_generation, ifindex);
        let key = CacheKey {
            name: question.name.canonical_wire().to_vec(),
            rr_type: question.rr_type,
            class: question.class,
            checking_disabled: header.checking_disabled(),
            route,
        };
        if self.config.cache {
            if let Some(response) = self.cache.get(&key, header.id, false) {
                self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(response);
            }
            self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        let scopes = self.routing().select(
            question.name.text(),
            ifindex,
            &self.global_servers,
            &self.fallback_servers,
            &self.config.domains,
        )?;
        if scopes.is_empty() {
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
            return Err(ResolveError::NoNameServers);
        }

        let inflight_key = InflightKey::new(route, query)?;
        loop {
            match self.inflight.begin(inflight_key.clone()) {
                InflightRole::Leader(transaction_leader) => {
                    let result = match self.query_scopes(&scopes, query) {
                        Ok(response) => {
                            if self.config.cache {
                                let _ = self.cache.insert(key.clone(), &response);
                            }
                            Ok(response)
                        }
                        Err(error) => {
                            if self.config.cache {
                                if let Some(response) = self.cache.get(&key, header.id, true) {
                                    self.counters
                                        .cache_hits
                                        .fetch_add(1, Ordering::Relaxed);
                                    transaction_leader.complete(normalize_shared_response(&response));
                                    return Ok(response);
                                }
                            }
                            self.counters.failures.fetch_add(1, Ordering::Relaxed);
                            Err(error)
                        }
                    };
                    transaction_leader.complete(
                        result
                            .as_ref()
                            .ok()
                            .and_then(|response| normalize_shared_response(response)),
                    );
                    return result;
                }
                InflightRole::Follower(entry) => {
                    if let Some(mut response) = entry.wait() {
                        wire::rewrite_id(&mut response, header.id)?;
                        return Ok(response);
                    }
                }
            }
        }
    }
