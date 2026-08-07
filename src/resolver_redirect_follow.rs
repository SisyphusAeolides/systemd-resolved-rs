const CNAME_LOOP_PROTOCOL_ERROR: &str = "CNAME or DNAME redirect loop";

impl Resolver {
    fn query_following_redirects(
        &self,
        name: &str,
        class: u16,
        rr_type: u16,
        ifindex: Option<i32>,
    ) -> Result<(Vec<u8>, String), ResolveError> {
        let mut current = name.to_owned();
        let mut visited = HashSet::new();
        let mut redirects = 0usize;

        loop {
            let query =
                make_query_with_class(&current, rr_type, class, self.transaction_id())?;
            let question = first_question(&query)?;
            if !visited.insert(question.name.canonical_wire().to_vec()) {
                return Err(ResolveError::Wire(WireError::CnameLoop));
            }

            let response = self.query_on_link(&query, QueryMode::Full, ifindex)?;
            let rcode = Header::parse(&response)?.response_code();
            if rcode != 0 {
                return Err(ResolveError::DnsError {
                    rcode,
                    query: current,
                });
            }
            match wire::classify_redirect_answer(&response)? {
                wire::RedirectAnswer::Direct {
                    canonical_name,
                    redirects: packet_redirects,
                } => {
                    redirects = redirects
                        .checked_add(packet_redirects)
                        .ok_or(ResolveError::Wire(WireError::CnameLoop))?;
                    if redirects > wire::CNAME_REDIRECTS_MAX {
                        return Err(ResolveError::Wire(WireError::CnameLoop));
                    }
                    return Ok((response, canonical_name));
                }
                wire::RedirectAnswer::Redirect {
                    canonical_name,
                    redirects: packet_redirects,
                } => {
                    if packet_redirects == 0 {
                        return Err(ResolveError::Protocol(CNAME_LOOP_PROTOCOL_ERROR));
                    }
                    redirects = redirects
                        .checked_add(packet_redirects)
                        .ok_or(ResolveError::Wire(WireError::CnameLoop))?;
                    if redirects > wire::CNAME_REDIRECTS_MAX {
                        return Err(ResolveError::Wire(WireError::CnameLoop));
                    }
                    current = canonical_name;
                }
                wire::RedirectAnswer::NoData => {
                    return Err(ResolveError::NoSuchResourceRecord);
                }
            }
        }
    }
}
