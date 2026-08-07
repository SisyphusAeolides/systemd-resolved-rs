impl Resolver {
    fn lookup_name_exact(
        &self,
        name: &str,
        types: &[u16],
        ifindex: Option<i32>,
    ) -> Result<NameLookup, ResolveError> {
        let outcomes = if types.len() > 1 {
            thread::scope(|thread_scope| {
                let (sender, receiver) = mpsc::channel();
                for (index, &rr_type) in types.iter().enumerate() {
                    let sender = sender.clone();
                    thread_scope.spawn(move || {
                        let result =
                            self.query_following_redirects(name, wire::CLASS_IN, rr_type, ifindex);
                        let _ = sender.send((index, rr_type, result));
                    });
                }
                drop(sender);

                let mut outcomes: Vec<_> = receiver.into_iter().collect();
                outcomes.sort_by_key(|(index, _, _)| *index);
                outcomes
                    .into_iter()
                    .map(|(_, rr_type, result)| (rr_type, result))
                    .collect::<Vec<_>>()
            })
        } else {
            types
                .iter()
                .copied()
                .map(|rr_type| {
                    (
                        rr_type,
                        self.query_following_redirects(name, wire::CLASS_IN, rr_type, ifindex),
                    )
                })
                .collect()
        };

        let mut addresses = Vec::new();
        let mut canonical_name = None;
        let mut last_error = None;
        for (rr_type, result) in outcomes {
            match result {
                Ok((response, followed_name)) => {
                    let response_family = match rr_type {
                        TYPE_A => Some(2),
                        TYPE_AAAA => Some(10),
                        _ => None,
                    };
                    let records = extract_address_records(&response, response_family)?;
                    if !records.addresses.is_empty() && canonical_name.is_none() {
                        canonical_name = Some(if records.canonical_name.is_empty() {
                            followed_name
                        } else {
                            records.canonical_name
                        });
                    }
                    for address in records.addresses {
                        if !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        if addresses.is_empty() {
            return Err(last_error.unwrap_or(ResolveError::NoSuchResourceRecord));
        }
        Ok(NameLookup {
            addresses,
            canonical_name: canonical_name.unwrap_or_else(|| name.trim_end_matches('.').to_owned()),
            flags: 0,
        })
    }
}
