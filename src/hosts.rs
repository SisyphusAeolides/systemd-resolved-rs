// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::wire::{parse_reverse_name, LocalRecord, Question, CLASS_ANY, CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_PTR};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct Hosts {
    by_name: HashMap<String, Vec<IpAddr>>,
    by_address: HashMap<IpAddr, Vec<String>>,
}

impl Hosts {
    pub fn load(path: &Path) -> io::Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut hosts = Self::default();
        for raw_line in text.lines() {
            let line = raw_line.split_once('#').map_or(raw_line, |(head, _)| head);
            let mut fields = line.split_whitespace();
            let Some(address) = fields.next().and_then(|field| field.parse::<IpAddr>().ok()) else {
                continue;
            };
            for name in fields {
                let canonical = canonical_name(name);
                if canonical.is_empty() {
                    continue;
                }
                let addresses = hosts.by_name.entry(canonical.clone()).or_default();
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
                let names = hosts.by_address.entry(address).or_default();
                if !names.contains(&canonical) {
                    names.push(canonical);
                }
            }
        }
        hosts
    }

    pub fn lookup(&self, question: &Question) -> Option<Vec<LocalRecord>> {
        if question.class != CLASS_IN && question.class != CLASS_ANY {
            return None;
        }
        match question.rr_type {
            TYPE_A | TYPE_AAAA | 255 => self.lookup_forward(question),
            TYPE_PTR => self.lookup_reverse(question),
            _ => self.known_name(question.name.text()).then(Vec::new),
        }
    }

    fn lookup_forward(&self, question: &Question) -> Option<Vec<LocalRecord>> {
        let name = canonical_name(question.name.text());
        let mut addresses = synthetic_addresses(&name);
        if let Ok(address) = name.parse::<IpAddr>() {
            addresses.push(address);
        }
        if let Some(host_addresses) = self.by_name.get(&name) {
            for address in host_addresses {
                if !addresses.contains(address) {
                    addresses.push(*address);
                }
            }
        }
        if addresses.is_empty() {
            return None;
        }

        let records = addresses
            .into_iter()
            .filter_map(|address| match (question.rr_type, address) {
                (TYPE_A | 255, IpAddr::V4(address)) => Some(LocalRecord::A(address)),
                (TYPE_AAAA | 255, IpAddr::V6(address)) => Some(LocalRecord::Aaaa(address)),
                _ => None,
            })
            .collect();
        Some(records)
    }

    fn lookup_reverse(&self, question: &Question) -> Option<Vec<LocalRecord>> {
        let address = parse_reverse_name(question.name.text())?;
        let mut names = synthetic_names(address);
        if let Some(host_names) = self.by_address.get(&address) {
            for name in host_names {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }
        if names.is_empty() {
            return None;
        }
        Some(names.into_iter().map(LocalRecord::Ptr).collect())
    }

    fn known_name(&self, name: &str) -> bool {
        let name = canonical_name(name);
        self.by_name.contains_key(&name)
            || !synthetic_addresses(&name).is_empty()
            || name.parse::<IpAddr>().is_ok()
    }
}

fn canonical_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn synthetic_addresses(name: &str) -> Vec<IpAddr> {
    match name {
        "localhost" | "localhost.localdomain" => {
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)]
        }
        "localhost4" | "localhost4.localdomain4" => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "localhost6" | "localhost6.localdomain6" => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        "_localdnsstub" => vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))],
        "_localdnsproxy" => vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 54))],
        _ => Vec::new(),
    }
}

fn synthetic_names(address: IpAddr) -> Vec<String> {
    match address {
        IpAddr::V4(address) if address == Ipv4Addr::LOCALHOST => vec!["localhost".to_owned()],
        IpAddr::V6(address) if address == Ipv6Addr::LOCALHOST => vec!["localhost".to_owned()],
        IpAddr::V4(address) if address == Ipv4Addr::new(127, 0, 0, 53) => {
            vec!["_localdnsstub".to_owned()]
        }
        IpAddr::V4(address) if address == Ipv4Addr::new(127, 0, 0, 54) => {
            vec!["_localdnsproxy".to_owned()]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{first_question, make_query};

    #[test]
    fn parses_aliases_and_reverse_entries() {
        let hosts = Hosts::parse("192.0.2.10 host.example alias.example\n");
        let query = make_query("alias.example", TYPE_A, 1).expect("query");
        let records = hosts
            .lookup(&first_question(&query).expect("question"))
            .expect("local answer");
        assert_eq!(records, vec![LocalRecord::A(Ipv4Addr::new(192, 0, 2, 10))]);
    }

    #[test]
    fn numeric_address_is_answered_locally() {
        let hosts = Hosts::default();
        let query = make_query("192.0.2.15", TYPE_A, 1).expect("query");
        let records = hosts
            .lookup(&first_question(&query).expect("question"))
            .expect("local answer");
        assert_eq!(records, vec![LocalRecord::A(Ipv4Addr::new(192, 0, 2, 15))]);
    }

    #[test]
    fn synthesizes_stub_address() {
        let hosts = Hosts::default();
        let query = make_query("_localdnsstub", TYPE_A, 1).expect("query");
        assert!(hosts
            .lookup(&first_question(&query).expect("question"))
            .is_some());
    }
}
