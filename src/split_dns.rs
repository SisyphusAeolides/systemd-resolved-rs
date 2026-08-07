//! Longest-suffix split-DNS routing + VPN no-leak.

#[derive(Clone, Debug)]
pub struct DomainRule {
    pub suffix: String,
    pub ifindex: i32,
    pub search: bool,
    pub route_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pick {
    Links(Vec<i32>),
    DefaultRoute,
    Blackhole,
}

pub fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn pick_links_for_name(
    name: &str,
    rules: &[DomainRule],
    default_route_links: &[i32],
    allow_default: bool,
) -> Pick {
    let n = normalize_name(name);
    let mut best_len: isize = -1;
    let mut hits: Vec<i32> = Vec::new();

    for r in rules {
        let d = normalize_name(&r.suffix);
        if d.is_empty() || d == "." {
            continue;
        }
        let matched = n == d || n.ends_with(&format!(".{}", d));
        if !matched {
            continue;
        }
        let len = d.len() as isize;
        if len > best_len {
            best_len = len;
            hits.clear();
            hits.push(r.ifindex);
        } else if len == best_len && !hits.contains(&r.ifindex) {
            hits.push(r.ifindex);
        }
    }

    if !hits.is_empty() {
        hits.sort_unstable();
        return Pick::Links(hits);
    }
    if allow_default {
        let _ = default_route_links;
        Pick::DefaultRoute
    } else {
        Pick::Blackhole
    }
}

pub fn expand_search(name: &str, search: &[String], ndots: usize) -> Vec<String> {
    let raw = name.trim();
    if raw.ends_with('.') {
        return vec![normalize_name(raw)];
    }
    let n = normalize_name(raw);
    let dots = n.chars().filter(|c| *c == '.').count();
    let mut out = Vec::new();
    if dots >= ndots {
        out.push(n.clone());
    }
    for s in search {
        let s = normalize_name(s);
        if !s.is_empty() {
            out.push(format!("{}.{}", n, s));
        }
    }
    if dots < ndots {
        out.push(n);
    }
    out.dedup();
    out
}
