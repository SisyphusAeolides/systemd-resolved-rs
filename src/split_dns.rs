//! `src/split_dns.rs`
//! - longest suffix match on search/route-only domains
//! - `~.` default route flag per link
//! - domain with routing-only (no search) vs search
//! - VPN leak prevention: never send corp.domain to uplink if link route exists

#[derive(Clone, Debug)]
pub struct DomainRoute {
    pub domain: String, // "corp.example" or "."
    pub ifindex: i32,
    pub search: bool,
    pub route_only: bool,
}

pub fn pick_links_for_name(
    name: &str,
    routes: &[DomainRoute],
    default_route_links: &[i32],
) -> Vec<i32> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let mut best_len = -1isize;
    let mut hits = Vec::new();
    for r in routes {
        let d = r.domain.trim_end_matches('.').to_ascii_lowercase();
        if d == "." || d.is_empty() {
            continue;
        }
        if n == d || n.ends_with(&format!(".{d}")) {
            let len = d.len() as isize;
            if len > best_len {
                best_len = len;
                hits.clear();
                hits.push(r.ifindex);
            } else if len == best_len {
                hits.push(r.ifindex);
            }
        }
    }
    if hits.is_empty() {
        default_route_links.to_vec()
    } else {
        hits.sort_unstable();
        hits.dedup();
        hits
    }
}
