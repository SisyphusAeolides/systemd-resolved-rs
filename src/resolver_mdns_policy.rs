impl Resolver {
    pub fn multicast_dns_mode_for_link(&self, ifindex: Option<i32>) -> SupportMode {
        if let Some(ifindex) = ifindex {
            if let Some(link) = self.link(ifindex) {
                return link.multicast_dns;
            }
        }
        self.config().multicast_dns
    }

    pub fn multicast_dns_resolve_enabled(&self, ifindex: Option<i32>) -> bool {
        !matches!(self.multicast_dns_mode_for_link(ifindex), SupportMode::No)
    }

    pub fn multicast_dns_respond_enabled(&self, ifindex: i32) -> bool {
        matches!(
            self.multicast_dns_mode_for_link(Some(ifindex)),
            SupportMode::Yes
        )
    }
}

#[cfg(test)]
mod mdns_policy_tests {
    use super::*;

    #[test]
    fn global_mdns_policy_controls_unknown_links() {
        let mut config = Config::default();
        config.multicast_dns = SupportMode::No;
        let resolver = Resolver::new(config);
        assert!(!resolver.multicast_dns_resolve_enabled(None));
        assert!(!resolver.multicast_dns_respond_enabled(42));
    }
}
