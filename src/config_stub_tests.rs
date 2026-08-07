// SPDX-License-Identifier: LGPL-2.1-or-later
#[cfg(test)]
mod stub_listener_tests {
    use super::*;

    #[test]
    fn default_stub_listener_matches_upstream() {
        let config = Config::default();
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Yes);
        assert!(config.dns_stub_listener.udp_enabled());
        assert!(config.dns_stub_listener.tcp_enabled());
        assert_eq!(config.dns_stub_listener.as_str(), "yes");
    }

    #[test]
    fn modes_preserve_listener_addresses() {
        let mut config = Config::default();
        let listeners = config.listeners.clone();
        let proxy_listeners = config.proxy_listeners.clone();

        config
            .apply_text("[Resolve]\nDNSStubListener=no\n")
            .expect("disabled stub listener");
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::No);
        assert!(!config.dns_stub_listener.udp_enabled());
        assert!(!config.dns_stub_listener.tcp_enabled());
        assert_eq!(config.listeners, listeners);
        assert_eq!(config.proxy_listeners, proxy_listeners);

        config
            .apply_text("[Resolve]\nDNSStubListener=udp\n")
            .expect("UDP stub listener");
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Udp);
        assert!(config.dns_stub_listener.udp_enabled());
        assert!(!config.dns_stub_listener.tcp_enabled());

        config
            .apply_text("[Resolve]\nDNSStubListener=tcp\n")
            .expect("TCP stub listener");
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Tcp);
        assert!(!config.dns_stub_listener.udp_enabled());
        assert!(config.dns_stub_listener.tcp_enabled());

        config
            .apply_text("[Resolve]\nDNSStubListener=yes\n")
            .expect("enabled stub listener");
        assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Yes);
        assert_eq!(config.listeners, listeners);
        assert_eq!(config.proxy_listeners, proxy_listeners);
    }

    #[test]
    fn boolean_spellings_match_upstream_yes_no_aliases() {
        for value in ["yes", "true", "on", "1"] {
            let mut config = Config::default();
            config
                .apply_text(&format!("[Resolve]\nDNSStubListener={value}\n"))
                .expect("enabled alias");
            assert_eq!(config.dns_stub_listener, DnsStubListenerMode::Yes);
        }
        for value in ["no", "false", "off", "0"] {
            let mut config = Config::default();
            config
                .apply_text(&format!("[Resolve]\nDNSStubListener={value}\n"))
                .expect("disabled alias");
            assert_eq!(config.dns_stub_listener, DnsStubListenerMode::No);
        }
    }
}
