// SPDX-License-Identifier: LGPL-2.1-or-later

pub const TRANSPORT_RETRY_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportMode {
    #[default]
    Udp,
    Tcp,
}

#[derive(Clone, Debug, Default)]
pub struct ServerTransportState {
    mode: TransportMode,
    failed_udp: u8,
    failed_tcp: u8,
    packet_truncated: bool,
    advertised_payload_size: Option<u16>,
}

impl ServerTransportState {
    pub const fn mode(&self) -> TransportMode {
        self.mode
    }

    pub const fn packet_truncated(&self) -> bool {
        self.packet_truncated
    }

    pub const fn failures(&self, mode: TransportMode) -> u8 {
        match mode {
            TransportMode::Udp => self.failed_udp,
            TransportMode::Tcp => self.failed_tcp,
        }
    }

    pub fn record_success(&mut self, mode: TransportMode) {
        match mode {
            TransportMode::Udp => self.failed_udp = 0,
            TransportMode::Tcp => self.failed_tcp = 0,
        }
    }

    pub fn record_failure(&mut self, mode: TransportMode) -> Option<TransportMode> {
        let failures = match mode {
            TransportMode::Udp => &mut self.failed_udp,
            TransportMode::Tcp => &mut self.failed_tcp,
        };
        *failures = failures.saturating_add(1);
        if *failures < TRANSPORT_RETRY_ATTEMPTS || mode != self.mode {
            return None;
        }

        self.mode = match mode {
            TransportMode::Udp => TransportMode::Tcp,
            TransportMode::Tcp => TransportMode::Udp,
        };
        self.clear_failures();
        Some(self.mode)
    }

    pub fn record_truncated(&mut self) {
        self.packet_truncated = true;
    }

    pub fn clear_failures(&mut self) {
        self.failed_udp = 0;
        self.failed_tcp = 0;
    }

    pub const fn advertised_payload_size(&self) -> Option<u16> {
        self.advertised_payload_size
    }

    pub fn set_advertised_payload_size(&mut self, size: u16) {
        self.advertised_payload_size = Some(size);
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_udp_loss_switches_to_tcp() {
        let mut state = ServerTransportState::default();
        assert_eq!(state.record_failure(TransportMode::Udp), None);
        assert_eq!(state.record_failure(TransportMode::Udp), None);
        assert_eq!(
            state.record_failure(TransportMode::Udp),
            Some(TransportMode::Tcp)
        );
        assert_eq!(state.mode(), TransportMode::Tcp);
    }

    #[test]
    fn repeated_tcp_loss_switches_back_to_udp() {
        let mut state = ServerTransportState::default();
        for _ in 0..TRANSPORT_RETRY_ATTEMPTS {
            let _ = state.record_failure(TransportMode::Udp);
        }
        assert_eq!(state.mode(), TransportMode::Tcp);
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(
            state.record_failure(TransportMode::Tcp),
            Some(TransportMode::Udp)
        );
        assert_eq!(state.mode(), TransportMode::Udp);
    }

    #[test]
    fn fallback_tcp_failures_do_not_replace_the_udp_mode() {
        let mut state = ServerTransportState::default();
        state.record_truncated();
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(state.record_failure(TransportMode::Tcp), None);
        assert_eq!(state.mode(), TransportMode::Udp);
        assert_eq!(state.failures(TransportMode::Tcp), TRANSPORT_RETRY_ATTEMPTS);
        assert!(state.packet_truncated());
    }
}
