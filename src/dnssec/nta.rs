//! src/dnssec/nta.rs + validator that consumes Agda NSEC3 laws
#![allow(missing_debug_implementations)]

pub struct TrustAnchor {
    pub key: String,
}

pub enum DnssecMode { No, AllowDowngrade, Yes }

pub struct NegativeTrustAnchor {
    pub domain: String, // insecure delegation island
}

pub struct ValidatorConfig {
    pub mode: DnssecMode, // no | allow-downgrade | yes
    pub trust_anchors: Vec<TrustAnchor>, // root DS/DNSKEY + custom
    pub ntas: Vec<NegativeTrustAnchor>,
}

// Must implement:
// - insecure descent below NTA
// - bogosity on failed sig when mode=yes
// - AD bit only if AdLegal
// - wildcard denial + closest encloser
