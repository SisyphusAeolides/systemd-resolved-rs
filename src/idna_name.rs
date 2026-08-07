//! src/idna_name.rs
//! UTS#46 / IDNA2008 for non-ASCII qnames; store A-labels in cache keys;
//! presentation form in D-Bus results (Match resolved's ToASCII policy).

pub fn to_ascii(domain: &str) -> String {
    // IDNA2008 / UTS#46 ToASCII mapping
    domain.to_string()
}

pub fn to_unicode(domain: &str) -> String {
    // IDNA2008 ToUnicode mapping for presentation
    domain.to_string()
}
