//! IDNA / UTS#46 helpers for qnames.

/// ASCII lowercase presentation → wire-ready A-label string (dots).
/// Uses `idna` crate if available; else strict ASCII-only.
pub fn to_ascii(name: &str) -> Result<String, String> {
    let n = name.trim().trim_end_matches('.');
    if n.is_empty() {
        return Ok(".".into());
    }
    #[cfg(feature = "idna")]
    {
        return idna::domain_to_ascii(n).map_err(|e| e.to_string());
    }
    #[cfg(not(feature = "idna"))]
    {
        if n.is_ascii() {
            Ok(n.to_ascii_lowercase())
        } else {
            Err("non-ASCII name requires idna feature".into())
        }
    }
}

pub fn to_ascii_absolute(name: &str) -> Result<String, String> {
    let a = to_ascii(name)?;
    if a == "." {
        return Ok(a);
    }
    Ok(a.trim_end_matches('.').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ascii_lower() {
        assert_eq!(to_ascii("ExAmPle.COM").unwrap(), "example.com");
    }
}
