//! Publish /run/systemd/resolve/{stub-,}resolv.conf — drop-in path parity.

use std::fs::{self, File};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvConfMode {
    /// nameserver 127.0.0.53 (apps → stub)
    Stub,
    /// flattened uplink servers
    Uplink,
    /// do not manage /etc/resolv.conf
    Foreign,
}

#[derive(Clone, Debug, Default)]
pub struct GlobalDnsState {
    pub search: Vec<String>,
    pub uplink_servers: Vec<IpAddr>,
    /// edns0 trust-ad etc.
    pub options: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ResolvConfPublisher {
    pub run_dir: PathBuf,
    pub mode: ResolvConfMode,
}

impl Default for ResolvConfPublisher {
    fn default() -> Self {
        Self {
            run_dir: PathBuf::from("/run/systemd/resolve"),
            mode: ResolvConfMode::Stub,
        }
    }
}

impl ResolvConfPublisher {
    pub fn ensure_dirs(&self) -> io::Result<()> {
        fs::create_dir_all(&self.run_dir)?;
        Ok(())
    }

    fn atomic_write(path: &Path, body: &str) -> io::Result<()> {
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn write_stub(&self, state: &GlobalDnsState) -> io::Result<()> {
        let path = self.run_dir.join("stub-resolv.conf");
        let mut body = String::from(
            "# This is /run/systemd/resolve/stub-resolv.conf managed by systemd-resolved-rs.\n\
             # Do not edit.\n\
             nameserver 127.0.0.53\n\
             nameserver 127.0.0.54\n",
        );
        if !state.search.is_empty() {
            body.push_str("search ");
            body.push_str(&state.search.join(" "));
            body.push('\n');
        }
        let opts = if state.options.is_empty() {
            vec!["edns0".into(), "trust-ad".into()]
        } else {
            state.options.clone()
        };
        body.push_str("options ");
        body.push_str(&opts.join(" "));
        body.push('\n');
        Self::atomic_write(&path, &body)
    }

    pub fn write_uplink(&self, state: &GlobalDnsState) -> io::Result<()> {
        let path = self.run_dir.join("resolv.conf");
        let mut body = String::from(
            "# This is /run/systemd/resolve/resolv.conf managed by systemd-resolved-rs.\n\
             # Do not edit.\n",
        );
        if state.uplink_servers.is_empty() {
            body.push_str("# No uplink servers currently known.\n");
        } else {
            for s in &state.uplink_servers {
                body.push_str(&format!("nameserver {}\n", s));
            }
        }
        if !state.search.is_empty() {
            body.push_str("search ");
            body.push_str(&state.search.join(" "));
            body.push('\n');
        }
        Self::atomic_write(&path, &body)
    }

    pub fn republish(&self, state: &GlobalDnsState) -> io::Result<()> {
        self.ensure_dirs()?;
        self.write_stub(state)?;
        self.write_uplink(state)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn writes_stub_and_uplink() {
        let dir = tempfile::tempdir().unwrap();
        let pubr = ResolvConfPublisher {
            run_dir: dir.path().to_path_buf(),
            mode: ResolvConfMode::Stub,
        };
        let st = GlobalDnsState {
            search: vec!["example".into()],
            uplink_servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            options: vec![],
        };
        pubr.republish(&st).unwrap();
        let stub = fs::read_to_string(dir.path().join("stub-resolv.conf")).unwrap();
        assert!(stub.contains("127.0.0.53"));
        let up = fs::read_to_string(dir.path().join("resolv.conf")).unwrap();
        assert!(up.contains("1.1.1.1"));
    }
}
