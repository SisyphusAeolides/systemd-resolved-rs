//! Atomic publisher for systemd-resolved-compatible resolv.conf files.
//!
//! Paths (upstream parity):
//!   /run/systemd/resolve/stub-resolv.conf  — nameserver 127.0.0.53[.54]
//!   /run/systemd/resolve/resolv.conf       — current uplink servers
//!
//! Also optional per-link dumps under netif/ for debugging.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, warn};

const SYSTEM_RESOLV_CONF: &str = "/etc/resolv.conf";
const STATIC_RESOLV_CONF_PATHS: [&str; 2] =
    ["/usr/lib/systemd/resolv.conf", "/lib/systemd/resolv.conf"];

/// How `/etc/resolv.conf` is currently managed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ResolvConfMode {
    /// Clients talk to uplink servers directly through the generated file.
    Uplink,
    /// Clients use the local stub resolver.
    #[default]
    Stub,
    /// Clients use systemd's static stub resolver file.
    Static,
    /// `/etc/resolv.conf` does not exist or is a dangling symbolic link.
    Missing,
    /// A third party owns `/etc/resolv.conf`.
    Foreign,
}

impl ResolvConfMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uplink => "uplink",
            Self::Stub => "stub",
            Self::Static => "static",
            Self::Missing => "missing",
            Self::Foreign => "foreign",
        }
    }
}

/// Determine the resolver mode using the same inode comparison as upstream.
///
/// `std::fs::metadata` follows symbolic links, matching `stat(2)` behavior.
/// Thus direct files, symbolic links, and hard links are classified by the
/// object they resolve to rather than by path spelling.
pub fn detect_resolv_conf_mode(
    system_path: &Path,
    run_dir: &Path,
    static_paths: &[&Path],
) -> io::Result<ResolvConfMode> {
    let system_metadata = match fs::metadata(system_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ResolvConfMode::Missing);
        }
        Err(error) => return Err(error),
    };

    for (mode, path) in [
        (ResolvConfMode::Uplink, run_dir.join("resolv.conf")),
        (ResolvConfMode::Stub, run_dir.join("stub-resolv.conf")),
    ] {
        if path_matches(&system_metadata, &path)? {
            return Ok(mode);
        }
    }

    for path in static_paths {
        if path_matches(&system_metadata, path)? {
            return Ok(ResolvConfMode::Static);
        }
    }

    Ok(ResolvConfMode::Foreign)
}

pub fn system_resolv_conf_mode(run_dir: &Path) -> io::Result<ResolvConfMode> {
    let static_paths = STATIC_RESOLV_CONF_PATHS.map(Path::new);
    detect_resolv_conf_mode(Path::new(SYSTEM_RESOLV_CONF), run_dir, &static_paths)
}

fn path_matches(system_metadata: &Metadata, candidate: &Path) -> io::Result<bool> {
    match fs::metadata(candidate) {
        Ok(candidate_metadata) => Ok(same_inode(system_metadata, &candidate_metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[derive(Clone, Debug, Default)]
pub struct GlobalDnsState {
    pub search: Vec<String>,
    pub uplink_servers: Vec<IpAddr>,
    pub options: Vec<String>,
    /// Optional comment banner (distro name, version).
    pub banner: Option<String>,
    pub llmnr_hostname: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ResolvConfPublisher {
    pub run_dir: PathBuf,
    pub mode: ResolvConfMode,
    pub stub_addresses: Vec<IpAddr>,
    pub file_mode: u32,
}

impl Default for ResolvConfPublisher {
    fn default() -> Self {
        Self {
            run_dir: PathBuf::from("/run/systemd/resolve"),
            mode: ResolvConfMode::Stub,
            stub_addresses: vec![
                IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 53)),
                IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 54)),
            ],
            file_mode: 0o644,
        }
    }
}

impl ResolvConfPublisher {
    pub fn with_run_dir(mut self, p: impl Into<PathBuf>) -> Self {
        self.run_dir = p.into();
        self
    }

    pub fn ensure_dirs(&self) -> io::Result<()> {
        fs::create_dir_all(&self.run_dir)?;
        let netif = self.run_dir.join("netif");
        fs::create_dir_all(&netif)?;
        Ok(())
    }

    fn atomic_write(&self, path: &Path, body: &str) -> io::Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let tmp = path.with_extension(format!(
            "tmp.{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(self.file_mode);
            let mut f = opts.open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        debug!(path = %path.display(), bytes = body.len(), "resolv.conf written");
        Ok(())
    }

    fn header(state: &GlobalDnsState, which: &str) -> String {
        let mut h = String::new();
        h.push_str("# This is ");
        h.push_str(which);
        h.push_str(" managed by systemd-resolved-rs.\n");
        h.push_str("# Do not edit this file manually.\n");
        if let Some(b) = &state.banner {
            h.push_str("# ");
            h.push_str(b);
            h.push('\n');
        }
        h.push('\n');
        h
    }

    fn render_search(state: &GlobalDnsState) -> String {
        if state.search.is_empty() {
            return String::new();
        }
        let mut cleaned: Vec<String> = state
            .search
            .iter()
            .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty() && s != ".")
            .collect();
        cleaned.dedup();
        if cleaned.is_empty() {
            return String::new();
        }
        format!("search {}\n", cleaned.join(" "))
    }

    fn render_options(state: &GlobalDnsState) -> String {
        let opts = if state.options.is_empty() {
            vec!["edns0".to_string(), "trust-ad".to_string()]
        } else {
            state.options.clone()
        };
        format!("options {}\n", opts.join(" "))
    }

    pub fn write_stub(&self, state: &GlobalDnsState) -> io::Result<()> {
        let path = self.run_dir.join("stub-resolv.conf");
        let mut body = Self::header(state, "/run/systemd/resolve/stub-resolv.conf");
        body.push_str(
            "# Run \\\"resolvectl status\\\" to see details about the uplink DNS servers\n\\
             # currently in use.\n\n",
        );
        for a in &self.stub_addresses {
            body.push_str(&format!("nameserver {}\n", a));
        }
        body.push_str(&Self::render_search(state));
        body.push_str(&Self::render_options(state));
        self.atomic_write(&path, &body)
    }

    pub fn write_uplink(&self, state: &GlobalDnsState) -> io::Result<()> {
        let path = self.run_dir.join("resolv.conf");
        let mut body = Self::header(state, "/run/systemd/resolve/resolv.conf");
        body.push_str(
            "# This file lists the uplink DNS servers discovered by systemd-resolved-rs.\n\\
             # Applications that cannot use the stub may point at this file.\n\n",
        );
        if state.uplink_servers.is_empty() {
            body.push_str("# No uplink DNS servers are currently known.\n");
        } else {
            for s in &state.uplink_servers {
                body.push_str(&format!("nameserver {}\n", s));
            }
        }
        body.push_str(&Self::render_search(state));
        // Uplink file traditionally omits trust-ad unless validated end-to-end.
        let opts: Vec<String> = state
            .options
            .iter()
            .filter(|o| o.as_str() != "trust-ad")
            .cloned()
            .collect();
        if opts.is_empty() {
            body.push_str("options edns0\n");
        } else {
            body.push_str(&format!("options {}\n", opts.join(" ")));
        }
        self.atomic_write(&path, &body)
    }

    /// Write a simple per-link status file (debug / compatibility).
    pub fn write_link_snapshot(
        &self,
        ifindex: i32,
        ifname: &str,
        dns: &[IpAddr],
        domains: &[String],
    ) -> io::Result<()> {
        let dir = self.run_dir.join("netif");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{ifindex}"));
        let mut body = format!("# link {ifindex} ({ifname})\n");
        for d in dns {
            body.push_str(&format!("DNS={d}\n"));
        }
        for d in domains {
            body.push_str(&format!("Domains={d}\n"));
        }
        self.atomic_write(&path, &body)
    }

    pub fn remove_link_snapshot(&self, ifindex: i32) -> io::Result<()> {
        let path = self.run_dir.join("netif").join(format!("{ifindex}"));
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn republish(&self, state: &GlobalDnsState) -> io::Result<()> {
        self.ensure_dirs()?;
        self.write_stub(state)?;
        self.write_uplink(state)?;
        Ok(())
    }

    /// Best-effort republish; logs and continues on error.
    pub fn republish_lossy(&self, state: &GlobalDnsState) {
        if let Err(e) = self.republish(state) {
            warn!(error = %e, "failed to publish resolv.conf files");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::symlink;

    #[test]
    fn stub_contains_local_nameservers() {
        let dir = tempfile::tempdir().unwrap();
        let p = ResolvConfPublisher::default().with_run_dir(dir.path());
        let st = GlobalDnsState {
            search: vec!["lan".into(), "lan".into(), "".into()],
            uplink_servers: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            options: vec![],
            banner: Some("test".into()),
            llmnr_hostname: None,
        };
        p.republish(&st).unwrap();
        let stub = fs::read_to_string(dir.path().join("stub-resolv.conf")).unwrap();
        assert!(stub.contains("127.0.0.53"));
        assert!(stub.contains("search lan\n"));
        assert!(stub.contains("trust-ad"));
        let up = fs::read_to_string(dir.path().join("resolv.conf")).unwrap();
        assert!(up.contains("9.9.9.9"));
        assert!(!up.contains("trust-ad"));
    }

    #[test]
    fn detects_all_upstream_resolv_conf_modes_by_inode() {
        let root = tempfile::tempdir().unwrap();
        let run_dir = root.path().join("run");
        let static_dir = root.path().join("lib");
        fs::create_dir_all(&run_dir).unwrap();
        fs::create_dir_all(&static_dir).unwrap();

        let uplink = run_dir.join("resolv.conf");
        let stub = run_dir.join("stub-resolv.conf");
        let static_file = static_dir.join("resolv.conf");
        let foreign = root.path().join("foreign.conf");
        fs::write(&uplink, "nameserver 192.0.2.1\n").unwrap();
        fs::write(&stub, "nameserver 127.0.0.53\n").unwrap();
        fs::write(&static_file, "nameserver 127.0.0.53\n").unwrap();
        fs::write(&foreign, "nameserver 198.51.100.1\n").unwrap();

        let system = root.path().join("etc-resolv.conf");
        let static_paths = [static_file.as_path()];
        assert_eq!(
            detect_resolv_conf_mode(&system, &run_dir, &static_paths).unwrap(),
            ResolvConfMode::Missing
        );

        symlink(&uplink, &system).unwrap();
        assert_eq!(
            detect_resolv_conf_mode(&system, &run_dir, &static_paths).unwrap(),
            ResolvConfMode::Uplink
        );

        fs::remove_file(&system).unwrap();
        symlink(&stub, &system).unwrap();
        assert_eq!(
            detect_resolv_conf_mode(&system, &run_dir, &static_paths).unwrap(),
            ResolvConfMode::Stub
        );

        fs::remove_file(&system).unwrap();
        symlink(&static_file, &system).unwrap();
        assert_eq!(
            detect_resolv_conf_mode(&system, &run_dir, &static_paths).unwrap(),
            ResolvConfMode::Static
        );

        fs::remove_file(&system).unwrap();
        symlink(&foreign, &system).unwrap();
        assert_eq!(
            detect_resolv_conf_mode(&system, &run_dir, &static_paths).unwrap(),
            ResolvConfMode::Foreign
        );
    }

    #[test]
    fn dangling_resolv_conf_symlink_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let system = root.path().join("resolv.conf");
        symlink(root.path().join("absent"), &system).unwrap();
        assert_eq!(
            detect_resolv_conf_mode(&system, root.path(), &[]).unwrap(),
            ResolvConfMode::Missing
        );
    }
}
