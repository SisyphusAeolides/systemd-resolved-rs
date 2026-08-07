use std::path::Path;
use std::process::Command;

fn script(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/parity")
        .join(name)
}

#[test]
fn parity_scripts_are_nonempty() {
    for s in [
        "stub_dig.sh",
        "nss_getent.sh",
        "resolv_conf_paths.sh",
        "check_dbus_abi.sh",
        "run_all.sh",
    ] {
        let p = script(s);
        assert!(p.exists(), "missing {s}");
        let meta = std::fs::metadata(&p).unwrap();
        assert!(meta.len() > 40, "{s} still a stub");
    }
}

#[test]
#[ignore] // run with: cargo test -- --ignored (needs root/service)
fn boot_smoke_if_available() {
    let smoke = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/boot-smoke.sh");
    if !smoke.exists() {
        return;
    }
    let st = Command::new("bash").arg(smoke).status().unwrap();
    assert!(st.success());
}
