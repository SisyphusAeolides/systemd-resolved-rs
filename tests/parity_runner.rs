//! Run: cargo test --test parity_runner -- --nocapture
// Or invoke scripts from integration environment.
#[test]
fn parity_scripts_exist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/parity");
    assert!(root.join("stub_dig.sh").exists());
    assert!(root.join("nss_getent.sh").exists());
    assert!(root.join("check_dbus_abi.sh").exists());
}
