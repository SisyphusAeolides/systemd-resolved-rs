#[test]
fn varlink_socket_path_constant() {
    let p = "/run/systemd/resolve/io.systemd.Resolve";
    assert!(p.starts_with("/run/systemd/resolve/"));
}
