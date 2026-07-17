use super::*;

#[test]
fn only_absent_or_refused_daemon_connections_are_safe_unavailability() {
    let socket = Path::new("/tmp/gommage-test.sock");
    for kind in [io::ErrorKind::NotFound, io::ErrorKind::ConnectionRefused] {
        assert!(matches!(
            classify_daemon_connect_error(socket, &io::Error::from(kind)),
            DaemonReloadOutcome::Unavailable(_)
        ));
    }
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::OutOfMemory,
    ] {
        assert!(matches!(
            classify_daemon_connect_error(socket, &io::Error::from(kind)),
            DaemonReloadOutcome::Failed(_)
        ));
    }
}
