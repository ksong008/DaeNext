use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

fn poison(registry: &ProductHttpConnectionRegistry) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = registry.connections.lock().unwrap();
        panic!("injected HTTP registry poison");
    }));
}

#[test]
fn poisoned_shutdown_interrupts_sockets_and_preserves_registration_fence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    let registry = Arc::new(ProductHttpConnectionRegistry::default());
    let lease = registry.register(&server).unwrap();
    poison(&registry);
    assert!(registry.register(&server).is_err());
    assert_eq!(registry.active_count(), 1);
    assert_eq!(registry.shutdown_all().unwrap(), 1);
    assert_eq!(registry.active_count(), 0);
    let mut byte = [0];
    assert_eq!(server.read(&mut byte).unwrap(), 0);
    // The peer sees EOF even while the original accepted socket is retained.
    let _ = peer.write_all(b"x");
    assert_eq!(peer.read(&mut byte).unwrap(), 0);
    drop(lease);
    assert!(registry.connections.is_poisoned());
    assert_eq!(registry.shutdown_all().unwrap(), 0);
}

#[test]
fn poisoned_lease_drop_removes_its_socket_inventory_entry() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let registry = Arc::new(ProductHttpConnectionRegistry::default());
    let lease = registry.register(&server).unwrap();
    poison(&registry);
    drop(lease);
    assert_eq!(registry.active_count(), 0);
    assert!(registry.connections.is_poisoned());
}
