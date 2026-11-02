use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

#[derive(Clone, Default)]
struct FakeMap(Rc<RefCell<FakeState>>);
#[derive(Default)]
struct FakeState {
    slots: BTreeMap<u32, u64>,
    writes: usize,
    fail_at: usize,
}
impl MapIo for FakeMap {
    fn cookie(&self, key: u32) -> io::Result<Option<u64>> {
        Ok(self.0.borrow().slots.get(&key).copied())
    }
    fn put(&self, key: u32, fd: i32) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        state.writes += 1;
        if state.writes == state.fail_at {
            return Err(io::Error::other("injected update failure"));
        }
        state.slots.insert(key, fd as u64);
        Ok(())
    }
    fn delete(&self, key: u32) -> io::Result<()> {
        self.0.borrow_mut().slots.remove(&key);
        Ok(())
    }
}
fn stage(map: &FakeMap) -> io::Result<Transaction<FakeMap>> {
    Transaction::stage(map.clone(), [10, 10, 20, 20], [10, 10, 20, 20])
}
#[test]
fn each_listener_or_ready_write_failure_reclaims_only_this_transaction() {
    for fail_at in 1..=5 {
        let map = FakeMap::default();
        map.0.borrow_mut().fail_at = fail_at;
        if fail_at < 5 {
            assert!(stage(&map).is_err());
        } else {
            let mut transaction = stage(&map).unwrap();
            assert!(transaction.publish().is_err());
        }
        assert!(map.0.borrow().slots.is_empty(), "failure at {fail_at}");
    }
}
#[test]
fn staging_is_invisible_and_drop_cancels_it() {
    let map = FakeMap::default();
    let transaction = stage(&map).unwrap();
    assert_eq!(map.0.borrow().slots.len(), 4);
    assert_eq!(map.cookie(LISTEN_SOCKET_KEY_READY).unwrap(), None);
    drop(transaction);
    assert!(map.0.borrow().slots.is_empty());
}
#[test]
fn publication_is_idempotent_and_active_or_partial_foreign_maps_are_immutable() {
    let map = FakeMap::default();
    assert_eq!(
        stage(&map).unwrap().publish().unwrap(),
        ListenerPublicationOutcome::Published
    );
    let snapshot = map.0.borrow().slots.clone();
    assert_eq!(
        stage(&map).unwrap().publish().unwrap(),
        ListenerPublicationOutcome::AlreadyPublished
    );
    assert_eq!(map.0.borrow().writes, 5);
    assert!(Transaction::stage(map.clone(), [30, 30, 40, 40], [30, 30, 40, 40]).is_err());
    assert_eq!(map.0.borrow().slots, snapshot);
    map.0.borrow_mut().slots.remove(&LISTEN_SOCKET_KEY_READY);
    assert!(stage(&map).is_err());
    assert_eq!(map.0.borrow().slots.len(), 4);
}
#[test]
fn rollback_preserves_a_slot_replaced_by_an_external_writer() {
    let map = FakeMap::default();
    let mut transaction = stage(&map).unwrap();
    map.0.borrow_mut().slots.insert(2, 999);
    assert!(transaction.publish().is_err());
    drop(transaction);
    assert_eq!(map.0.borrow().slots, BTreeMap::from([(2, 999)]));
}
#[test]
fn socket_prevalidation_rejects_streams_and_non_ip_fds() {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let udp = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    assert_ne!(validate_socket(tcp.as_raw_fd(), true).unwrap(), 0);
    assert_ne!(validate_socket(udp.as_raw_fd(), false).unwrap(), 0);
    assert!(validate_socket(udp.as_raw_fd(), true).is_err());
    assert!(validate_socket(tcp.as_raw_fd(), false).is_err());
    let (unix, _) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(validate_socket(unix.as_raw_fd(), true).is_err());
}
#[test]
fn kernel_sockmap_staging_rollback_and_cookie_idempotence() {
    if std::env::var("DAE_RUN_SOCKMAP_LIFECYCLE_SMOKE").as_deref() != Ok("1") {
        eprintln!("skip kernel sockmap lifecycle smoke: opt-in required");
        return;
    }
    let map = create_sockmap().unwrap();
    let tcp = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let udp = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let fds = [
        tcp.as_raw_fd(),
        tcp.as_raw_fd(),
        udp.as_raw_fd(),
        udp.as_raw_fd(),
    ];
    let duplicate = || {
        let fd = unsafe { libc::fcntl(map.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    {
        let _staged = ListenerPublication::stage(duplicate(), fds).unwrap();
        assert_eq!(
            KernelMap(duplicate())
                .cookie(LISTEN_SOCKET_KEY_READY)
                .unwrap(),
            None
        );
    }
    for key in 0..5 {
        assert_eq!(KernelMap(duplicate()).cookie(key).unwrap(), None);
    }
    ListenerPublication::stage(duplicate(), fds)
        .unwrap()
        .publish()
        .unwrap();
    ListenerPublication::stage(duplicate(), fds)
        .unwrap()
        .publish()
        .unwrap();
    let other = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    assert!(
        ListenerPublication::stage(
            duplicate(),
            [
                other.as_raw_fd(),
                other.as_raw_fd(),
                udp.as_raw_fd(),
                udp.as_raw_fd()
            ]
        )
        .is_err()
    );
    for key in 0..5 {
        assert!(KernelMap(duplicate()).cookie(key).unwrap().is_some());
    }
}

#[test]
fn kernel_public_staging_and_parity_preserve_ready_and_socket_identity() {
    if std::env::var("DAE_RUN_SOCKMAP_LIFECYCLE_SMOKE").as_deref() != Ok("1") {
        eprintln!("skip public listener lifecycle smoke: opt-in required");
        return;
    }
    let mut attr = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_SOCKMAP,
        key_size: 4,
        value_size: 8,
        max_entries: LISTEN_SOCKET_MAP_MAX_ENTRIES,
        ..BpfMapCreateAttr::default()
    };
    let name = LISTEN_SOCKET_MAP_KERNEL_NAME.as_bytes();
    attr.map_name[..name.len()].copy_from_slice(name);
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr,
            size_of::<BpfMapCreateAttr>(),
        )
    };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    let map = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let id = crate::runtime_maps::map_info(map.as_raw_fd()).unwrap().id;
    let cookies = || {
        let fd = unsafe { libc::fcntl(map.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        assert!(fd >= 0);
        let reader = KernelMap(unsafe { OwnedFd::from_raw_fd(fd) });
        (0..5)
            .map(|key| reader.cookie(key).unwrap())
            .collect::<Vec<_>>()
    };
    {
        let staged = stage_tproxy_listener_set_by_id(id, 0).unwrap();
        assert!(!staged.is_published().unwrap());
        assert_eq!(cookies()[4], None);
    }
    assert_eq!(cookies(), vec![None; 5]);
    let live = stage_tproxy_listener_set_by_id(id, 0).unwrap();
    live.publish().unwrap();
    assert!(live.is_published().unwrap());
    let before = cookies();
    assert!(before.iter().all(Option::is_some));
    let update =
        update_listen_socket_map_by_id(id, live.tcp_listener_fd, None, live.udp_socket_fd, None)
            .unwrap();
    assert_eq!(
        update.publication,
        ListenerPublicationOutcome::AlreadyPublished
    );
    assert_eq!(cookies(), before);
    let other = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    assert!(
        update_listen_socket_map_by_id(id, other.as_raw_fd(), None, live.udp_socket_fd, None)
            .is_err()
    );
    assert_eq!(cookies(), before);
    for key in 0..5 {
        crate::runtime_maps::delete_map_elem_bytes(map.as_raw_fd(), &(key as u32).to_ne_bytes())
            .unwrap();
    }
    let update =
        update_listen_socket_map_by_id(id, live.tcp_listener_fd, None, live.udp_socket_fd, None)
            .unwrap();
    assert_eq!(update.publication, ListenerPublicationOutcome::Published);
}
