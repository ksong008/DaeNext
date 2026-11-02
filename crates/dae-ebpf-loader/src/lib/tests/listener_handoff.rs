//! Exercise the real SCM_RIGHTS lifecycle against a real kernel SOCKMAP.
use crate::*;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn cold_map() -> OwnedFd {
    // union bpf_attr's map-create prefix (including the 16-byte name).
    let mut attr = [0u32; 18];
    attr[..4].copy_from_slice(&[15, 4, 8, 5]);
    let name = b"listen_socket_m";
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            attr.as_mut_ptr().cast::<u8>().add(28),
            name.len(),
        );
    }
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            0,
            attr.as_ptr(),
            std::mem::size_of_val(&attr),
        )
    };
    assert!(fd >= 0, "{}", std::io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}
fn slot(map: &OwnedFd, key: u32) -> Option<u64> {
    let mut value = [0; 8];
    match dae_ebpf_support::lookup_map_elem_bytes(map.as_raw_fd(), &key.to_ne_bytes(), &mut value) {
        Ok(()) => Some(u64::from_ne_bytes(value)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
        Err(error) => panic!("lookup: {error}"),
    }
}
fn receive_prepare(socket: &UnixStream) -> (Value, Vec<OwnedFd>) {
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut data = [0; 8192];
    let mut control = [0u64; 16];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    assert!(count > 0, "{}", std::io::Error::last_os_error());
    assert_eq!(msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC), 0);
    let mut fds = Vec::new();
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null());
        assert_eq!((*cmsg).cmsg_type, libc::SCM_RIGHTS);
        let count =
            ((*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<i32>();
        for index in 0..count {
            fds.push(OwnedFd::from_raw_fd(
                *libc::CMSG_DATA(cmsg).cast::<i32>().add(index),
            ));
        }
    }
    assert_eq!(fds.len(), 2);
    (
        serde_json::from_slice(&data[..count as usize]).unwrap(),
        fds,
    )
}
#[test]
fn real_open_handoff_publishes_only_after_adoption_and_reclaims_failures() {
    if std::env::var("DAE_RUN_LISTENER_HANDOFF_SMOKE").as_deref() != Ok("1") {
        eprintln!("skip real listener handoff smoke: opt-in required");
        return;
    }
    for scenario in ["success", "bad-ack", "closed", "timeout", "send-failure"] {
        let map = cold_map();
        let map_id = dae_ebpf_support::map_info(map.as_raw_fd()).unwrap().id;
        let (a, mut b) = UnixStream::pair().unwrap();
        if scenario == "send-failure" {
            drop(b);
            b = UnixStream::pair().unwrap().0;
        }
        let worker = std::thread::spawn(move || {
            run_tproxy_listener_open_handoff(TproxyListenerOpenHandoffOptions {
                map_id,
                port: 0,
                handoff_fd: a.as_raw_fd(),
            })
        });
        let mut adopted = Vec::new();
        if scenario != "send-failure" {
            let (payload, fds) = receive_prepare(&b);
            adopted = fds;
            assert_eq!(payload["status"], "prepared");
            for key in 0..4 {
                assert!(slot(&map, key).is_some());
            }
            assert_eq!(slot(&map, 4), None, "must not publish merely after sendmsg");
            if scenario == "success" {
                // The receiving process owns both real sockets before ACK.
                // Production Tokio reactor adoption is covered by its startup
                // barrier and the native runtime traffic tests.
                let tcp: std::net::TcpListener = adopted.remove(0).into();
                let udp: std::net::UdpSocket = adopted.remove(0).into();
                assert!(tcp.local_addr().is_ok());
                assert!(udp.local_addr().is_ok());
                b.write_all(payload["ready_ack"].as_str().unwrap().as_bytes())
                    .unwrap();
                let output = worker.join().unwrap();
                assert_eq!(output.exit_code, 0, "{}", output.stderr);
                assert!(slot(&map, 4).is_some());
                drop((tcp, udp));
                continue;
            } else if scenario == "bad-ack" {
                b.write_all(b"invalid ready ack\n").unwrap();
            } else if scenario == "closed" {
                drop(b);
                b = UnixStream::pair().unwrap().0;
            }
        }
        let output = worker.join().unwrap();
        assert_ne!(output.exit_code, 0, "scenario {scenario}");
        for key in 0..5 {
            assert_eq!(slot(&map, key), None, "scenario {scenario}, key {key}");
        }
        drop((adopted, b));
    }
}

#[test]
fn real_update_map_reports_only_keys_written_by_this_invocation() {
    if std::env::var("DAE_RUN_SOCKMAP_LIFECYCLE_SMOKE").as_deref() != Ok("1") {
        eprintln!("skip real listener update evidence smoke: opt-in required");
        return;
    }
    let map = cold_map();
    let map_id = dae_ebpf_support::map_info(map.as_raw_fd()).unwrap().id;
    let tcp = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let udp = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    for (outcome, expected_keys, ready_updated) in [
        ("Published", vec![0, 1, 2, 3], true),
        ("AlreadyPublished", Vec::new(), false),
    ] {
        let before = (0..5).map(|key| slot(&map, key)).collect::<Vec<_>>();
        let output = run_tproxy_listener_update_map(TproxyListenerUpdateMapOptions {
            map_id,
            tcp4_fd: tcp.as_raw_fd(),
            tcp6_fd: None,
            udp4_fd: udp.as_raw_fd(),
            udp6_fd: None,
        });
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let value: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(value["publication_outcome"], outcome);
        assert_eq!(value["keys_updated"], json!(expected_keys));
        assert_eq!(value["keys_validated"], json!([0, 1, 2, 3]));
        assert_eq!(value["ready_key_updated"], ready_updated);
        let after = (0..5).map(|key| slot(&map, key)).collect::<Vec<_>>();
        if ready_updated {
            assert_eq!(before, vec![None; 5]);
            assert!(after.iter().all(Option::is_some));
        } else {
            assert_eq!(after, before);
        }
    }
}
