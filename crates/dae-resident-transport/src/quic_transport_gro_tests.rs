use super::*;
use quinn::Runtime;
use std::{future::poll_fn, net::UdpSocket, os::fd::AsRawFd};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn salamander_disables_gro_after_wrap_and_receives_gso_datagrams() {
    let runtime = Hysteria2SalamanderRuntime {
        inner: quinn::default_runtime().unwrap(),
        key: Arc::new(b"gro-regression-key".to_vec()),
    };
    // Repeat initialization as port hopping does for each replacement socket.
    for _ in 0..3 {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let handle = receiver.try_clone().unwrap();
        let wrapped = runtime.wrap_udp_socket(receiver).unwrap();
        let mut gro: libc::c_int = -1;
        let mut len = std::mem::size_of_val(&gro) as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    handle.as_raw_fd(),
                    libc::SOL_UDP,
                    libc::UDP_GRO,
                    (&mut gro as *mut libc::c_int).cast(),
                    &mut len,
                )
            },
            0
        );
        assert_eq!(gro, 0);
        assert_eq!(wrapped.max_receive_segments(), 1);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let state = udp::UdpSocketState::new((&sender).into()).unwrap();
        assert!(state.max_gso_segments() >= 4, "test requires Linux UDP GSO");
        let mut wire = Vec::new();
        for sequence in 0..4_u8 {
            let mut packet = Vec::new();
            salamander_obfuscate_packet_into(
                &runtime.key,
                &vec![sequence; 1192],
                &[sequence; 8],
                &mut packet,
            );
            wire.extend_from_slice(&packet);
        }
        state
            .send(
                (&sender).into(),
                &udp::Transmit {
                    destination: wrapped.local_addr().unwrap(),
                    ecn: None,
                    contents: &wire,
                    segment_size: Some(1200),
                    src_ip: None,
                },
            )
            .unwrap();
        for sequence in 0..4_u8 {
            // Quinn allocates 1472 bytes per iovec for a single-segment socket.
            let mut data = [0; 1472];
            let mut bufs = [IoSliceMut::new(&mut data)];
            let mut meta = [udp::RecvMeta::default()];
            let count = time::timeout(
                Duration::from_secs(3),
                poll_fn(|cx| wrapped.poll_recv(cx, &mut bufs, &mut meta)),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(count, 1);
            assert_eq!(meta[0].len, 1192);
            assert_eq!(meta[0].stride, 1192);
            assert_eq!(&data[..1192], &vec![sequence; 1192]);
        }
    }
}
