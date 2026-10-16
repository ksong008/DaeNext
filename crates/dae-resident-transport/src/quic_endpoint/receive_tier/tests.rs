use super::*;
use quinn::Runtime;

#[test]
fn profiles_preserve_gro_capacity_outside_low_memory() {
    for (profile, expected) in [
        (ResidentRuntimeProfile::LowMemory, 1),
        (ResidentRuntimeProfile::Balanced, 64),
        (ResidentRuntimeProfile::HighPerformance, 64),
    ] {
        assert_eq!(segments_for_profile(profile), expected, "{profile:?}");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn every_replacement_disables_gro_before_advertising_a_smaller_slab() {
    use std::os::fd::AsRawFd;
    for segments in [1, 16, 64] {
        let runtime = ReceiveTierRuntime {
            inner: quinn::default_runtime().unwrap(),
            segments,
        };
        for _ in 0..3 {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let handle = socket.try_clone().unwrap();
            let wrapped = runtime.wrap_udp_socket(socket).unwrap();
            assert!(wrapped.max_receive_segments() <= segments);
            if segments < 64 {
                let mut enabled: libc::c_int = -1;
                let mut len = std::mem::size_of_val(&enabled) as libc::socklen_t;
                assert_eq!(
                    unsafe {
                        libc::getsockopt(
                            handle.as_raw_fd(),
                            libc::SOL_UDP,
                            libc::UDP_GRO,
                            (&mut enabled as *mut libc::c_int).cast(),
                            &mut len,
                        )
                    },
                    0
                );
                assert_eq!(enabled, 0);
            }
        }
    }
}
