pub(super) fn send_fd_handoff(socket_fd: i32, payload: &[u8], fds: &[i32]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("fd handoff payload must not be empty".to_owned());
    }
    if fds.is_empty() {
        return Err("fd handoff requires at least one fd".to_owned());
    }

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let rights_bytes = std::mem::size_of_val(fds);
    let rights_len = rights_bytes
        .try_into()
        .map_err(|_| "fd handoff rights payload exceeds the platform cmsg limit".to_owned())?;
    let control_len = unsafe { libc::CMSG_SPACE(rights_len) } as usize;
    let cmsg_len = unsafe { libc::CMSG_LEN(rights_len) };
    let mut control = vec![0_u8; control_len];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    #[cfg(target_env = "musl")]
    {
        msg.msg_controllen = u32::try_from(control.len()).map_err(|_| {
            "fd handoff control buffer exceeds the platform msghdr limit".to_owned()
        })?;
    }
    #[cfg(not(target_env = "musl"))]
    {
        msg.msg_controllen = control.len();
    }

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err("failed to allocate SCM_RIGHTS control message".to_owned());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        #[cfg(target_env = "musl")]
        {
            (*cmsg).cmsg_len = cmsg_len;
        }
        #[cfg(not(target_env = "musl"))]
        {
            (*cmsg).cmsg_len = cmsg_len as usize;
        }
        std::ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(cmsg).cast::<u8>(),
            rights_bytes,
        );
        #[cfg(target_os = "linux")]
        let send_flags = libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT;
        #[cfg(not(target_os = "linux"))]
        let send_flags = 0;
        let sent = libc::sendmsg(socket_fd, &msg, send_flags);
        if sent < 0 {
            return Err(format!(
                "sendmsg failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if sent as usize != payload.len() {
            return Err(format!(
                "sendmsg wrote {sent} bytes, expected {}",
                payload.len()
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "native-ebpf")]
pub(super) fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Versioned ACK is sent by the consumer only after adopting both received FDs.
/// This helper does not claim worker readiness based on a successful sendmsg.
pub(super) fn await_listener_ready(
    fd: i32,
    token: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let expected = format!("DAE_LISTENER_READY_V1 {token}\n");
    let deadline = std::time::Instant::now() + timeout;
    let mut bytes = vec![0; expected.len()];
    let mut received = 0;
    while received < bytes.len() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("listener ready ack timed out".to_owned());
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let status = unsafe { libc::poll(&mut poll, 1, millis) };
        if status < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll listener ready ack: {error}"));
        }
        if status == 0 {
            continue;
        }
        let count = unsafe {
            libc::recv(
                fd,
                bytes[received..].as_mut_ptr().cast(),
                bytes.len() - received,
                libc::MSG_DONTWAIT,
            )
        };
        if count == 0 {
            return Err("listener consumer closed before ready ack".to_owned());
        }
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(format!("receive listener ready ack: {error}"));
        }
        received += count as usize;
        if bytes[..received] != expected.as_bytes()[..received] {
            return Err("invalid listener ready ack".to_owned());
        }
    }
    Ok(())
}

pub(super) fn listener_handoff_token() -> Result<String, String> {
    use std::io::Read;
    let mut bytes = [0; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("create handoff token: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod ready_tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    #[test]
    fn ack_requires_matching_token_and_version() {
        for message in [
            "DAE_LISTENER_READY_V1 abc\n",
            "DAE_LISTENER_READY_V1 def\n",
            "DAE_LISTENER_READY_V0 abc\n",
        ] {
            let (a, mut b) = UnixStream::pair().unwrap();
            b.write_all(message.as_bytes()).unwrap();
            assert_eq!(
                await_listener_ready(a.as_raw_fd(), "abc", Duration::from_millis(100)).is_ok(),
                message.ends_with("V1 abc\n")
            );
        }
    }
    #[test]
    fn missing_ack_and_closed_or_failed_delivery_are_bounded_errors() {
        let (a, b) = UnixStream::pair().unwrap();
        assert!(
            await_listener_ready(a.as_raw_fd(), "abc", Duration::from_millis(10))
                .unwrap_err()
                .contains("timed out")
        );
        drop(b);
        assert!(await_listener_ready(a.as_raw_fd(), "abc", Duration::from_millis(100)).is_err());
        assert!(send_fd_handoff(a.as_raw_fd(), b"prepare", &[a.as_raw_fd()]).is_err());
    }
    #[test]
    fn fragmented_stream_ack_is_supported() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            b.write_all(b"DAE_LISTENER_").unwrap();
            b.write_all(b"READY_V1 abc\n").unwrap();
        });
        await_listener_ready(a.as_raw_fd(), "abc", Duration::from_secs(1)).unwrap();
        writer.join().unwrap();
    }
}
