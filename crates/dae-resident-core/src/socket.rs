pub fn set_socket_mark(fd: i32, mark: u32) -> std::io::Result<()> {
    let mark = mark as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SocketBufferSetting {
    kernel_bytes: Option<usize>,
    set_errno: Option<i32>,
    read_errno: Option<i32>,
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct UdpSocketBufferObservation {
    requested_bytes: usize,
    receive: SocketBufferSetting,
    send: SocketBufferSetting,
}

#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct UdpSocketBufferObservations {
    sockets_tuned: u64,
    set_errors: u64,
    read_errors: u64,
    last_observation_per_request: Vec<UdpSocketBufferObservation>,
}

static UDP_SOCKET_BUFFERS: std::sync::OnceLock<std::sync::Mutex<UdpSocketBufferObservations>> =
    std::sync::OnceLock::new();

pub fn apply_udp_socket_buffer_tuning(fd: i32, bytes: usize) {
    let observation = tune_udp_socket_buffers(fd, bytes);
    let mut observations = UDP_SOCKET_BUFFERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    observations.sockets_tuned = observations.sockets_tuned.saturating_add(1);
    for setting in [&observation.receive, &observation.send] {
        observations.set_errors = observations
            .set_errors
            .saturating_add(u64::from(setting.set_errno.is_some()));
        observations.read_errors = observations
            .read_errors
            .saturating_add(u64::from(setting.read_errno.is_some()));
    }
    // This is bounded process-level observation history, not a live-fd registry.
    observations
        .last_observation_per_request
        .retain(|old| old.requested_bytes != bytes);
    if observations.last_observation_per_request.len() == 8 {
        observations.last_observation_per_request.remove(0);
    }
    observations.last_observation_per_request.push(observation);
}

pub fn udp_socket_buffer_tuning_snapshot() -> serde_json::Value {
    let observations = UDP_SOCKET_BUFFERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    serde_json::json!({
        "scope": "process-lifetime tuning attempts; latest socket per requested size, not all live sockets",
        "kernelBytesScope": "getsockopt accounting value; Linux includes doubled skb overhead",
        "observations": &*observations,
    })
}

fn tune_udp_socket_buffers(fd: i32, bytes: usize) -> UdpSocketBufferObservation {
    let tune = |option| {
        let set_errno = set_socket_buffer_bytes(fd, option, bytes)
            .err()
            .and_then(|error| error.raw_os_error());
        let read = socket_buffer_bytes(fd, option);
        SocketBufferSetting {
            kernel_bytes: read.as_ref().ok().copied(),
            set_errno,
            read_errno: read.err().and_then(|error| error.raw_os_error()),
        }
    };
    UdpSocketBufferObservation {
        requested_bytes: bytes,
        receive: tune(libc::SO_RCVBUF),
        send: tune(libc::SO_SNDBUF),
    }
}

fn socket_buffer_bytes(fd: i32, option: i32) -> std::io::Result<usize> {
    let mut bytes: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&bytes) as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut bytes as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(bytes.max(0) as usize)
}

fn set_socket_buffer_bytes(fd: i32, option: i32, bytes: usize) -> std::io::Result<()> {
    let value = bytes.min(i32::MAX as usize) as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&value as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn udp_socket_tuning_reports_kernel_values_and_errors() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for requested in [64 * 1024, 8 * 1024 * 1024] {
            let result = tune_udp_socket_buffers(socket.as_raw_fd(), requested);
            assert_eq!(result.requested_bytes, requested);
            for (setting, option) in [
                (&result.receive, libc::SO_RCVBUF),
                (&result.send, libc::SO_SNDBUF),
            ] {
                assert_eq!(setting.set_errno, None);
                assert_eq!(setting.read_errno, None);
                assert_eq!(
                    setting.kernel_bytes,
                    Some(socket_buffer_bytes(socket.as_raw_fd(), option).unwrap())
                );
                assert!(setting.kernel_bytes.unwrap() > 0);
            }
        }
        let result = tune_udp_socket_buffers(-1, 512 * 1024);
        for setting in [&result.receive, &result.send] {
            assert_eq!(setting.kernel_bytes, None);
            assert_eq!(setting.set_errno, Some(libc::EBADF));
            assert_eq!(setting.read_errno, Some(libc::EBADF));
        }
    }
}
