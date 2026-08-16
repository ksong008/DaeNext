use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpLivenessPolicy {
    keepalive_idle_seconds: i32,
    keepalive_interval_seconds: i32,
}

impl TcpLivenessPolicy {
    pub const fn keepalive_idle_seconds(self) -> i32 {
        self.keepalive_idle_seconds
    }

    pub const fn keepalive_interval_seconds(self) -> i32 {
        self.keepalive_interval_seconds
    }
}

pub const DEFAULT_TCP_LIVENESS_POLICY: TcpLivenessPolicy = TcpLivenessPolicy {
    keepalive_idle_seconds: 45,
    keepalive_interval_seconds: 45,
};

pub(crate) fn apply_tcp_liveness_policy(fd: OwnedFd) -> io::Result<OwnedFd> {
    apply_tcp_liveness_policy_with(fd, DEFAULT_TCP_LIVENESS_POLICY, set_i32_option)
}

fn apply_tcp_liveness_policy_with(
    fd: OwnedFd,
    policy: TcpLivenessPolicy,
    mut set_option: impl FnMut(i32, i32, i32, i32) -> io::Result<()>,
) -> io::Result<OwnedFd> {
    let raw_fd = fd.as_raw_fd();
    set_option(raw_fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)
        .map_err(|err| tcp_liveness_option_error("SO_KEEPALIVE", err))?;
    set_option(
        raw_fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPIDLE,
        policy.keepalive_idle_seconds,
    )
    .map_err(|err| tcp_liveness_option_error("TCP_KEEPIDLE", err))?;
    set_option(
        raw_fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        policy.keepalive_interval_seconds,
    )
    .map_err(|err| tcp_liveness_option_error("TCP_KEEPINTVL", err))?;
    Ok(fd)
}

fn set_i32_option(fd: i32, level: i32, option: i32, value: i32) -> io::Result<()> {
    let status = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const i32).cast::<libc::c_void>(),
            size_of::<i32>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn tcp_liveness_option_error(option: &str, err: io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!("set TCP liveness option {option}: {err}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn required_option_failures_are_contextual_and_close_the_socket() {
        for (failed_call, expected_option) in [
            (0, "SO_KEEPALIVE"),
            (1, "TCP_KEEPIDLE"),
            (2, "TCP_KEEPINTVL"),
        ] {
            let (socket, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let fd: OwnedFd = socket.into();
            let mut call = 0_usize;
            let result = apply_tcp_liveness_policy_with(
                fd,
                DEFAULT_TCP_LIVENESS_POLICY,
                |_fd, _level, _option, _value| {
                    let current_call = call;
                    call += 1;
                    if current_call == failed_call {
                        return Err(io::Error::from_raw_os_error(libc::EPERM));
                    }
                    Ok(())
                },
            );

            let err = result.unwrap_err();
            assert!(
                err.to_string().contains(expected_option),
                "missing option context in {err}"
            );
            let mut byte = [0_u8; 1];
            assert_eq!(
                peer.read(&mut byte).unwrap(),
                0,
                "failed configuration leaked socket"
            );
        }
    }
}
