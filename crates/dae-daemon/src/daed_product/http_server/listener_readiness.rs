use std::{
    io,
    net::TcpListener,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

pub(super) const LISTENER_SHUTDOWN_CHECK_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ListenerReadiness {
    Ready,
    TimedOut,
}

pub(super) fn wait_for_listener_readiness(
    listener: &TcpListener,
    timeout: Duration,
) -> io::Result<ListenerReadiness> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut descriptor = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(ListenerReadiness::TimedOut);
        }
        descriptor.revents = 0;
        let timeout_millis = duration_to_poll_timeout(remaining);
        // SAFETY: `descriptor` points to one initialized pollfd for the live
        // TcpListener. poll only mutates revents during this call.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_millis) };
        if result > 0 {
            return Ok(ListenerReadiness::Ready);
        }
        if result == 0 {
            return Ok(ListenerReadiness::TimedOut);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn duration_to_poll_timeout(duration: Duration) -> libc::c_int {
    duration.as_millis().max(1).min(libc::c_int::MAX as u128) as libc::c_int
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpStream, thread};

    #[test]
    fn incoming_connection_wakes_listener_without_waiting_for_timeout() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let connector = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            TcpStream::connect(address).unwrap()
        });

        let started = Instant::now();
        assert_eq!(
            wait_for_listener_readiness(&listener, Duration::from_secs(1)).unwrap(),
            ListenerReadiness::Ready
        );
        assert!(started.elapsed() < Duration::from_millis(200));
        let (_server, _) = listener.accept().unwrap();
        drop(connector.join().unwrap());
    }

    #[test]
    fn idle_listener_reports_timeout() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();

        let started = Instant::now();
        assert_eq!(
            wait_for_listener_readiness(&listener, Duration::from_millis(20)).unwrap(),
            ListenerReadiness::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(10));
    }
}
