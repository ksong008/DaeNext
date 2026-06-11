use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDirectSocketOptions {
    pub mark: u32,
    pub timeout: Duration,
}

impl Default for UdpDirectSocketOptions {
    fn default() -> Self {
        Self {
            mark: 0,
            timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDirectSocketReport {
    pub requested_mark: u32,
    pub so_mark: u32,
    pub so_mark_applied: bool,
    pub peer_addr: String,
    pub local_addr: String,
}

#[derive(Debug)]
pub struct UdpDirectPacketConn {
    socket: UdpSocket,
    target: SocketAddr,
    report: UdpDirectSocketReport,
}

impl UdpDirectPacketConn {
    pub fn connect(
        target: SocketAddr,
        opts: &UdpDirectSocketOptions,
    ) -> io::Result<UdpDirectPacketConn> {
        let bind = match target {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(opts.timeout))?;
        socket.set_write_timeout(Some(opts.timeout))?;
        if opts.mark != 0 {
            set_so_mark(socket.as_raw_fd(), opts.mark)?;
        }
        let so_mark = get_so_mark(socket.as_raw_fd()).unwrap_or(0);
        let peer_addr = target.to_string();
        let local_addr = socket
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        Ok(Self {
            socket,
            target,
            report: UdpDirectSocketReport {
                requested_mark: opts.mark,
                so_mark,
                so_mark_applied: opts.mark == 0 || so_mark == opts.mark,
                peer_addr,
                local_addr,
            },
        })
    }

    pub fn exchange(&self, payload: &[u8], response_len: usize) -> io::Result<Vec<u8>> {
        self.write_to(payload, self.target)?;
        let (response, _) = self.read_from(response_len)?;
        Ok(response)
    }

    pub fn write_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(payload, target)
    }

    pub fn read_from(&self, response_len: usize) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut response = vec![0_u8; response_len];
        let (read, peer) = self.socket.recv_from(&mut response)?;
        response.truncate(read);
        Ok((response, peer))
    }

    pub fn target(&self) -> SocketAddr {
        self.target
    }

    pub fn report(&self) -> &UdpDirectSocketReport {
        &self.report
    }
}

fn set_so_mark(fd: i32, mark: u32) -> io::Result<()> {
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
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_so_mark(fd: i32) -> io::Result<u32> {
    let mut mark: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut mark as *mut libc::c_int).cast::<libc::c_void>(),
            &mut len as *mut libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(mark as u32)
}
