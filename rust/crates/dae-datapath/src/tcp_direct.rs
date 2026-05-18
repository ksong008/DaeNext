use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::time::Duration;

const IPPROTO_MPTCP: libc::c_int = 262;
const SOL_MPTCP: libc::c_int = 284;
const MPTCP_INFO: libc::c_int = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpDirectDialOptions {
    pub mark: u32,
    pub mptcp: bool,
    pub timeout: Duration,
}

impl Default for TcpDirectDialOptions {
    fn default() -> Self {
        Self {
            mark: 0,
            mptcp: false,
            timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpDirectDialReport {
    pub requested_mark: u32,
    pub requested_mptcp: bool,
    pub mptcp_socket_attempted: bool,
    pub mptcp_socket_created: bool,
    pub mptcp_connect_fallback_used: bool,
    pub socket_protocol: i32,
    pub so_mark: u32,
    pub so_mark_applied: bool,
    pub mptcp_info_available: bool,
    pub mptcp_fallen_back: bool,
    pub mptcp_protocol_observed: bool,
    pub peer_addr: String,
    pub local_addr: String,
}

#[derive(Debug)]
pub struct TcpDirectConnection {
    pub stream: TcpStream,
    pub report: TcpDirectDialReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpLoopbackListenerReport {
    pub requested_mptcp: bool,
    pub mptcp_socket_created: bool,
    pub fallback_used: bool,
    pub socket_protocol: i32,
    pub local_addr: String,
}

pub fn bind_loopback_tcp_listener(
    requested_mptcp: bool,
) -> io::Result<(TcpListener, TcpLoopbackListenerReport)> {
    let (fd, mptcp_socket_created, fallback_used) = open_tcp_socket(requested_mptcp)?;
    set_reuse_addr(fd.as_raw_fd())?;
    bind_loopback_any_port(fd.as_raw_fd())?;
    let listen_status = unsafe { libc::listen(fd.as_raw_fd(), 128) };
    if listen_status < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket_protocol = get_socket_protocol(fd.as_raw_fd()).unwrap_or(0);
    let listener = unsafe { TcpListener::from_raw_fd(fd.into_raw_fd()) };
    let local_addr = listener.local_addr()?.to_string();
    Ok((
        listener,
        TcpLoopbackListenerReport {
            requested_mptcp,
            mptcp_socket_created,
            fallback_used,
            socket_protocol,
            local_addr,
        },
    ))
}

pub fn magic_tcp_connect(
    target: SocketAddrV4,
    opts: &TcpDirectDialOptions,
) -> io::Result<TcpDirectConnection> {
    match connect_with_protocol(target, opts, opts.mptcp) {
        Ok(mut connected) => {
            connected.report.mptcp_connect_fallback_used = false;
            Ok(connected)
        }
        Err(first_err) if opts.mptcp => match connect_with_protocol(target, opts, false) {
            Ok(mut connected) => {
                connected.report.mptcp_socket_attempted = true;
                connected.report.mptcp_connect_fallback_used = true;
                Ok(connected)
            }
            Err(_) => Err(first_err),
        },
        Err(err) => Err(err),
    }
}

pub fn mptcp_socket_supported() -> bool {
    open_socket(IPPROTO_MPTCP).is_ok()
}

fn connect_with_protocol(
    target: SocketAddrV4,
    opts: &TcpDirectDialOptions,
    use_mptcp: bool,
) -> io::Result<TcpDirectConnection> {
    let (fd, mptcp_socket_created, fallback_used) = open_tcp_socket(use_mptcp)?;
    set_timeouts(fd.as_raw_fd(), opts.timeout)?;
    if opts.mark != 0 {
        set_so_mark(fd.as_raw_fd(), opts.mark)?;
    }
    connect_ipv4(fd.as_raw_fd(), target)?;
    let socket_protocol = get_socket_protocol(fd.as_raw_fd()).unwrap_or(0);
    let so_mark = get_so_mark(fd.as_raw_fd()).unwrap_or(0);
    let mptcp_info = read_mptcp_info_status(fd.as_raw_fd());
    let stream = unsafe { TcpStream::from_raw_fd(fd.into_raw_fd()) };
    let peer_addr = stream
        .peer_addr()
        .unwrap_or(SocketAddr::V4(target))
        .to_string();
    let local_addr = stream
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    Ok(TcpDirectConnection {
        stream,
        report: TcpDirectDialReport {
            requested_mark: opts.mark,
            requested_mptcp: opts.mptcp,
            mptcp_socket_attempted: opts.mptcp,
            mptcp_socket_created,
            mptcp_connect_fallback_used: fallback_used,
            socket_protocol,
            so_mark,
            so_mark_applied: opts.mark == 0 || so_mark == opts.mark,
            mptcp_info_available: mptcp_info.available,
            mptcp_fallen_back: mptcp_info.fallen_back,
            mptcp_protocol_observed: socket_protocol == IPPROTO_MPTCP,
            peer_addr,
            local_addr,
        },
    })
}

fn open_tcp_socket(requested_mptcp: bool) -> io::Result<(OwnedFd, bool, bool)> {
    if requested_mptcp {
        match open_socket(IPPROTO_MPTCP) {
            Ok(fd) => return Ok((fd, true, false)),
            Err(_) => {}
        }
    }
    open_socket(libc::IPPROTO_TCP).map(|fd| (fd, false, requested_mptcp))
}

fn open_socket(protocol: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bind_loopback_any_port(fd: i32) -> io::Result<()> {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0_u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
        },
        sin_zero: [0; 8],
    };
    let status = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn connect_ipv4(fd: i32, target: SocketAddrV4) -> io::Result<()> {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: target.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(target.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    let status = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_reuse_addr(fd: i32) -> io::Result<()> {
    set_i32_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)
}

fn set_so_mark(fd: i32, mark: u32) -> io::Result<()> {
    set_i32_opt(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as i32)
}

fn get_so_mark(fd: i32) -> io::Result<u32> {
    get_i32_opt(fd, libc::SOL_SOCKET, libc::SO_MARK).map(|value| value as u32)
}

fn get_socket_protocol(fd: i32) -> io::Result<i32> {
    get_i32_opt(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL)
}

fn set_timeouts(fd: i32, timeout: Duration) -> io::Result<()> {
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    set_timeval_opt(fd, libc::SO_SNDTIMEO, timeval)?;
    set_timeval_opt(fd, libc::SO_RCVTIMEO, timeval)
}

fn set_i32_opt(fd: i32, level: i32, option: i32, value: i32) -> io::Result<()> {
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

fn set_timeval_opt(fd: i32, option: i32, timeval: libc::timeval) -> io::Result<()> {
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&timeval as *const libc::timeval).cast::<libc::c_void>(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_i32_opt(fd: i32, level: i32, option: i32) -> io::Result<i32> {
    let mut value = 0_i32;
    let mut len = size_of::<i32>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut i32).cast::<libc::c_void>(),
            &mut len as *mut libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MptcpInfoStatus {
    available: bool,
    fallen_back: bool,
}

fn read_mptcp_info_status(fd: i32) -> MptcpInfoStatus {
    let mut info = [MaybeUninit::<u8>::uninit(); 256];
    let mut len = info.len() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            SOL_MPTCP,
            MPTCP_INFO,
            info.as_mut_ptr().cast::<libc::c_void>(),
            &mut len as *mut libc::socklen_t,
        )
    };
    if status == 0 {
        return MptcpInfoStatus {
            available: true,
            fallen_back: false,
        };
    }
    let err = io::Error::last_os_error();
    let fallen_back = matches!(
        err.raw_os_error(),
        Some(code) if code == libc::EOPNOTSUPP || code == libc::ENOPROTOOPT
    );
    MptcpInfoStatus {
        available: false,
        fallen_back,
    }
}
