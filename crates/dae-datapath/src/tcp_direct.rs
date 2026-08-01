use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::time::Duration;

use crate::tcp_liveness::apply_tcp_liveness_policy;

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
    pub mptcp_tcp_retry_used: bool,
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

#[derive(Debug)]
pub struct TcpDirectConnectAttempt {
    stream: TcpStream,
    state: TcpDirectConnectState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpDirectConnectState {
    pub target: SocketAddr,
    pub opts: TcpDirectDialOptions,
    pub mptcp_socket_created: bool,
    pub mptcp_tcp_retry_used: bool,
}

impl TcpDirectConnectAttempt {
    pub fn into_parts(self) -> (TcpStream, TcpDirectConnectState) {
        (self.stream, self.state)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpLoopbackListenerReport {
    pub requested_mptcp: bool,
    pub mptcp_socket_created: bool,
    pub tcp_socket_retry_used: bool,
    pub socket_protocol: i32,
    pub local_addr: String,
}

pub fn bind_loopback_tcp_listener(
    requested_mptcp: bool,
) -> io::Result<(TcpListener, TcpLoopbackListenerReport)> {
    bind_loopback_tcp_listener_on_port(requested_mptcp, 0)
}

pub fn bind_loopback_tcp_listener_on_port(
    requested_mptcp: bool,
    port: u16,
) -> io::Result<(TcpListener, TcpLoopbackListenerReport)> {
    let (fd, mptcp_socket_created, tcp_socket_retry_used) =
        open_tcp_socket(libc::AF_INET, requested_mptcp)?;
    set_reuse_addr(fd.as_raw_fd())?;
    bind_loopback_port(fd.as_raw_fd(), port)?;
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
            tcp_socket_retry_used,
            socket_protocol,
            local_addr,
        },
    ))
}

pub fn magic_tcp_connect(
    target: SocketAddr,
    opts: &TcpDirectDialOptions,
) -> io::Result<TcpDirectConnection> {
    match connect_with_protocol(target, opts, opts.mptcp) {
        Ok(mut connected) => {
            connected.report.mptcp_tcp_retry_used = false;
            Ok(connected)
        }
        Err(first_err) if opts.mptcp => match connect_with_protocol(target, opts, false) {
            Ok(mut connected) => {
                connected.report.mptcp_socket_attempted = true;
                connected.report.mptcp_tcp_retry_used = true;
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

pub fn tcp_direct_connect_start(
    target: SocketAddr,
    opts: &TcpDirectDialOptions,
    use_mptcp: bool,
) -> io::Result<TcpDirectConnectAttempt> {
    let family = socket_family(target);
    let (fd, mptcp_socket_created, _) =
        open_outbound_tcp_socket_with_flags(family, use_mptcp, libc::SOCK_NONBLOCK)?;
    if opts.mark != 0 {
        set_so_mark(fd.as_raw_fd(), opts.mark)?;
    }
    connect_nonblocking(fd.as_raw_fd(), target)?;
    let stream = unsafe { TcpStream::from_raw_fd(fd.into_raw_fd()) };
    Ok(TcpDirectConnectAttempt {
        stream,
        state: TcpDirectConnectState {
            target,
            opts: opts.clone(),
            mptcp_socket_created,
            mptcp_tcp_retry_used: false,
        },
    })
}

pub fn tcp_direct_connect_finish(
    stream: TcpStream,
    state: TcpDirectConnectState,
) -> io::Result<TcpDirectConnection> {
    let so_error = get_socket_error(stream.as_raw_fd())?;
    if so_error != 0 {
        return Err(io::Error::from_raw_os_error(so_error));
    }
    finish_tcp_direct_connection(stream, state)
}

fn connect_with_protocol(
    target: SocketAddr,
    opts: &TcpDirectDialOptions,
    use_mptcp: bool,
) -> io::Result<TcpDirectConnection> {
    let (fd, mptcp_socket_created, tcp_socket_retry_used) =
        open_outbound_tcp_socket_with_flags(socket_family(target), use_mptcp, 0)?;
    set_timeouts(fd.as_raw_fd(), opts.timeout)?;
    if opts.mark != 0 {
        set_so_mark(fd.as_raw_fd(), opts.mark)?;
    }
    connect_socket_addr(fd.as_raw_fd(), target)?;
    let socket_protocol = get_socket_protocol(fd.as_raw_fd()).unwrap_or(0);
    let so_mark = get_so_mark(fd.as_raw_fd()).unwrap_or(0);
    let mptcp_info = read_mptcp_info_status(fd.as_raw_fd());
    let stream = unsafe { TcpStream::from_raw_fd(fd.into_raw_fd()) };
    let peer_addr = stream.peer_addr().unwrap_or(target).to_string();
    let local_addr = stream
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    Ok(TcpDirectConnection {
        stream,
        report: tcp_direct_dial_report(
            target,
            opts,
            mptcp_socket_created,
            tcp_socket_retry_used,
            socket_protocol,
            so_mark,
            mptcp_info,
            peer_addr,
            local_addr,
        ),
    })
}

fn open_tcp_socket(
    family: libc::c_int,
    requested_mptcp: bool,
) -> io::Result<(OwnedFd, bool, bool)> {
    open_tcp_socket_with_flags(family, requested_mptcp, 0)
}

fn open_tcp_socket_with_flags(
    family: libc::c_int,
    requested_mptcp: bool,
    socket_flags: libc::c_int,
) -> io::Result<(OwnedFd, bool, bool)> {
    if requested_mptcp && let Ok(fd) = open_socket_with_flags(family, IPPROTO_MPTCP, socket_flags) {
        return Ok((fd, true, false));
    }
    open_socket_with_flags(family, libc::IPPROTO_TCP, socket_flags)
        .map(|fd| (fd, false, requested_mptcp))
}

fn open_outbound_tcp_socket_with_flags(
    family: libc::c_int,
    requested_mptcp: bool,
    socket_flags: libc::c_int,
) -> io::Result<(OwnedFd, bool, bool)> {
    let (fd, mptcp_socket_created, tcp_socket_retry_used) =
        open_tcp_socket_with_flags(family, requested_mptcp, socket_flags)?;
    let fd = apply_tcp_liveness_policy(fd)?;
    Ok((fd, mptcp_socket_created, tcp_socket_retry_used))
}

fn open_socket(protocol: libc::c_int) -> io::Result<OwnedFd> {
    open_socket_with_flags(libc::AF_INET, protocol, 0)
}

fn open_socket_with_flags(
    family: libc::c_int,
    protocol: libc::c_int,
    socket_flags: libc::c_int,
) -> io::Result<OwnedFd> {
    // SAFETY: socket is called with a valid address family/type/protocol
    // combination supplied by this module. A non-negative fd is immediately
    // wrapped in OwnedFd below so it is closed on all later error paths.
    let fd = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | socket_flags,
            protocol,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, non-negative descriptor returned by socket and
    // ownership has not been transferred anywhere else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bind_loopback_port(fd: i32, port: u16) -> io::Result<()> {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
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

fn connect_socket_addr(fd: i32, target: SocketAddr) -> io::Result<()> {
    let (storage, len) = sockaddr_from_socket_addr(target);
    let status = unsafe {
        libc::connect(
            fd,
            (&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr>(),
            len,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn connect_nonblocking(fd: i32, target: SocketAddr) -> io::Result<()> {
    let (storage, len) = sockaddr_from_socket_addr(target);
    let status = unsafe {
        libc::connect(
            fd,
            (&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr>(),
            len,
        )
    };
    if status == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if matches!(
        err.raw_os_error(),
        Some(code)
            if code == libc::EINPROGRESS
                || code == libc::EWOULDBLOCK
                || code == libc::EALREADY
    ) {
        return Ok(());
    }
    Err(err)
}

fn socket_family(addr: SocketAddr) -> libc::c_int {
    match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    }
}

fn sockaddr_from_socket_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(addr) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw);
            }
            (storage, size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(addr) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            unsafe {
                std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw);
            }
            (storage, size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
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

fn get_socket_error(fd: i32) -> io::Result<i32> {
    get_i32_opt(fd, libc::SOL_SOCKET, libc::SO_ERROR)
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

fn finish_tcp_direct_connection(
    stream: TcpStream,
    state: TcpDirectConnectState,
) -> io::Result<TcpDirectConnection> {
    let socket_protocol = get_socket_protocol(stream.as_raw_fd()).unwrap_or(0);
    let so_mark = get_so_mark(stream.as_raw_fd()).unwrap_or(0);
    let mptcp_info = read_mptcp_info_status(stream.as_raw_fd());
    let peer_addr = stream.peer_addr().unwrap_or(state.target).to_string();
    let local_addr = stream
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    Ok(TcpDirectConnection {
        stream,
        report: tcp_direct_dial_report(
            state.target,
            &state.opts,
            state.mptcp_socket_created,
            state.mptcp_tcp_retry_used,
            socket_protocol,
            so_mark,
            mptcp_info,
            peer_addr,
            local_addr,
        ),
    })
}

// Report assembly keeps the observable socket fields explicit.
#[allow(clippy::too_many_arguments)]
fn tcp_direct_dial_report(
    _target: SocketAddr,
    opts: &TcpDirectDialOptions,
    mptcp_socket_created: bool,
    mptcp_tcp_retry_used: bool,
    socket_protocol: i32,
    so_mark: u32,
    mptcp_info: MptcpInfoStatus,
    peer_addr: String,
    local_addr: String,
) -> TcpDirectDialReport {
    TcpDirectDialReport {
        requested_mark: opts.mark,
        requested_mptcp: opts.mptcp,
        mptcp_socket_attempted: opts.mptcp,
        mptcp_socket_created,
        mptcp_tcp_retry_used,
        socket_protocol,
        so_mark,
        so_mark_applied: opts.mark == 0 || so_mark == opts.mark,
        mptcp_info_available: mptcp_info.available,
        mptcp_fallen_back: mptcp_info.fallen_back,
        mptcp_protocol_observed: socket_protocol == IPPROTO_MPTCP,
        peer_addr,
        local_addr,
    }
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
