use std::fs::File;
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;

const IPV6_TRANSPARENT: libc::c_int = 75;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TproxySocketOptions {
    pub ip_transparent: bool,
    pub ipv6_transparent: bool,
    pub so_reuseaddr: bool,
    pub ip_recvorigdstaddr: bool,
    pub ipv6_recvorigdstaddr: bool,
    pub original_dst_capture_ready: bool,
}

#[derive(Debug)]
pub struct TproxyListenerSet {
    pub tcp_listener: TcpListener,
    pub udp_socket: UdpSocket,
    pub tcp_options: TproxySocketOptions,
    pub udp_options: TproxySocketOptions,
}

pub fn open_tproxy_listener_set(port: u16) -> io::Result<TproxyListenerSet> {
    let tcp_fd = open_tproxy_bound_socket(libc::SOCK_STREAM, port)?;
    let listen_status = unsafe { libc::listen(tcp_fd.as_raw_fd(), 128) };
    if listen_status < 0 {
        return Err(io::Error::last_os_error());
    }

    let udp_fd = open_tproxy_bound_socket(libc::SOCK_DGRAM, port)?;

    let tcp_options = read_options(tcp_fd.as_raw_fd())?;
    let udp_options = read_options(udp_fd.as_raw_fd())?;
    let tcp_listener = unsafe { TcpListener::from_raw_fd(tcp_fd.into_raw_fd()) };
    let udp_socket = unsafe { UdpSocket::from_raw_fd(udp_fd.into_raw_fd()) };

    Ok(TproxyListenerSet {
        tcp_listener,
        udp_socket,
        tcp_options,
        udp_options,
    })
}

pub fn open_tproxy_listener_set_in_netns(
    netns_name: &str,
    port: u16,
) -> io::Result<TproxyListenerSet> {
    let current = File::open("/proc/self/ns/net")?;
    let target = open_named_netns(netns_name)?;
    let guard = NetnsGuard::enter(current, target)?;
    let result = open_tproxy_listener_set(port);
    let restore = guard.restore();
    match (result, restore) {
        (Ok(listeners), Ok(())) => Ok(listeners),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Err(restore_err)) => Err(io::Error::new(
            err.kind(),
            format!("{err}; failed to restore netns: {restore_err}"),
        )),
    }
}

pub fn open_transparent_udp_socket_bound_in_netns(
    netns_name: &str,
    addr: SocketAddr,
) -> io::Result<UdpSocket> {
    let current = File::open("/proc/self/ns/net")?;
    let target = open_named_netns(netns_name)?;
    let guard = NetnsGuard::enter(current, target)?;
    let result = open_transparent_udp_socket_bound(addr);
    let restore = guard.restore();
    match (result, restore) {
        (Ok(socket), Ok(())) => Ok(socket),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Err(restore_err)) => Err(io::Error::new(
            err.kind(),
            format!("{err}; failed to restore netns: {restore_err}"),
        )),
    }
}

pub fn open_transparent_udp_socket_bound(addr: SocketAddr) -> io::Result<UdpSocket> {
    let udp_fd = open_socket(socket_family(addr), libc::SOCK_DGRAM)?;
    apply_tproxy_control(udp_fd.as_raw_fd())?;
    bind_socket_addr(udp_fd.as_raw_fd(), addr)?;
    Ok(unsafe { UdpSocket::from_raw_fd(udp_fd.into_raw_fd()) })
}

fn open_named_netns(name: &str) -> io::Result<File> {
    let mut last_err = None;
    for parent in ["/run/netns", "/var/run/netns"] {
        match File::open(PathBuf::from(parent).join(name)) {
            Ok(file) => return Ok(file),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "netns not found")))
}

struct NetnsGuard {
    current: File,
    restored: bool,
}

impl NetnsGuard {
    fn enter(current: File, target: File) -> io::Result<Self> {
        set_netns(target.as_raw_fd())?;
        Ok(Self {
            current,
            restored: false,
        })
    }

    fn restore(mut self) -> io::Result<()> {
        // N-06: 只有在 setns 成功后标记 restored；失败时保持未恢复，
        // Drop 会再次尝试回到当前 netns。
        set_netns(self.current.as_raw_fd())?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        if !self.restored {
            let _ = set_netns(self.current.as_raw_fd());
        }
    }
}

fn set_netns(fd: i32) -> io::Result<()> {
    let status = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn open_socket(family: libc::c_int, socket_type: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(family, socket_type | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_tproxy_bound_socket(socket_type: libc::c_int, port: u16) -> io::Result<OwnedFd> {
    match open_dual_stack_tproxy_bound_socket(socket_type, port) {
        Ok(fd) => Ok(fd),
        Err(ipv6_err) => open_ipv4_tproxy_bound_socket(socket_type, port).map_err(|ipv4_err| {
            io::Error::new(
                ipv4_err.kind(),
                format!(
                    "open dual-stack IPv6 tproxy socket: {ipv6_err}; open IPv4 tproxy socket: {ipv4_err}"
                ),
            )
        }),
    }
}

fn open_dual_stack_tproxy_bound_socket(socket_type: libc::c_int, port: u16) -> io::Result<OwnedFd> {
    let fd = open_socket(libc::AF_INET6, socket_type)?;
    set_dual_stack(fd.as_raw_fd())?;
    apply_tproxy_control(fd.as_raw_fd())?;
    bind_ipv6_any(fd.as_raw_fd(), port)?;
    Ok(fd)
}

fn open_ipv4_tproxy_bound_socket(socket_type: libc::c_int, port: u16) -> io::Result<OwnedFd> {
    let fd = open_socket(libc::AF_INET, socket_type)?;
    apply_tproxy_control(fd.as_raw_fd())?;
    bind_ipv4_any(fd.as_raw_fd(), port)?;
    Ok(fd)
}

fn apply_tproxy_control(fd: i32) -> io::Result<()> {
    set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    let ipv4_transparent = set_opt(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT, 1);
    let ipv6_transparent = set_opt(fd, libc::SOL_IPV6, IPV6_TRANSPARENT, 1);
    if ipv4_transparent.is_err() && ipv6_transparent.is_err() {
        return Err(ipv4_transparent
            .err()
            .unwrap_or_else(io::Error::last_os_error));
    }
    let ipv4 = set_opt(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1);
    let ipv6 = set_opt(fd, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR, 1);
    if ipv4.is_err() && ipv6.is_err() {
        return Err(ipv4.err().unwrap_or_else(io::Error::last_os_error));
    }
    Ok(())
}

fn set_dual_stack(fd: i32) -> io::Result<()> {
    set_opt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0)
}

fn bind_ipv4_any(fd: i32, port: u16) -> io::Result<()> {
    bind_ipv4(fd, Ipv4Addr::UNSPECIFIED, port)
}

fn bind_ipv4(fd: i32, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
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

fn bind_ipv6(fd: i32, ip: Ipv6Addr, port: u16) -> io::Result<()> {
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: ip.octets(),
        },
        sin6_scope_id: 0,
    };
    let status = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in6).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind_ipv6_any(fd: i32, port: u16) -> io::Result<()> {
    bind_ipv6(fd, Ipv6Addr::UNSPECIFIED, port)
}

fn bind_socket_addr(fd: i32, addr: SocketAddr) -> io::Result<()> {
    match addr {
        SocketAddr::V4(addr) => bind_ipv4(fd, *addr.ip(), addr.port()),
        SocketAddr::V6(addr) => bind_ipv6(fd, *addr.ip(), addr.port()),
    }
}

fn socket_family(addr: SocketAddr) -> libc::c_int {
    match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    }
}

fn read_options(fd: i32) -> io::Result<TproxySocketOptions> {
    let ip_transparent = get_opt(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT).unwrap_or(0) != 0;
    let ipv6_transparent = get_opt(fd, libc::SOL_IPV6, IPV6_TRANSPARENT).unwrap_or(0) != 0;
    let so_reuseaddr = get_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR)? != 0;
    let ip_recvorigdstaddr = get_opt(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR).unwrap_or(0) != 0;
    let ipv6_recvorigdstaddr =
        get_opt(fd, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR).unwrap_or(0) != 0;
    Ok(TproxySocketOptions {
        ip_transparent,
        ipv6_transparent,
        so_reuseaddr,
        ip_recvorigdstaddr,
        ipv6_recvorigdstaddr,
        original_dst_capture_ready: ip_recvorigdstaddr || ipv6_recvorigdstaddr,
    })
}

fn set_opt(fd: i32, level: i32, option: i32, value: i32) -> io::Result<()> {
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

fn get_opt(fd: i32, level: i32, option: i32) -> io::Result<i32> {
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
