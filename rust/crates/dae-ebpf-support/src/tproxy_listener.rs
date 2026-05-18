use std::fs::File;
use std::io;
use std::mem::size_of;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TproxySocketOptions {
    pub ip_transparent: bool,
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
    let tcp_fd = open_socket(libc::SOCK_STREAM)?;
    apply_tproxy_control(tcp_fd.as_raw_fd())?;
    bind_ipv4_any(tcp_fd.as_raw_fd(), port)?;
    let listen_status = unsafe { libc::listen(tcp_fd.as_raw_fd(), 128) };
    if listen_status < 0 {
        return Err(io::Error::last_os_error());
    }

    let udp_fd = open_socket(libc::SOCK_DGRAM)?;
    apply_tproxy_control(udp_fd.as_raw_fd())?;
    bind_ipv4_any(udp_fd.as_raw_fd(), port)?;

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
        self.restored = true;
        set_netns(self.current.as_raw_fd())
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

fn open_socket(socket_type: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, socket_type | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn apply_tproxy_control(fd: i32) -> io::Result<()> {
    set_opt(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT, 1)?;
    set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    let ipv4 = set_opt(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1);
    let ipv6 = set_opt(fd, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR, 1);
    if ipv4.is_err() && ipv6.is_err() {
        return Err(ipv4.err().unwrap_or_else(io::Error::last_os_error));
    }
    Ok(())
}

fn bind_ipv4_any(fd: i32, port: u16) -> io::Result<()> {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([0, 0, 0, 0]),
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

fn read_options(fd: i32) -> io::Result<TproxySocketOptions> {
    let ip_transparent = get_opt(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT)? != 0;
    let so_reuseaddr = get_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR)? != 0;
    let ip_recvorigdstaddr = get_opt(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR)? != 0;
    let ipv6_recvorigdstaddr =
        get_opt(fd, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR).unwrap_or(0) != 0;
    Ok(TproxySocketOptions {
        ip_transparent,
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
