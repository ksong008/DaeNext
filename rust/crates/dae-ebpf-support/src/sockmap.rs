use std::io;
use std::mem::size_of;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
const BPF_MAP_TYPE_SOCKMAP: u32 = 15;
const BPF_ANY: u64 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenSocketMapFdSmoke {
    pub map_type: &'static str,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub keys_updated: [u32; 2],
    pub tcp_listener_fd: i32,
    pub udp_socket_fd: i32,
}

pub fn run_listen_socket_map_fd_smoke() -> io::Result<ListenSocketMapFdSmoke> {
    let map_fd = create_sockmap()?;
    let tcp_listener = TcpListener::bind(("127.0.0.1", 0))?;
    let udp_socket = UdpSocket::bind(("127.0.0.1", 0))?;

    update_sockmap_fd(map_fd.as_raw_fd(), 0, tcp_listener.as_raw_fd())?;
    update_sockmap_fd(map_fd.as_raw_fd(), 1, udp_socket.as_raw_fd())?;

    Ok(ListenSocketMapFdSmoke {
        map_type: "SockMap",
        key_size: 4,
        value_size: 8,
        max_entries: 2,
        keys_updated: [0, 1],
        tcp_listener_fd: tcp_listener.as_raw_fd(),
        udp_socket_fd: udp_socket.as_raw_fd(),
    })
}

fn create_sockmap() -> io::Result<OwnedFd> {
    let mut attr = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_SOCKMAP,
        key_size: 4,
        value_size: 8,
        max_entries: 2,
        ..BpfMapCreateAttr::default()
    };
    attr.map_name[..12].copy_from_slice(b"dae36sockmap");
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const BpfMapCreateAttr,
            size_of::<BpfMapCreateAttr>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn update_sockmap_fd(map_fd: i32, key: u32, socket_fd: i32) -> io::Result<()> {
    let value = socket_fd as u64;
    let attr = BpfMapUpdateElemAttr {
        map_fd: map_fd as u32,
        key: (&key as *const u32) as u64,
        value: (&value as *const u64) as u64,
        flags: BPF_ANY,
        ..BpfMapUpdateElemAttr::default()
    };
    let status = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr as *const BpfMapUpdateElemAttr,
            size_of::<BpfMapUpdateElemAttr>(),
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapUpdateElemAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}
