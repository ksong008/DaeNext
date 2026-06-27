use std::io;
use std::mem::size_of;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::runtime_maps::{RuntimeMapInfo, map_ids, map_info, open_map_fd};
use crate::tproxy_listener::{
    TproxyListenerSet, TproxySocketOptions, open_tproxy_listener_set,
    open_tproxy_listener_set_in_netns,
};

pub const LISTEN_SOCKET_KEY_TCP4: u32 = 0;
pub const LISTEN_SOCKET_KEY_TCP6: u32 = 1;
pub const LISTEN_SOCKET_KEY_UDP4: u32 = 2;
pub const LISTEN_SOCKET_KEY_UDP6: u32 = 3;
pub const LISTEN_SOCKET_KEYS: [u32; 4] = [
    LISTEN_SOCKET_KEY_TCP4,
    LISTEN_SOCKET_KEY_TCP6,
    LISTEN_SOCKET_KEY_UDP4,
    LISTEN_SOCKET_KEY_UDP6,
];
pub const LISTEN_SOCKET_MAP_MAX_ENTRIES: u32 = LISTEN_SOCKET_KEYS.len() as u32;

const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
const BPF_MAP_TYPE_SOCKMAP: u32 = 15;
const BPF_ANY: u64 = 0;
const LISTEN_SOCKET_MAP_KERNEL_NAME: &str = "listen_socket_m";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenSocketMapFdSmoke {
    pub map_type: &'static str,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub keys_updated: Vec<u32>,
    pub tcp_listener_fd: i32,
    pub udp_socket_fd: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedListenSocketMapFdSmoke {
    pub map: RuntimeMapInfo,
    pub new_map_ids: Vec<u32>,
    pub keys_updated: Vec<u32>,
    pub tcp_listener_fd: i32,
    pub udp_socket_fd: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedTproxyListenSocketMapFdSmoke {
    pub map: RuntimeMapInfo,
    pub new_map_ids: Vec<u32>,
    pub keys_updated: Vec<u32>,
    pub tcp_listener_fd: i32,
    pub udp_socket_fd: i32,
    pub tcp_options: TproxySocketOptions,
    pub udp_options: TproxySocketOptions,
}

#[derive(Debug)]
pub struct LiveLoadedTproxyListenSocketMap {
    pub map: RuntimeMapInfo,
    pub new_map_ids: Vec<u32>,
    pub keys_updated: Vec<u32>,
    pub tcp_listener_fd: i32,
    pub udp_socket_fd: i32,
    pub tcp_options: TproxySocketOptions,
    pub udp_options: TproxySocketOptions,
    pub listeners: TproxyListenerSet,
}

pub fn run_listen_socket_map_fd_smoke() -> io::Result<ListenSocketMapFdSmoke> {
    let map_fd = create_sockmap()?;
    let tcp_listener = TcpListener::bind(("127.0.0.1", 0))?;
    let udp_socket = UdpSocket::bind(("127.0.0.1", 0))?;

    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_TCP4,
        tcp_listener.as_raw_fd(),
    )?;
    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_TCP6,
        tcp_listener.as_raw_fd(),
    )?;
    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_UDP4,
        udp_socket.as_raw_fd(),
    )?;
    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_UDP6,
        udp_socket.as_raw_fd(),
    )?;

    Ok(ListenSocketMapFdSmoke {
        map_type: "SockMap",
        key_size: 4,
        value_size: 8,
        max_entries: LISTEN_SOCKET_MAP_MAX_ENTRIES,
        keys_updated: LISTEN_SOCKET_KEYS.to_vec(),
        tcp_listener_fd: tcp_listener.as_raw_fd(),
        udp_socket_fd: udp_socket.as_raw_fd(),
    })
}

pub fn run_loaded_listen_socket_map_fd_smoke(
    before_map_ids: &[u32],
) -> io::Result<LoadedListenSocketMapFdSmoke> {
    let (map_fd, map, new_map_ids) = open_new_loaded_listen_socket_map(before_map_ids)?;
    let tcp_listener = TcpListener::bind(("127.0.0.1", 0))?;
    let udp_socket = UdpSocket::bind(("127.0.0.1", 0))?;

    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_TCP4,
        tcp_listener.as_raw_fd(),
    )?;
    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_TCP6,
        tcp_listener.as_raw_fd(),
    )?;
    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_UDP4,
        udp_socket.as_raw_fd(),
    )?;
    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_UDP6,
        udp_socket.as_raw_fd(),
    )?;

    Ok(LoadedListenSocketMapFdSmoke {
        map,
        new_map_ids,
        keys_updated: LISTEN_SOCKET_KEYS.to_vec(),
        tcp_listener_fd: tcp_listener.as_raw_fd(),
        udp_socket_fd: udp_socket.as_raw_fd(),
    })
}

pub fn run_loaded_tproxy_listen_socket_map_fd_smoke(
    before_map_ids: &[u32],
    port: u16,
) -> io::Result<LoadedTproxyListenSocketMapFdSmoke> {
    let live = open_live_loaded_tproxy_listen_socket_map(before_map_ids, port)?;
    Ok(LoadedTproxyListenSocketMapFdSmoke {
        map: live.map,
        new_map_ids: live.new_map_ids,
        keys_updated: live.keys_updated,
        tcp_listener_fd: live.tcp_listener_fd,
        udp_socket_fd: live.udp_socket_fd,
        tcp_options: live.tcp_options,
        udp_options: live.udp_options,
    })
}

pub fn open_live_loaded_tproxy_listen_socket_map(
    before_map_ids: &[u32],
    port: u16,
) -> io::Result<LiveLoadedTproxyListenSocketMap> {
    open_live_loaded_tproxy_listen_socket_map_with_listener(before_map_ids, || {
        open_tproxy_listener_set(port)
    })
}

pub fn open_live_loaded_tproxy_listen_socket_map_in_netns(
    before_map_ids: &[u32],
    port: u16,
    netns_name: &str,
) -> io::Result<LiveLoadedTproxyListenSocketMap> {
    open_live_loaded_tproxy_listen_socket_map_with_listener(before_map_ids, || {
        open_tproxy_listener_set_in_netns(netns_name, port)
    })
}

pub fn open_tproxy_listener_set_and_update_sockmap_by_id(
    map_id: u32,
    port: u16,
) -> io::Result<LiveLoadedTproxyListenSocketMap> {
    let (map_fd, map) = open_listen_socket_map_by_id(map_id)?;
    let listeners = open_tproxy_listener_set(port)?;

    let keys_updated = update_sockmap_from_tproxy_listeners(map_fd.as_raw_fd(), &listeners)?;

    Ok(LiveLoadedTproxyListenSocketMap {
        map,
        new_map_ids: Vec::new(),
        keys_updated,
        tcp_listener_fd: listeners.tcp_listener.as_raw_fd(),
        udp_socket_fd: listeners.udp_socket.as_raw_fd(),
        tcp_options: listeners.tcp_options.clone(),
        udp_options: listeners.udp_options.clone(),
        listeners,
    })
}

pub fn update_listen_socket_map_by_id(
    map_id: u32,
    tcp4_socket_fd: i32,
    tcp6_socket_fd: Option<i32>,
    udp4_socket_fd: i32,
    udp6_socket_fd: Option<i32>,
) -> io::Result<RuntimeMapInfo> {
    let (map_fd, map) = open_listen_socket_map_by_id(map_id)?;
    update_sockmap_fd(map_fd.as_raw_fd(), LISTEN_SOCKET_KEY_TCP4, tcp4_socket_fd)?;
    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_TCP6,
        tcp6_socket_fd.unwrap_or(tcp4_socket_fd),
    )?;
    update_sockmap_fd(map_fd.as_raw_fd(), LISTEN_SOCKET_KEY_UDP4, udp4_socket_fd)?;
    update_sockmap_fd(
        map_fd.as_raw_fd(),
        LISTEN_SOCKET_KEY_UDP6,
        udp6_socket_fd.unwrap_or(udp4_socket_fd),
    )?;
    Ok(map)
}

fn open_live_loaded_tproxy_listen_socket_map_with_listener(
    before_map_ids: &[u32],
    listener_factory: impl FnOnce() -> io::Result<TproxyListenerSet>,
) -> io::Result<LiveLoadedTproxyListenSocketMap> {
    let (map_fd, map, new_map_ids) = open_new_loaded_listen_socket_map(before_map_ids)?;
    let listeners = listener_factory()?;

    let keys_updated = update_sockmap_from_tproxy_listeners(map_fd.as_raw_fd(), &listeners)?;

    Ok(LiveLoadedTproxyListenSocketMap {
        map,
        new_map_ids,
        keys_updated,
        tcp_listener_fd: listeners.tcp_listener.as_raw_fd(),
        udp_socket_fd: listeners.udp_socket.as_raw_fd(),
        tcp_options: listeners.tcp_options.clone(),
        udp_options: listeners.udp_options.clone(),
        listeners,
    })
}

fn open_new_loaded_listen_socket_map(
    before_map_ids: &[u32],
) -> io::Result<(OwnedFd, RuntimeMapInfo, Vec<u32>)> {
    let current_map_ids = map_ids()?;
    let new_map_ids = current_map_ids
        .iter()
        .copied()
        .filter(|id| !before_map_ids.contains(id))
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for id in &new_map_ids {
        let fd = open_map_fd(*id)?;
        let info = map_info(fd.as_raw_fd())?;
        if listen_socket_map_matches(&info) {
            candidates.push((fd, info));
        }
    }
    if candidates.len() != 1 {
        return Err(io::Error::other(format!(
            "expected exactly one new real listen_socket_map, found {}",
            candidates.len()
        )));
    }
    let (map_fd, map) = candidates.remove(0);
    Ok((map_fd, map, new_map_ids))
}

fn open_listen_socket_map_by_id(map_id: u32) -> io::Result<(OwnedFd, RuntimeMapInfo)> {
    let fd = open_map_fd(map_id)?;
    let info = map_info(fd.as_raw_fd())?;
    if !listen_socket_map_matches(&info) {
        return Err(io::Error::other(format!(
            "map id {} is not a listen_socket_map: name={} type={} key_size={} value_size={} max_entries={}",
            map_id, info.name, info.map_type, info.key_size, info.value_size, info.max_entries
        )));
    }
    Ok((fd, info))
}

fn listen_socket_map_matches(info: &RuntimeMapInfo) -> bool {
    info.name == LISTEN_SOCKET_MAP_KERNEL_NAME
        && info.map_type == BPF_MAP_TYPE_SOCKMAP
        && info.key_size == 4
        && info.value_size == 8
        && info.max_entries == LISTEN_SOCKET_MAP_MAX_ENTRIES
}

fn create_sockmap() -> io::Result<OwnedFd> {
    let mut attr = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_SOCKMAP,
        key_size: 4,
        value_size: 8,
        max_entries: LISTEN_SOCKET_MAP_MAX_ENTRIES,
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

fn update_sockmap_from_tproxy_listeners(
    map_fd: i32,
    listeners: &TproxyListenerSet,
) -> io::Result<Vec<u32>> {
    let mut keys_updated = Vec::new();
    update_sockmap_fd(
        map_fd,
        LISTEN_SOCKET_KEY_TCP4,
        listeners.tcp_listener.as_raw_fd(),
    )?;
    keys_updated.push(LISTEN_SOCKET_KEY_TCP4);
    update_sockmap_fd(
        map_fd,
        LISTEN_SOCKET_KEY_TCP6,
        listeners.tcp_listener.as_raw_fd(),
    )?;
    keys_updated.push(LISTEN_SOCKET_KEY_TCP6);
    update_sockmap_fd(
        map_fd,
        LISTEN_SOCKET_KEY_UDP4,
        listeners.udp_socket.as_raw_fd(),
    )?;
    keys_updated.push(LISTEN_SOCKET_KEY_UDP4);
    update_sockmap_fd(
        map_fd,
        LISTEN_SOCKET_KEY_UDP6,
        listeners.udp_socket.as_raw_fd(),
    )?;
    keys_updated.push(LISTEN_SOCKET_KEY_UDP6);
    Ok(keys_updated)
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
