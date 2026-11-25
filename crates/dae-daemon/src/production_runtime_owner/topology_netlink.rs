use std::ffi::CString;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use dae_netutil::rtnetlink::{attr, find_attr, malformed, request};
use serde_json::{Value, json};

const CREATE_EXCLUSIVE: u16 = (libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
const CREATE_REPLACE: u16 = (libc::NLM_F_CREATE | libc::NLM_F_REPLACE) as u16;
const NESTED: u16 = 1 << 15;
const IFLA_IFNAME: u16 = 3;
const IFLA_ADDRESS: u16 = 1;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
// Linux UAPI. Both veth and netkit use a peer ifinfomsg followed by attributes.
const LINK_INFO_PEER: u16 = 1;
const NETKIT_MODE: u16 = 5;
const NETKIT_SCRUB: u16 = 6;
const NETKIT_PEER_SCRUB: u16 = 7;
const NETNSA_NSID: u16 = 1;
const NETNSA_FD: u16 = 3;
const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;

pub(super) fn step(
    steps: &mut Vec<Value>,
    name: &str,
    operation: impl FnOnce() -> io::Result<Value>,
) -> Value {
    let started = std::time::Instant::now();
    let mut report = match operation() {
        Ok(detail) => json!({"status": "pass", "detail": detail}),
        Err(error) => json!({
            "status": "fail", "stderr": error.to_string(), "errno": error.raw_os_error(),
        }),
    };
    report["name"] = json!(name);
    report["backend"] = json!("rtnetlink");
    report["elapsed_ms"] = json!(started.elapsed().as_millis());
    steps.push(report.clone());
    report
}

pub(super) fn create_pair(host: &str, peer: &str, netkit: bool, no_scrub: bool) -> io::Result<()> {
    let mut peer_info = link_header(0, false);
    attr(&mut peer_info, IFLA_IFNAME, &name_bytes(peer)?);

    let mut data = Vec::new();
    attr(&mut data, LINK_INFO_PEER, &peer_info);
    let kind = if netkit {
        attr(&mut data, NETKIT_MODE, &0_u32.to_ne_bytes());
        if no_scrub {
            attr(&mut data, NETKIT_SCRUB, &0_u32.to_ne_bytes());
            attr(&mut data, NETKIT_PEER_SCRUB, &0_u32.to_ne_bytes());
        }
        b"netkit\0".as_slice()
    } else {
        b"veth\0".as_slice()
    };
    let mut info = Vec::new();
    attr(&mut info, IFLA_INFO_KIND, kind);
    attr(&mut info, IFLA_INFO_DATA | NESTED, &data);
    let mut payload = link_header(0, false);
    attr(&mut payload, IFLA_IFNAME, &name_bytes(host)?);
    attr(&mut payload, IFLA_LINKINFO | NESTED, &info);
    request(libc::RTM_NEWLINK, 0x600, &payload, None)?;
    Ok(())
}

// Named network namespaces are namespace files mounted under /run/netns.
pub(super) fn create_namespace(name: &str) -> io::Result<()> {
    let directory = Path::new("/run/netns");
    std::fs::create_dir_all(directory)?;
    let path = directory.join(name);
    let target = CString::new(path.as_os_str().as_bytes())?;
    let _placeholder = File::options().write(true).create_new(true).open(&path)?;
    let result = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                if unsafe {
                    libc::mount(
                        c"/proc/thread-self/ns/net".as_ptr(),
                        target.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })
            .join()
            .map_err(|_| io::Error::other("network namespace creation panicked"))?
    });
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

pub(super) fn delete_namespace(name: &str) -> io::Result<()> {
    let path = Path::new("/run/netns").join(name);
    let target = CString::new(path.as_os_str().as_bytes())?;
    if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } != 0 {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOENT) => return Ok(()),
            Some(libc::EINVAL) => (),
            _ => return Err(error),
        }
    }
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

pub(super) fn add_address(name: &str, address: IpAddr) -> io::Result<()> {
    with_ip_bytes(address, |family, octets| {
        let mut payload = vec![family, octets.len() as u8 * 8, 0, libc::RT_SCOPE_UNIVERSE];
        payload.extend_from_slice(&ifindex(name)?.to_ne_bytes());
        attr(&mut payload, libc::IFA_LOCAL, octets);
        attr(&mut payload, libc::IFA_ADDRESS, octets);
        request(libc::RTM_NEWADDR, CREATE_EXCLUSIVE, &payload, None)?;
        Ok(())
    })
}

pub(super) fn add_mark_rule(family: u8, mark: u32, table: u32) -> io::Result<()> {
    // fib_rule_hdr followed by FRA_FWMARK (10), FRA_TABLE (15), FRA_FWMASK (16).
    let mut payload = [0; 12].to_vec();
    payload[0] = family;
    payload[7] = 1; // FR_ACT_TO_TBL
    attr(&mut payload, 10, &mark.to_ne_bytes());
    attr(&mut payload, 15, &table.to_ne_bytes());
    attr(&mut payload, 16, &mark.to_ne_bytes());
    request(libc::RTM_NEWRULE, CREATE_EXCLUSIVE, &payload, None)?;
    Ok(())
}

pub(super) fn add_route(
    name: &str,
    address: IpAddr,
    local_table: Option<u32>,
    gateway: bool,
) -> io::Result<()> {
    with_ip_bytes(address, |family, octets| {
        let (prefix, scope, kind) = if local_table.is_some() {
            (0, libc::RT_SCOPE_HOST, libc::RTN_LOCAL)
        } else if gateway {
            (0, libc::RT_SCOPE_UNIVERSE, libc::RTN_UNICAST)
        } else {
            (
                octets.len() as u8 * 8,
                libc::RT_SCOPE_LINK,
                libc::RTN_UNICAST,
            )
        };
        let mut payload = vec![
            family,
            prefix,
            0,
            0,
            libc::RT_TABLE_MAIN,
            libc::RTPROT_BOOT,
            scope,
            kind,
            0,
            0,
            0,
            0,
        ];
        if let Some(table) = local_table {
            payload[4] = libc::RT_TABLE_UNSPEC;
            attr(&mut payload, libc::RTA_TABLE, &table.to_ne_bytes());
        } else {
            attr(
                &mut payload,
                if gateway {
                    libc::RTA_GATEWAY
                } else {
                    libc::RTA_DST
                },
                octets,
            );
        }
        attr(&mut payload, libc::RTA_OIF, &ifindex(name)?.to_ne_bytes());
        request(libc::RTM_NEWROUTE, CREATE_EXCLUSIVE, &payload, None)?;
        Ok(())
    })
}

pub(super) fn replace_permanent_neighbor(
    name: &str,
    address: IpAddr,
    mac: [u8; 6],
) -> io::Result<()> {
    with_ip_bytes(address, |family, octets| {
        let mut payload = vec![family, 0, 0, 0];
        payload.extend_from_slice(&ifindex(name)?.to_ne_bytes());
        payload.extend_from_slice(&libc::NUD_PERMANENT.to_ne_bytes());
        payload.extend_from_slice(&[0, libc::RTN_UNICAST]);
        attr(&mut payload, libc::NDA_DST, octets);
        attr(&mut payload, libc::NDA_LLADDR, &mac);
        request(libc::RTM_NEWNEIGH, CREATE_REPLACE, &payload, None)?;
        Ok(())
    })
}

fn with_ip_bytes<T>(address: IpAddr, operation: impl FnOnce(u8, &[u8]) -> T) -> T {
    match address {
        IpAddr::V4(address) => operation(libc::AF_INET as u8, &address.octets()),
        IpAddr::V6(address) => operation(libc::AF_INET6 as u8, &address.octets()),
    }
}

pub(super) fn open_namespace(name: &str) -> io::Result<File> {
    File::open(Path::new("/run/netns").join(name))
}

pub(super) fn assign_namespace_id(namespace: &File) -> io::Result<u32> {
    let mut payload = vec![0; 4];
    attr(
        &mut payload,
        NETNSA_FD,
        &namespace.as_raw_fd().to_ne_bytes(),
    );
    let mut assign = payload.clone();
    attr(&mut assign, NETNSA_NSID, &(-1_i32).to_ne_bytes());
    if let Err(error) = request(RTM_NEWNSID, 0, &assign, None)
        && error.raw_os_error() != Some(libc::EEXIST)
    {
        return Err(error);
    }
    let response = request(RTM_GETNSID, 0, &payload, Some(RTM_NEWNSID))?;
    let attributes = response.get(4..).ok_or_else(malformed)?;
    let value = find_attr(attributes, NETNSA_NSID)?.ok_or_else(malformed)?;
    let id = i32::from_ne_bytes(value.try_into().map_err(|_| malformed())?);
    u32::try_from(id).map_err(|_| malformed())
}

pub(super) fn move_link(name: &str, namespace: &File) -> io::Result<()> {
    let mut payload = link_header(ifindex(name)?, false);
    attr(
        &mut payload,
        IFLA_NET_NS_FD,
        &namespace.as_raw_fd().to_ne_bytes(),
    );
    request(libc::RTM_NEWLINK, 0, &payload, None)?;
    Ok(())
}

pub(super) fn bring_up(name: &str, namespace: Option<&File>) -> io::Result<()> {
    in_namespace(namespace, || {
        request(
            libc::RTM_NEWLINK,
            0,
            &link_header(ifindex(name)?, true),
            None,
        )?;
        Ok(())
    })
}

pub(super) fn delete_link(name: &str) -> io::Result<()> {
    match ifindex(name) {
        Ok(index) => {
            request(libc::RTM_DELLINK, 0, &link_header(index, false), None)?;
            Ok(())
        }
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENODEV | libc::ENXIO)) => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
pub(super) struct LinkInfo {
    pub(super) index: u32,
    pub(super) mac: [u8; 6],
    pub(super) kind: Option<String>,
}

pub(super) fn read_link(name: &str, namespace: Option<&File>) -> io::Result<LinkInfo> {
    in_namespace(namespace, || {
        let index = ifindex(name)?;
        let response = request(
            libc::RTM_GETLINK,
            0,
            &link_header(index, false),
            Some(libc::RTM_NEWLINK),
        )?;
        let attributes = response.get(16..).ok_or_else(malformed)?;
        let address = find_attr(attributes, IFLA_ADDRESS)?.ok_or_else(malformed)?;
        let mac = address.try_into().map_err(|_| malformed())?;
        let kind = match find_attr(attributes, IFLA_LINKINFO)? {
            Some(info) => find_attr(info, IFLA_INFO_KIND)?.map(|kind| {
                String::from_utf8_lossy(kind.strip_suffix(&[0]).unwrap_or(kind)).into_owned()
            }),
            None => None,
        };
        Ok(LinkInfo { index, mac, kind })
    })
}

pub(super) fn ifindex(name: &str) -> io::Result<u32> {
    let name = CString::new(name)?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        index => Ok(index),
    }
}

#[cfg(feature = "native-ebpf")]
pub(super) fn interface_indices() -> io::Result<Vec<u32>> {
    use dae_netutil::rtnetlink::{dump, read_u32};

    let mut indices = Vec::new();
    dump(libc::RTM_GETLINK, &[0; 16], libc::RTM_NEWLINK, |link| {
        indices.push(read_u32(link.get(4..8).ok_or_else(malformed)?)?);
        Ok(())
    })?;
    Ok(indices)
}

fn name_bytes(name: &str) -> io::Result<Vec<u8>> {
    Ok(CString::new(name)?.into_bytes_with_nul())
}

pub(super) fn in_namespace<T: Send>(
    namespace: Option<&File>,
    operation: impl FnOnce() -> io::Result<T> + Send,
) -> io::Result<T> {
    let Some(namespace) = namespace else {
        return operation();
    };
    // A short-lived OS thread makes the namespace lifetime synchronous, including
    // panic paths. The runtime worker never changes namespaces.
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                operation()
            })
            .join()
            .map_err(|_| io::Error::other("network namespace operation panicked"))?
    })
}

fn link_header(index: u32, up: bool) -> Vec<u8> {
    let mut header = vec![0; 16];
    header[4..8].copy_from_slice(&index.to_ne_bytes());
    if up {
        header[8..12].copy_from_slice(&libc::IFF_UP.to_ne_bytes());
        header[12..16].copy_from_slice(&libc::IFF_UP.to_ne_bytes());
    }
    header
}

pub(super) fn default_route_interfaces(family: u8) -> io::Result<Vec<String>> {
    let mut ifaces = Vec::new();
    for route in dae_netutil::rtnetlink::default_routes(family)? {
        let mut name = [0; libc::IF_NAMESIZE];
        if unsafe { libc::if_indextoname(route.ifindex, name.as_mut_ptr()) }.is_null() {
            continue;
        }
        // SAFETY: a successful call wrote a NUL-terminated interface name.
        let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy();
        if !ifaces.iter().any(|iface| iface == &name) {
            ifaces.push(name.into_owned());
        }
    }
    Ok(ifaces)
}
