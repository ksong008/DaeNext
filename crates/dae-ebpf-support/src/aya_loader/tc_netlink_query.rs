//! Read-only rtnetlink classifier metadata and ownership checks.
use super::*;

pub(super) const HOST_TC_RECOVERY_SLOTS: [(u16, u32); 2] = [
    (1, crate::tc_handle(0x2023, 2)),
    (2, crate::tc_handle(0x2023, 4)),
];

#[derive(Debug)]
pub(super) struct FilterLocation {
    pub ifindex: u32,
    pub parent: u32,
    pub priority: u16,
    pub handle: u32,
}

#[derive(Debug)]
pub(super) struct FilterIdentity {
    pub program_id: u32,
    pub tag: Option<[u8; 8]>,
}

pub(super) fn filter_program_id(location: &FilterLocation) -> Result<Option<u32>, String> {
    filter_identity(location).map(|identity| identity.map(|filter| filter.program_id))
}

pub(super) fn filter_identity(location: &FilterLocation) -> Result<Option<FilterIdentity>, String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // A removed interface cannot retain a filter. Other lookup failures remain
    // errors; an ifindex reused by another interface is checked by program ID.
    if unsafe { libc::if_indextoname(location.ifindex, name.as_mut_ptr()) }.is_null() {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENXIO | libc::ENODEV)) {
            return Ok(None);
        }
        return Err(format!("resolve netlink interface: {error}"));
    }
    let mut found = None;
    visit_filters(location.ifindex, location.parent, |message| {
        if filter_slot(message)? != (location.priority, location.handle) {
            return Ok(());
        }
        let attributes = attrs(&message[36..])?;
        let kind = attributes
            .iter()
            .find(|(kind, _)| *kind == 1)
            .map(|(_, data)| *data);
        if kind != Some(b"bpf\0".as_slice()) {
            return Err(invalid("foreign non-BPF filter"));
        }
        let options = attributes
            .iter()
            .find(|(kind, _)| *kind == 2)
            .ok_or_else(|| invalid("missing BPF options"))?
            .1;
        let nested = attrs(options)?;
        let id = nested
            .iter()
            .find(|(kind, _)| *kind == 11)
            .ok_or_else(|| invalid("missing BPF program ID"))?
            .1;
        let tag = nested
            .iter()
            .find(|(kind, _)| *kind == 10)
            .map(|(_, data)| (*data).try_into())
            .transpose()
            .map_err(|_| invalid("invalid BPF program tag"))?;
        let identity = FilterIdentity {
            program_id: u32_at(id, 0)?,
            tag,
        };
        if found.replace(identity).is_some() {
            return Err(invalid("ambiguous TC filter location"));
        }
        Ok(())
    })
    .map_err(|e| format!("observe netlink {location:?}: {e}"))?;
    Ok(found)
}

pub(super) fn reserved_slot_occupied(ifindex: u32, parent: u32) -> io::Result<bool> {
    let mut occupied = false;
    visit_filters(ifindex, parent, |message| {
        occupied |= HOST_TC_RECOVERY_SLOTS.contains(&filter_slot(message)?);
        Ok(())
    })?;
    Ok(occupied)
}

fn filter_slot(message: &[u8]) -> io::Result<(u16, u32)> {
    Ok(((u32_at(message, 32)? >> 16) as u16, u32_at(message, 24)?))
}

fn visit_filters(
    ifindex: u32,
    parent: u32,
    mut visit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    // SAFETY: fresh datagram socket, exclusively owned below.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: all pointers reference initialized values of the specified size.
    if unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            mem::size_of_val(&timeout) as _,
        )
    } < 0
        || unsafe {
            libc::bind(
                raw,
                (&address as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&address) as _,
            )
        } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // nlmsghdr + tcmsg; request a complete dump for this exact parent/ifindex.
    let mut request = [0_u8; 36];
    request[0..4].copy_from_slice(&36_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&46_u16.to_ne_bytes()); // RTM_GETTFILTER
    request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    request[28..32].copy_from_slice(&parent.to_ne_bytes());
    if unsafe {
        libc::sendto(
            raw,
            request.as_ptr().cast(),
            request.len(),
            0,
            (&address as *const libc::sockaddr_nl).cast(),
            mem::size_of_val(&address) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0_u8; 65536];
    for _ in 0..256 {
        let count = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize > buffer.len() || count == 0 {
            return Err(invalid("truncated netlink dump"));
        }
        let mut bytes = &buffer[..count as usize];
        while bytes.len() >= 16 {
            let len = u32_at(bytes, 0)? as usize;
            if len < 16 || len > bytes.len() {
                return Err(invalid("invalid nlmsg length"));
            }
            let message = &bytes[..len];
            if u16_at(message, 6)? & 0x10 != 0 {
                return Err(invalid("interrupted netlink dump"));
            }
            match u16_at(message, 4)? {
                3 => {
                    // NLMSG_DONE can also carry a dump error.
                    if message.len() >= 20 {
                        let error = u32_at(message, 16)? as i32;
                        if error != 0 {
                            return Err(io::Error::from_raw_os_error(-error));
                        }
                    }
                    return Ok(());
                }
                2 => {
                    let error = u32_at(message, 16)? as i32;
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(-error));
                    }
                }
                44 => {
                    // RTM_NEWTFILTER
                    if u32_at(message, 20)? == ifindex && u32_at(message, 28)? == parent {
                        visit(message)?;
                    }
                }
                _ => {}
            }
            let aligned = (len + 3) & !3;
            if aligned > bytes.len() {
                break;
            }
            bytes = &bytes[aligned..];
        }
    }
    Err(invalid("netlink dump exceeded cleanup budget"))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| invalid("short netlink u32"))?
            .try_into()
            .unwrap(),
    ))
}
fn u16_at(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(|| invalid("short netlink u16"))?
            .try_into()
            .unwrap(),
    ))
}
fn attrs(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while bytes.len() >= 4 {
        let len = u16_at(bytes, 0)? as usize;
        if len < 4 || len > bytes.len() {
            return Err(invalid("invalid netlink attribute"));
        }
        result.push((u16_at(bytes, 2)? & 0x3fff, &bytes[4..len]));
        let aligned = (len + 3) & !3;
        if aligned > bytes.len() {
            break;
        }
        bytes = &bytes[aligned..];
    }
    Ok(result)
}
