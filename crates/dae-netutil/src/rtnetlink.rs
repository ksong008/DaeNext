//! Synchronous Linux route netlink requests on a socket owned by the caller.

use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const HEADER_LEN: usize = 16;

pub fn attr(message: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
    let size = 4 + bytes.len();
    message.extend_from_slice(&(size as u16).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(bytes);
    message.resize(message.len().next_multiple_of(4), 0);
}

pub fn find_attr(mut bytes: &[u8], kind: u16) -> io::Result<Option<&[u8]>> {
    while !bytes.is_empty() {
        let header = bytes.get(..4).ok_or_else(malformed)?;
        let size = u16::from_ne_bytes([header[0], header[1]]) as usize;
        if size < 4 || size > bytes.len() {
            return Err(malformed());
        }
        let attr_kind = u16::from_ne_bytes([header[2], header[3]]) & 0x3fff;
        if attr_kind == kind {
            return Ok(Some(&bytes[4..size]));
        }
        bytes = bytes
            .get(size.next_multiple_of(4)..)
            .ok_or_else(malformed)?;
    }
    Ok(None)
}

pub fn read_u32(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes.try_into().map_err(|_| malformed())?,
    ))
}

pub fn request(kind: u16, flags: u16, payload: &[u8], reply: Option<u16>) -> io::Result<Vec<u8>> {
    let socket = send_request(
        kind,
        flags
            | if reply.is_none() {
                libc::NLM_F_ACK as u16
            } else {
                0
            },
        payload,
    )?;
    let mut buffer = [0_u8; 8192];
    let (kind, _, data, _) = parse_message(receive(&socket, &mut buffer)?)?;
    if kind == libc::NLMSG_ERROR as u16 {
        check_status(data)?;
        if reply.is_none() {
            return Ok(Vec::new());
        }
    }
    if reply == Some(kind) {
        return Ok(data.to_vec());
    }
    Err(malformed())
}

fn send_request(kind: u16, flags: u16, payload: &[u8]) -> io::Result<OwnedFd> {
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
        tv_sec: 2,
        tv_usec: 0,
    };
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::timeval>() as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut message = Vec::with_capacity(HEADER_LEN + payload.len());
    message.extend_from_slice(&((HEADER_LEN + payload.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    let flags = flags | libc::NLM_F_REQUEST as u16;
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&1_u32.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(payload);
    if unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            0,
            (&raw const kernel).cast(),
            size_of::<libc::sockaddr_nl>() as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

fn receive<'a>(fd: &OwnedFd, buffer: &'a mut [u8]) -> io::Result<&'a [u8]> {
    let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut sender_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let count = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_TRUNC,
            (&raw mut sender).cast(),
            &mut sender_len,
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if sender.nl_pid != 0 || count as usize > buffer.len() || (count as usize) < HEADER_LEN {
        return Err(malformed());
    }
    Ok(&buffer[..count as usize])
}

fn parse_message(bytes: &[u8]) -> io::Result<(u16, u16, &[u8], &[u8])> {
    let header = bytes.get(..HEADER_LEN).ok_or_else(malformed)?;
    let len = read_u32(&header[..4])? as usize;
    if !(HEADER_LEN..=bytes.len()).contains(&len) || header[8..12] != 1_u32.to_ne_bytes() {
        return Err(malformed());
    }
    let remaining = if bytes.len() == len {
        &[]
    } else {
        bytes.get(len.next_multiple_of(4)..).ok_or_else(malformed)?
    };
    Ok((
        u16::from_ne_bytes([header[4], header[5]]),
        u16::from_ne_bytes([header[6], header[7]]),
        &bytes[HEADER_LEN..len],
        remaining,
    ))
}

fn check_status(data: &[u8]) -> io::Result<()> {
    let status = read_u32(data.get(..4).ok_or_else(malformed)?)? as i32;
    match status {
        0 => Ok(()),
        i32::MIN..=-1 => Err(io::Error::from_raw_os_error(status.saturating_neg())),
        _ => Err(malformed()),
    }
}

pub fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unexpected rtnetlink message")
}

/// Visit every record in one rtnetlink dump. An interrupted dump fails as a unit.
pub fn dump(
    kind: u16,
    payload: &[u8],
    reply: u16,
    mut visit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let socket = send_request(kind, libc::NLM_F_DUMP as u16, payload)?;
    let mut buffer = [0_u8; 32768];
    loop {
        let mut messages = receive(&socket, &mut buffer)?;
        while !messages.is_empty() {
            let (kind, flags, data, remaining) = parse_message(messages)?;
            messages = remaining;
            if flags & libc::NLM_F_DUMP_INTR as u16 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "rtnetlink dump changed",
                ));
            }
            match kind {
                kind if kind == libc::NLMSG_DONE as u16 => {
                    return if data.is_empty() {
                        Ok(())
                    } else {
                        check_status(data)
                    };
                }
                kind if kind == libc::NLMSG_ERROR as u16 => check_status(data)?,
                kind if kind == reply => visit(data)?,
                _ => return Err(malformed()),
            }
        }
    }
}

pub struct DefaultRoute {
    pub ifindex: u32,
    pub gateway: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
}

pub fn default_routes(family: u8) -> io::Result<Vec<DefaultRoute>> {
    let mut payload = [0; 12];
    payload[0] = family;
    let mut routes = Vec::new();
    dump(libc::RTM_GETROUTE, &payload, libc::RTM_NEWROUTE, |data| {
        let header = data.get(..12).ok_or_else(malformed)?;
        let attrs = &data[12..];
        let table = find_attr(attrs, libc::RTA_TABLE)?
            .map(read_u32)
            .transpose()?
            .unwrap_or(u32::from(header[4]));
        if header[0] != family
            || header[1] != 0
            || table != u32::from(libc::RT_TABLE_MAIN)
            || header[7] != libc::RTN_UNICAST
        {
            return Ok(());
        }

        let gateway = route_gateway(attrs, family)?;
        let preferred_source = address_attr(attrs, libc::RTA_PREFSRC, family)?;
        if let Some(index) = find_attr(attrs, libc::RTA_OIF)? {
            routes.push(DefaultRoute {
                ifindex: read_u32(index)?,
                gateway,
                preferred_source,
            });
        }
        if let Some(mut hops) = find_attr(attrs, libc::RTA_MULTIPATH)? {
            while !hops.is_empty() {
                let header = hops.get(..8).ok_or_else(malformed)?;
                let size = usize::from(u16::from_ne_bytes([header[0], header[1]]));
                let attrs = hops.get(8..size).ok_or_else(malformed)?;
                routes.push(DefaultRoute {
                    ifindex: read_u32(&header[4..8])?,
                    gateway: route_gateway(attrs, family)?.or(gateway),
                    preferred_source,
                });
                hops = hops.get(size.next_multiple_of(4)..).ok_or_else(malformed)?;
            }
        }
        Ok(())
    })?;
    Ok(routes)
}

fn route_gateway(attrs: &[u8], family: u8) -> io::Result<Option<IpAddr>> {
    if let Some(via) = find_attr(attrs, libc::RTA_VIA)? {
        let header = via.get(..2).ok_or_else(malformed)?;
        let family =
            u8::try_from(u16::from_ne_bytes([header[0], header[1]])).map_err(|_| malformed())?;
        return parse_ip(family, &via[2..]).map(Some);
    }
    address_attr(attrs, libc::RTA_GATEWAY, family)
}

pub fn address_attr(attrs: &[u8], kind: u16, family: u8) -> io::Result<Option<IpAddr>> {
    find_attr(attrs, kind)?
        .map(|bytes| parse_ip(family, bytes))
        .transpose()
}

fn parse_ip(family: u8, bytes: &[u8]) -> io::Result<IpAddr> {
    match i32::from(family) {
        libc::AF_INET => <[u8; 4]>::try_from(bytes).map(|bytes| Ipv4Addr::from(bytes).into()),
        libc::AF_INET6 => <[u8; 16]>::try_from(bytes).map(|bytes| Ipv6Addr::from(bytes).into()),
        _ => return Err(malformed()),
    }
    .map_err(|_| malformed())
}
