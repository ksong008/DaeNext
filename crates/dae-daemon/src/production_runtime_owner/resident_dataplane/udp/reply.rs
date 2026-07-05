#[cfg(test)]
use super::super::vision::VisionUnpadState;
use super::*;

use std::collections::HashMap;
use std::sync::OnceLock;

const UDP_REPLY_SOCKET_CACHE_MAX_ENTRIES: usize = 512;

static UDP_REPLY_SOCKET_CACHE: OnceLock<Mutex<UdpReplySocketCache>> = OnceLock::new();

#[derive(Default)]
struct UdpReplySocketCache {
    next_tick: u64,
    entries: HashMap<SocketAddr, UdpReplySocketEntry>,
}

struct UdpReplySocketEntry {
    socket: Arc<UdpSocket>,
    last_used: u64,
}

pub(super) fn send_udp_reply(
    original_dst: SocketAddr,
    peer: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let reply = cached_udp_reply_socket(original_dst)?;
    if let Err(first_err) = reply.send_to(payload, peer) {
        drop_cached_udp_reply_socket(original_dst);
        let reply = cached_udp_reply_socket(original_dst)?;
        reply.send_to(payload, peer).map_err(|err| {
            format!(
                "send transparent UDP reply: {err}; retry after cached socket error: {first_err}"
            )
        })?;
    }
    Ok(())
}

fn cached_udp_reply_socket(original_dst: SocketAddr) -> Result<Arc<UdpSocket>, String> {
    if let Some(socket) = lookup_cached_udp_reply_socket(original_dst)? {
        return Ok(socket);
    }

    let socket = Arc::new(
        open_transparent_udp_socket_bound_in_netns(PRODUCTION_NETNS, original_dst)
            .map_err(|err| format!("open transparent UDP reply socket: {err}"))?,
    );
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| format!("set UDP reply timeout: {err}"))?;

    insert_cached_udp_reply_socket(original_dst, socket)
}

fn lookup_cached_udp_reply_socket(
    original_dst: SocketAddr,
) -> Result<Option<Arc<UdpSocket>>, String> {
    let cache = UDP_REPLY_SOCKET_CACHE.get_or_init(|| Mutex::new(UdpReplySocketCache::default()));
    let mut cache = cache
        .lock()
        .map_err(|_| "resident UDP reply socket cache lock poisoned".to_owned())?;
    cache.next_tick = cache.next_tick.wrapping_add(1);
    let last_used = cache.next_tick;
    let Some(entry) = cache.entries.get_mut(&original_dst) else {
        return Ok(None);
    };
    entry.last_used = last_used;
    Ok(Some(Arc::clone(&entry.socket)))
}

fn insert_cached_udp_reply_socket(
    original_dst: SocketAddr,
    socket: Arc<UdpSocket>,
) -> Result<Arc<UdpSocket>, String> {
    let cache = UDP_REPLY_SOCKET_CACHE.get_or_init(|| Mutex::new(UdpReplySocketCache::default()));
    let mut cache = cache
        .lock()
        .map_err(|_| "resident UDP reply socket cache lock poisoned".to_owned())?;
    cache.next_tick = cache.next_tick.wrapping_add(1);
    let last_used = cache.next_tick;
    if let Some(entry) = cache.entries.get_mut(&original_dst) {
        entry.last_used = last_used;
        return Ok(Arc::clone(&entry.socket));
    }
    if cache.entries.len() >= UDP_REPLY_SOCKET_CACHE_MAX_ENTRIES {
        evict_oldest_udp_reply_socket(&mut cache);
    }
    cache.entries.insert(
        original_dst,
        UdpReplySocketEntry {
            socket: Arc::clone(&socket),
            last_used,
        },
    );
    Ok(socket)
}

fn drop_cached_udp_reply_socket(original_dst: SocketAddr) {
    let Some(cache) = UDP_REPLY_SOCKET_CACHE.get() else {
        return;
    };
    if let Ok(mut cache) = cache.lock() {
        cache.entries.remove(&original_dst);
    }
}

pub(crate) fn clear_udp_reply_socket_cache() -> usize {
    let Some(cache) = UDP_REPLY_SOCKET_CACHE.get() else {
        return 0;
    };
    let Ok(mut cache) = cache.lock() else {
        return 0;
    };
    let cleared = cache.entries.len();
    cache.entries.clear();
    cleared
}

fn evict_oldest_udp_reply_socket(cache: &mut UdpReplySocketCache) {
    let Some(oldest) = cache
        .entries
        .iter()
        .min_by_key(|(_, entry)| entry.last_used)
        .map(|(addr, _)| *addr)
    else {
        return;
    };
    cache.entries.remove(&oldest);
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn udp_reply_socket_cache_clear_drops_retained_sockets() {
        clear_udp_reply_socket_cache();
        let cache =
            UDP_REPLY_SOCKET_CACHE.get_or_init(|| Mutex::new(UdpReplySocketCache::default()));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind udp socket"));
        let key = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5300));
        {
            let mut cache = cache.lock().expect("udp reply cache lock");
            cache.entries.insert(
                key,
                UdpReplySocketEntry {
                    socket,
                    last_used: 1,
                },
            );
        }

        assert_eq!(clear_udp_reply_socket_cache(), 1);
        assert_eq!(clear_udp_reply_socket_cache(), 0);
    }
}

#[cfg(test)]
pub(super) fn parse_vless_udp_response(
    input: &[u8],
    flow: &str,
    user_uuid: [u8; 16],
) -> Result<Option<Vec<u8>>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    if input[0] != VLESS_RESPONSE_VERSION {
        return Err(format!("unexpected VLESS response version: {}", input[0]));
    }
    let header_len = 2 + input[1] as usize;
    if input.len() < header_len {
        return Ok(None);
    }
    if is_xtls_rprx_vision_flow(flow) {
        if input.len() == header_len {
            return Ok(None);
        }
        let mut unpadder = VisionUnpadder::new(user_uuid);
        let payload = unpadder.consume(&input[header_len..])?;
        if payload.is_empty() && !matches!(unpadder.state, VisionUnpadState::Raw) {
            return Ok(None);
        }
        return parse_xudp_response_payload(&payload);
    }
    if input.len() < header_len + 2 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([input[header_len], input[header_len + 1]]) as usize;
    if input.len() < header_len + 2 + payload_len {
        return Ok(None);
    }
    Ok(Some(
        input[header_len + 2..header_len + 2 + payload_len].to_vec(),
    ))
}

#[cfg(test)]
pub(super) fn parse_xudp_response_payload(input: &[u8]) -> Result<Option<Vec<u8>>, String> {
    Ok(parse_xudp_response_frame(input)?.map(|(payload, _)| payload))
}

pub(super) fn parse_xudp_response_frame(input: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    let metadata_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    let payload_len_offset = 2 + metadata_len;
    if input.len() < payload_len_offset + 2 {
        return Ok(None);
    }
    let payload_len =
        u16::from_be_bytes([input[payload_len_offset], input[payload_len_offset + 1]]) as usize;
    let payload_offset = payload_len_offset + 2;
    if input.len() < payload_offset + payload_len {
        return Ok(None);
    }
    Ok(Some((
        input[payload_offset..payload_offset + payload_len].to_vec(),
        payload_offset + payload_len,
    )))
}
