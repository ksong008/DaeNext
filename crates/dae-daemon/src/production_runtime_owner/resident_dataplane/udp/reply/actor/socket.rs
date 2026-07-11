use super::*;
use std::collections::HashMap;
use std::io;

pub(super) struct UdpReplySocketCache {
    capacity: usize,
    tick: u64,
    entries: HashMap<SocketAddr, UdpReplySocketEntry>,
}

struct UdpReplySocketEntry {
    socket: Arc<tokio::net::UdpSocket>,
    last_used: u64,
}

impl UdpReplySocketCache {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            entries: HashMap::new(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&mut self, original_dst: SocketAddr) -> Option<Arc<tokio::net::UdpSocket>> {
        self.tick = self.tick.wrapping_add(1);
        let entry = self.entries.get_mut(&original_dst)?;
        entry.last_used = self.tick;
        Some(Arc::clone(&entry.socket))
    }

    fn insert(
        &mut self,
        original_dst: SocketAddr,
        socket: Arc<tokio::net::UdpSocket>,
    ) -> Arc<tokio::net::UdpSocket> {
        self.tick = self.tick.wrapping_add(1);
        if let Some(entry) = self.entries.get_mut(&original_dst) {
            entry.last_used = self.tick;
            return Arc::clone(&entry.socket);
        }
        if self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        self.entries.insert(
            original_dst,
            UdpReplySocketEntry {
                socket: Arc::clone(&socket),
                last_used: self.tick,
            },
        );
        socket
    }

    fn remove(&mut self, original_dst: SocketAddr) {
        self.entries.remove(&original_dst);
    }

    fn evict_oldest(&mut self) {
        let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(addr, _)| *addr)
        else {
            return;
        };
        self.entries.remove(&oldest);
    }
}

pub(super) async fn send_udp_reply(
    cache: &mut UdpReplySocketCache,
    metrics: &ResidentDataplaneMetrics,
    request: &UdpReplyRequest,
) -> Result<(), UdpReplyError> {
    if time::Instant::now() >= request.deadline {
        return Err(UdpReplyError::TimedOut);
    }
    let socket = reply_socket(cache, request.original_dst)?;
    match time::timeout_at(
        request.deadline,
        send_udp_reply_when_writable(&socket, request.peer, &request.payload, metrics),
    )
    .await
    {
        Ok(Ok(())) => {
            metrics.udp_reply_sent();
            return Ok(());
        }
        Err(_) => return Err(UdpReplyError::TimedOut),
        Ok(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => {
            return Err(UdpReplyError::TimedOut);
        }
        Ok(Err(_)) => {}
    }

    cache.remove(request.original_dst);
    metrics.udp_reply_socket_recreated();
    let socket = reply_socket(cache, request.original_dst)?;
    match time::timeout_at(
        request.deadline,
        send_udp_reply_when_writable(&socket, request.peer, &request.payload, metrics),
    )
    .await
    {
        Ok(Ok(())) => {
            metrics.udp_reply_sent();
            Ok(())
        }
        Ok(Err(err)) => Err(UdpReplyError::Socket(format!(
            "send transparent UDP reply after socket recreation: {err}"
        ))),
        Err(_) => Err(UdpReplyError::TimedOut),
    }
}

fn reply_socket(
    cache: &mut UdpReplySocketCache,
    original_dst: SocketAddr,
) -> Result<Arc<tokio::net::UdpSocket>, UdpReplyError> {
    if let Some(socket) = cache.get(original_dst) {
        return Ok(socket);
    }
    let socket = open_transparent_udp_socket_bound_in_netns(PRODUCTION_NETNS, original_dst)
        .map_err(|err| {
            UdpReplyError::Socket(format!("open transparent UDP reply socket: {err}"))
        })?;
    apply_resident_udp_socket_buffer_tuning(&socket);
    socket.set_nonblocking(true).map_err(|err| {
        UdpReplyError::Socket(format!(
            "set transparent UDP reply socket nonblocking: {err}"
        ))
    })?;
    let socket = tokio::net::UdpSocket::from_std(socket).map_err(|err| {
        UdpReplyError::Socket(format!("register transparent UDP reply socket: {err}"))
    })?;
    Ok(cache.insert(original_dst, Arc::new(socket)))
}

async fn send_udp_reply_when_writable(
    socket: &tokio::net::UdpSocket,
    peer: SocketAddr,
    payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> io::Result<()> {
    loop {
        socket.writable().await?;
        match socket.try_send_to(payload, peer) {
            Ok(written) if written == payload.len() => return Ok(()),
            Ok(written) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!(
                        "partial UDP reply write: wrote {written} of {} bytes",
                        payload.len()
                    ),
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                metrics.udp_reply_send_would_block();
            }
            Err(err) => return Err(err),
        }
    }
}
