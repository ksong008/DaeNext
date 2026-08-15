use super::*;
use std::collections::HashMap;
use std::io;
use std::os::fd::AsRawFd;

pub(super) struct UdpReplySocketCache {
    capacity: usize,
    tick: u64,
    entries: HashMap<SocketAddr, UdpReplySocketEntry>,
}

struct UdpReplySocketEntry {
    socket: Arc<tokio::net::UdpSocket>,
    last_used: u64,
    last_used_at: time::Instant,
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
        entry.last_used_at = time::Instant::now();
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
            entry.last_used_at = time::Instant::now();
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
                last_used_at: time::Instant::now(),
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

    pub(super) fn evict_idle(&mut self, now: time::Instant, idle_timeout: Duration) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now.saturating_duration_since(entry.last_used_at) < idle_timeout);
        before.saturating_sub(self.entries.len())
    }
}

pub(super) async fn send_udp_reply(
    cache: &mut UdpReplySocketCache,
    metrics: &ResidentDataplaneMetrics,
    request: &UdpReplyRequest,
) -> Result<(), UdpReplyError> {
    if time::Instant::now() >= request.deadline {
        return Err(UdpReplyError::ResponseTimedOut);
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
        Err(_) => return Err(UdpReplyError::ResponseTimedOut),
        Ok(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => {
            return Err(UdpReplyError::ResponseTimedOut);
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
        Err(_) => Err(UdpReplyError::ResponseTimedOut),
    }
}

pub(super) async fn send_udp_reply_batch(
    cache: &mut UdpReplySocketCache,
    metrics: &ResidentDataplaneMetrics,
    requests: &[UdpReplyRequest],
) -> Vec<Result<(), UdpReplyError>> {
    let mut results = (0..requests.len()).map(|_| None).collect::<Vec<_>>();
    let mut groups = HashMap::<SocketAddr, Vec<usize>>::new();
    for (index, request) in requests.iter().enumerate() {
        if request.deadline <= time::Instant::now() {
            results[index] = Some(Err(UdpReplyError::ResponseTimedOut));
        } else {
            groups.entry(request.original_dst).or_default().push(index);
        }
    }

    for (original_dst, indices) in groups {
        if indices.len() == 1 {
            let index = indices[0];
            results[index] = Some(send_udp_reply(cache, metrics, &requests[index]).await);
            continue;
        }
        let socket = match reply_socket(cache, original_dst) {
            Ok(socket) => socket,
            Err(err) => {
                let error = err.to_string();
                for index in indices {
                    results[index] = Some(Err(UdpReplyError::Socket(error.clone())));
                }
                continue;
            }
        };
        let earliest_deadline = indices
            .iter()
            .map(|index| requests[*index].deadline)
            .min()
            .expect("non-empty UDP reply batch has a deadline");
        let sent = match time::timeout_at(earliest_deadline, socket.writable()).await {
            Ok(Ok(())) => {
                let datagrams = indices
                    .iter()
                    .map(|index| UdpSendMessage {
                        payload: &requests[*index].payload,
                        peer: Some(requests[*index].peer),
                    })
                    .collect::<Vec<_>>();
                metrics.udp_reply_send_syscall(datagrams.len());
                match try_sendmmsg(socket.as_raw_fd(), &datagrams) {
                    Ok(sent) => sent,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        metrics.udp_reply_send_would_block();
                        0
                    }
                    Err(_) => {
                        cache.remove(original_dst);
                        metrics.udp_reply_socket_recreated();
                        0
                    }
                }
            }
            _ => 0,
        };
        if sent != 0 {
            metrics.udp_reply_sent_count(sent);
            for index in indices.iter().take(sent) {
                results[*index] = Some(Ok(()));
            }
        }
        if sent < indices.len() {
            if sent != 0 {
                metrics.udp_reply_partial_failure();
            }
            for index in indices.into_iter().skip(sent) {
                results[index] = Some(send_udp_reply(cache, metrics, &requests[index]).await);
            }
        }
    }

    results
        .into_iter()
        .map(|result| result.unwrap_or(Err(UdpReplyError::DispatcherClosed)))
        .collect()
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
        metrics.udp_reply_send_syscall(1);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reply_socket_cache_evicts_idle_entries_without_capacity_pressure() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket = Arc::new(tokio::net::UdpSocket::from_std(socket).unwrap());
        let original_dst: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let mut cache = UdpReplySocketCache::new(4);
        cache.insert(original_dst, socket);
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.evict_idle(time::Instant::now(), Duration::from_secs(30)),
            0
        );
        assert_eq!(
            cache.evict_idle(
                time::Instant::now() + Duration::from_secs(31),
                Duration::from_secs(30),
            ),
            1
        );
        assert_eq!(cache.len(), 0);
    }

    #[cfg(not(feature = "test-scalar-udp-send"))]
    #[tokio::test]
    async fn reply_batch_sends_ready_datagrams_in_one_syscall() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.set_nonblocking(true).unwrap();
        let sender = Arc::new(tokio::net::UdpSocket::from_std(sender).unwrap());
        let original_dst: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let mut cache = UdpReplySocketCache::new(4);
        cache.insert(original_dst, sender);
        let admission = ResidentUdpPayloadAdmission::new(1, 1024);
        let requests = [b"first".to_vec(), b"second".to_vec()]
            .into_iter()
            .map(|payload| UdpReplyRequest {
                original_dst,
                peer,
                _payload_admission: admission.try_acquire(payload.len()).unwrap(),
                payload,
                deadline: time::Instant::now() + Duration::from_secs(1),
                response: None,
                download_bytes_on_success: 0,
            })
            .collect::<Vec<_>>();
        let metrics = ResidentDataplaneMetrics::default();

        let results = send_udp_reply_batch(&mut cache, &metrics, &requests).await;
        assert!(results.into_iter().all(|result| result.is_ok()));
        let mut received = Vec::new();
        for _ in 0..2 {
            let mut buf = [0_u8; 16];
            let read = receiver.recv(&mut buf).await.unwrap();
            received.push(buf[..read].to_vec());
        }
        assert_eq!(received, vec![b"first".to_vec(), b"second".to_vec()]);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["udpReplySyscalls"], 1);
        assert_eq!(snapshot["udpReplyDatagrams"], 2);
        assert_eq!(snapshot["udpReplyBatches"], 1);
        assert_eq!(snapshot["udpReplyBatchMax"], 2);
    }

    #[tokio::test]
    async fn expired_reply_does_not_discard_a_ready_datagram_from_the_same_socket() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.set_nonblocking(true).unwrap();
        let sender = Arc::new(tokio::net::UdpSocket::from_std(sender).unwrap());
        let original_dst: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let mut cache = UdpReplySocketCache::new(4);
        cache.insert(original_dst, sender);
        let admission = ResidentUdpPayloadAdmission::new(2, 1024);
        let now = time::Instant::now();
        let requests = vec![
            UdpReplyRequest {
                original_dst,
                peer,
                _payload_admission: admission.try_acquire(7).unwrap(),
                payload: b"expired".to_vec(),
                deadline: now - Duration::from_millis(1),
                response: None,
                download_bytes_on_success: 0,
            },
            UdpReplyRequest {
                original_dst,
                peer,
                _payload_admission: admission.try_acquire(5).unwrap(),
                payload: b"ready".to_vec(),
                deadline: now + Duration::from_secs(1),
                response: None,
                download_bytes_on_success: 0,
            },
        ];
        let metrics = ResidentDataplaneMetrics::default();

        let results = send_udp_reply_batch(&mut cache, &metrics, &requests).await;
        assert!(matches!(results[0], Err(UdpReplyError::ResponseTimedOut)));
        assert!(results[1].is_ok());
        let mut received = [0_u8; 16];
        let read = receiver.recv(&mut received).await.unwrap();
        assert_eq!(&received[..read], b"ready");
    }
}
