use super::*;

impl UdpSessionExecutor {
    fn batch_relay(&mut self) -> Option<&mut DatagramRelay> {
        match self {
            Self::ShadowsocksAead(session) => Some(&mut session.relay),
            Self::Shadowsocks2022(session) => Some(&mut session.relay),
            Self::Socks5(session) => Some(&mut session.relay),
            _ => None,
        }
    }
    pub(in crate::udp) fn begin_datagram_batch(&mut self, limit: usize) -> bool {
        self.batch_relay()
            .is_some_and(|relay| relay.begin_batch(limit))
    }
    pub(in crate::udp) async fn flush_datagram_batch(
        &mut self,
        mark: u32,
    ) -> Vec<Result<(), String>> {
        match self.batch_relay() {
            Some(relay) => relay.flush_batch(mark).await,
            None => Vec::new(),
        }
    }
}

impl DatagramRelay {
    fn begin_batch(&mut self, limit: usize) -> bool {
        // The syscall adapter has fixed 32-slot arrays. Profile limits may be
        // smaller, and scalar diagnostic builds must bypass batching entirely.
        let limit = limit.clamp(1, 32);
        if limit == 1 || cfg!(feature = "test-scalar-udp-send") {
            return false;
        }
        self.batch_limit = limit;
        self.batch = Some(Vec::with_capacity(limit));
        true
    }

    async fn flush_batch(&mut self, mark: u32) -> Vec<Result<(), String>> {
        let batch = self.batch.take().unwrap_or_default();
        let mut results = Vec::with_capacity(batch.len());
        if cfg!(feature = "test-scalar-udp-send") {
            for packet in batch {
                results.push(self.send_batch_packet(&packet, mark).await);
            }
            return results;
        }
        while results.len() < batch.len() {
            let remote = self.remote_candidates.get(self.selected_index).copied();
            let sent = match (&self.socket, remote) {
                (Some(socket), Some(remote)) => {
                    let messages: Vec<_> = batch[results.len()..]
                        .iter()
                        .map(|packet| UdpSendMessage {
                            payload: packet,
                            peer: Some(remote),
                        })
                        .collect();
                    socket
                        .async_io(tokio::io::Interest::WRITABLE, || {
                            try_sendmmsg(socket.as_raw_fd(), &messages)
                        })
                        .await
                }
                _ => Err(std::io::Error::other("UDP outbound batch has no socket")),
            };
            match sent {
                Ok(count) if count > 0 => results.extend((0..count).map(|_| Ok(()))),
                // Only the unaccepted suffix falls back to normal candidate
                // failover. A successful sendmmsg prefix is never replayed.
                _ => {
                    for packet in &batch[results.len()..] {
                        results.push(self.send_batch_packet(packet, mark).await);
                    }
                }
            }
        }
        results
    }

    async fn send_batch_packet(&mut self, packet: &[u8], mark: u32) -> Result<(), String> {
        if self.socket.is_none() {
            self.open_candidates(self.remote_candidates.clone(), mark, "batched proxy")
                .await?;
        }
        self.send_packet(packet, mark, "batched proxy").await
    }
}

#[cfg(test)]
mod tests;
