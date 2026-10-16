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
    pub(in crate::udp) fn begin_datagram_batch(&mut self) -> bool {
        if let Some(relay) = self.batch_relay() {
            relay.batch = Some(Vec::with_capacity(32));
            true
        } else {
            false
        }
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
    async fn flush_batch(&mut self, mark: u32) -> Vec<Result<(), String>> {
        let batch = self.batch.take().unwrap_or_default();
        let mut results = Vec::with_capacity(batch.len());
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
                        if self.socket.is_none() {
                            let _ = self
                                .open_candidates(
                                    self.remote_candidates.clone(),
                                    mark,
                                    "batched proxy",
                                )
                                .await;
                        }
                        results.push(self.send_packet(packet, mark, "batched proxy").await);
                    }
                }
            }
        }
        results
    }
}

#[cfg(test)]
mod tests;
