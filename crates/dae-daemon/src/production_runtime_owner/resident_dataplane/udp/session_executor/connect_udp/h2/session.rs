use std::collections::VecDeque;
use std::task::Poll;

use futures_util::future::poll_fn;

use super::tunnel::{ConnectUdpH2Tunnel, open_connect_udp_h2_tunnel};
use super::*;

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct ConnectUdpH2Session {
    runtime: ResidentConnectUdpRuntimePlan,
    tunnel: Option<ConnectUdpH2Tunnel>,
    decoder: MasqueCapsuleDecoder,
    responses: VecDeque<Bytes>,
}

impl ConnectUdpH2Session {
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn new(
        runtime: ResidentConnectUdpRuntimePlan,
    ) -> Self {
        Self {
            runtime,
            tunnel: None,
            decoder: MasqueCapsuleDecoder::new(runtime.capsule_limits),
            responses: VecDeque::new(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if self.tunnel.is_none() {
            self.open(proxy, original_dst).await?;
        }
        if self
            .tunnel
            .as_ref()
            .is_some_and(|tunnel| tunnel.target != original_dst)
        {
            return Err(format!(
                "CONNECT-UDP H2 session target changed from {} to {}; cross-target tunnel reuse is forbidden",
                self.tunnel
                    .as_ref()
                    .map(|tunnel| tunnel.target)
                    .unwrap_or(original_dst),
                original_dst,
            ));
        }
        if payload.len() > self.runtime.capsule_limits.max_datagram_payload_bytes
            && let Some(tunnel) = self.tunnel.as_ref()
        {
            tunnel.connection_lease.record_mtu_rejection();
        }
        let capsule = encode_connect_udp_capsule(payload, self.runtime.capsule_limits)
            .map_err(|err| format!("encode CONNECT-UDP H2 DATAGRAM Capsule: {err}"))?;
        let tunnel = self
            .tunnel
            .as_mut()
            .ok_or_else(|| "CONNECT-UDP H2 tunnel is not initialized".to_owned())?;
        send_connect_udp_h2_capsule(&mut tunnel.send, Bytes::from(capsule)).await?;
        if let Some(response) = self.poll_response().await? {
            Ok(response)
        } else {
            Ok(self.pending_response_result())
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn poll_response(
        &mut self,
    ) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(payload) = self.responses.pop_front() {
            return Ok(Some(self.response_result(payload)));
        }
        let Some(tunnel) = self.tunnel.as_mut() else {
            return Ok(None);
        };
        let chunk = poll_fn(|cx| match tunnel.receive.poll_data(cx) {
            Poll::Ready(value) => Poll::Ready(Some(value)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        match chunk {
            None => Ok(None),
            Some(Some(Ok(chunk))) => {
                release_h2_receive_capacity(&mut tunnel.receive, chunk.len())?;
                self.decode_chunk(&chunk)?;
                Ok(self
                    .responses
                    .pop_front()
                    .map(|payload| self.response_result(payload)))
            }
            Some(Some(Err(err))) => {
                if err.is_reset() {
                    tunnel.connection_lease.record_reset();
                }
                Err(format!("read CONNECT-UDP H2 Capsule DATA: {err}"))
            }
            Some(None) => Err(self.stream_closed_error()),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn wait_response(
        &mut self,
    ) -> Result<Option<UdpExchangeResult>, String> {
        loop {
            if let Some(payload) = self.responses.pop_front() {
                return Ok(Some(self.response_result(payload)));
            }
            let tunnel = match self.tunnel.as_mut() {
                Some(tunnel) => tunnel,
                None => return std::future::pending().await,
            };
            match tunnel.receive.data().await {
                Some(Ok(chunk)) => {
                    release_h2_receive_capacity(&mut tunnel.receive, chunk.len())?;
                    self.decode_chunk(&chunk)?;
                }
                Some(Err(err)) => {
                    if err.is_reset() {
                        tunnel.connection_lease.record_reset();
                    }
                    return Err(format!("read CONNECT-UDP H2 Capsule DATA: {err}"));
                }
                None => return Err(self.stream_closed_error()),
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn shutdown(&mut self) {
        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.send.send_reset(::h2::Reason::CANCEL);
        }
        self.responses.clear();
    }

    async fn open(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
    ) -> Result<(), String> {
        self.decoder = MasqueCapsuleDecoder::new(self.runtime.capsule_limits);
        self.responses.clear();
        self.tunnel = Some(open_connect_udp_h2_tunnel(proxy, original_dst, self.runtime).await?);
        Ok(())
    }

    fn decode_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
        let capsules = self
            .decoder
            .push(chunk)
            .map_err(|err| format!("decode CONNECT-UDP H2 Capsule: {err}"))?;
        for capsule in capsules {
            if let MasqueCapsule::Datagram(payload) = capsule
                && self.responses.len() < self.runtime.h2_session_queue_depth.max(1)
            {
                self.responses.push_back(payload);
            }
        }
        Ok(())
    }

    fn stream_closed_error(&self) -> String {
        if self.decoder.buffered_len() == 0 {
            "CONNECT-UDP H2 Capsule stream closed".to_owned()
        } else {
            format!(
                "CONNECT-UDP H2 Capsule stream closed with {} buffered byte(s)",
                self.decoder.buffered_len()
            )
        }
    }

    fn response_result(&self, payload: Bytes) -> UdpExchangeResult {
        UdpExchangeResult::new(payload.to_vec(), "connect-udp-h2-capsule")
            .with_session_executor("http2-extended-connect")
            .with_underlay_reuse("generation-owned-h2-connection-reused")
            .with_tls_underlay("rustls")
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("connect-udp-h2-capsule")
            .with_session_executor("http2-extended-connect")
            .with_underlay_reuse("generation-owned-h2-connection-reused")
            .with_tls_underlay("rustls")
    }
}

fn release_h2_receive_capacity(receive: &mut ::h2::RecvStream, bytes: usize) -> Result<(), String> {
    receive
        .flow_control()
        .release_capacity(bytes)
        .map_err(|err| format!("release CONNECT-UDP H2 receive capacity: {err}"))
}

async fn send_connect_udp_h2_capsule(
    send: &mut ::h2::SendStream<Bytes>,
    mut data: Bytes,
) -> Result<(), String> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = loop {
            let available = send.capacity();
            if available > 0 {
                break available;
            }
            let Some(capacity) = time::timeout(
                RESIDENT_CONNECT_TIMEOUT,
                poll_fn(|cx| send.poll_capacity(cx)),
            )
            .await
            .map_err(|_| "CONNECT-UDP H2 Capsule send capacity wait timeout".to_owned())?
            else {
                return Err(
                    "CONNECT-UDP H2 Capsule send stream closed before capacity became available"
                        .to_owned(),
                );
            };
            capacity
                .map_err(|err| format!("reserve CONNECT-UDP H2 Capsule send capacity: {err}"))?;
        };
        let chunk = data.split_to(capacity.min(data.len()));
        send.send_data(chunk, false)
            .map_err(|err| format!("send CONNECT-UDP H2 Capsule data: {err}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_response_queue_drops_excess_capsules_at_the_profile_limit() {
        let runtime = ResidentConnectUdpRuntimePlan {
            h2_session_queue_depth: 2,
            ..ResidentConnectUdpRuntimePlan::standalone()
        };
        let mut session = ConnectUdpH2Session::new(runtime);
        let mut encoded = Vec::new();
        for payload in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"excess".as_slice(),
        ] {
            encoded.extend(
                encode_connect_udp_capsule(payload, runtime.capsule_limits)
                    .expect("encode bounded H2 response fixture"),
            );
        }

        session
            .decode_chunk(&encoded)
            .expect("decode bounded H2 response fixture");

        assert_eq!(session.responses.len(), 2);
        assert_eq!(
            session.responses.pop_front().as_deref(),
            Some(b"first".as_slice())
        );
        assert_eq!(
            session.responses.pop_front().as_deref(),
            Some(b"second".as_slice())
        );
    }
}
