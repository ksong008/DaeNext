use super::*;
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::task::Poll;

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct Hysteria2QuicDatagramSession
{
    auth: String,
    allow_insecure: bool,
    pin_sha256: String,
    max_rx: u64,
    obfs: ResidentHysteria2ObfsPlan,
    port_hop_ports: Vec<u16>,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    session_id: u32,
    fragments: QuicUdpFragmentBuffer,
}

#[derive(Default)]
struct QuicUdpFragmentBuffer {
    pending: BTreeMap<u16, PendingQuicUdpFragments>,
}

struct PendingQuicUdpFragments {
    total: u8,
    parts: BTreeMap<u8, Vec<u8>>,
}

impl QuicUdpFragmentBuffer {
    fn push(
        &mut self,
        packet_id: u16,
        frag_id: u8,
        frag_count: u8,
        payload: Vec<u8>,
        label: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        if frag_count == 0 || frag_id >= frag_count {
            return Err(format!(
                "invalid {label} UDP fragment fields: frag_id={frag_id} frag_count={frag_count}"
            ));
        }
        if frag_count == 1 {
            return Ok(Some(payload));
        }
        if !self.pending.contains_key(&packet_id) && self.pending.len() >= 64 {
            return Err(format!("{label} UDP fragment buffer is full"));
        }
        if let Some(entry) = self.pending.get(&packet_id)
            && entry.total != frag_count
        {
            let previous = entry.total;
            self.pending.remove(&packet_id);
            return Err(format!(
                "{label} UDP fragment count changed for packet {packet_id}: {previous} -> {frag_count}"
            ));
        }
        let complete = {
            let entry = self
                .pending
                .entry(packet_id)
                .or_insert_with(|| PendingQuicUdpFragments {
                    total: frag_count,
                    parts: BTreeMap::new(),
                });
            entry.parts.insert(frag_id, payload);
            entry.parts.len() == frag_count as usize
        };
        if !complete {
            return Ok(None);
        }
        let entry = self
            .pending
            .remove(&packet_id)
            .ok_or_else(|| format!("{label} UDP fragment packet disappeared"))?;
        let mut out = Vec::new();
        for id in 0..entry.total {
            let part = entry.parts.get(&id).ok_or_else(|| {
                format!("{label} UDP fragment packet {packet_id} missing fragment {id}")
            })?;
            if out.len() + part.len() > u16::MAX as usize {
                return Err(format!(
                    "{label} UDP reassembled payload too large: {} bytes",
                    out.len() + part.len()
                ));
            }
            out.extend_from_slice(part);
        }
        Ok(Some(out))
    }

    fn clear(&mut self) {
        self.pending.clear();
    }
}

impl Hysteria2QuicDatagramSession {
    pub(super) fn new(
        auth: String,
        allow_insecure: bool,
        pin_sha256: String,
        max_rx: u64,
        obfs: ResidentHysteria2ObfsPlan,
        port_hop_ports: Vec<u16>,
    ) -> Self {
        Self {
            auth,
            allow_insecure,
            pin_sha256,
            max_rx,
            obfs,
            port_hop_ports,
            endpoint: None,
            connection: None,
            session_id: fastrand::u32(1..=u32::MAX),
            fragments: QuicUdpFragmentBuffer::default(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.ensure_open(proxy).await?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "Hysteria2 QUIC connection is not initialized".to_owned())?;
        let packet_id = fastrand::u16(1..=u16::MAX);
        let request = build_hysteria2_udp_message(
            self.session_id,
            packet_id,
            &original_dst.to_string(),
            payload,
        )?;
        connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| format!("send Hysteria2 UDP datagram: {err}"))?;
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let connection = match self.connection.as_ref() {
            Some(connection) => connection,
            None => return Ok(None),
        };
        let read = connection.read_datagram();
        tokio::pin!(read);
        let response = poll_fn(|cx| match read.as_mut().poll(cx) {
            Poll::Ready(response) => Poll::Ready(Some(response)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        let Some(response) = response else {
            return Ok(None);
        };
        let response = response.map_err(|err| format!("read Hysteria2 UDP datagram: {err}"))?;
        let parsed = parse_hysteria2_udp_message(&response)?;
        let Some(payload) = self.fragments.push(
            parsed.packet_id,
            parsed.frag_id,
            parsed.frag_count,
            parsed.payload,
            "Hysteria2",
        )?
        else {
            return Ok(None);
        };
        Ok(Some(
            UdpExchangeResult::new(payload, "quic-udp-datagram")
                .with_quic_underlay("quinn-h3")
                .with_session_executor("tokio-quic-datagram-session")
                .with_underlay_reuse("quic-endpoint-and-connection-reused"),
        ))
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("quic-udp-datagram")
            .with_quic_underlay("quinn-h3")
            .with_session_executor("tokio-quic-datagram-session")
            .with_underlay_reuse("quic-endpoint-and-connection-reused")
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.connection.is_some() {
            return Ok(());
        }
        let ResidentConnectedQuicEndpoint {
            endpoint,
            connection,
            ..
        } = open_hysteria2_quic_connection_candidates_async(
            proxy,
            proxy.mark,
            &self.obfs,
            &self.port_hop_ports,
            self.allow_insecure,
            &self.pin_sha256,
            RESIDENT_UDP_RESPONSE_TIMEOUT,
        )
        .await?;
        let auth_report = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            authenticate_hysteria2_connection(connection.clone(), &self.auth, self.max_rx),
        )
        .await
        .map_err(|_| "Hysteria2 QUIC auth timeout".to_owned())?
        .map_err(|err| format!("authenticate Hysteria2 QUIC connection: {err}"))?;
        if !auth_report.auth_ok || !auth_report.udp_enabled {
            connection.close(0x101_u32.into(), b"resident hysteria2 udp auth failed");
            endpoint.wait_idle().await;
            return Err(format!(
                "Hysteria2 UDP unavailable after auth: status={} udp_enabled={}",
                auth_report.status, auth_report.udp_enabled
            ));
        }
        self.connection = Some(connection);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"resident hysteria2 udp session done");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.wait_idle().await;
        }
        self.fragments.clear();
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct TuicQuicDatagramSession {
    uuid: String,
    password: String,
    alpn: Vec<String>,
    allow_insecure: bool,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    assoc_id: u16,
    fragments: QuicUdpFragmentBuffer,
}

impl TuicQuicDatagramSession {
    pub(super) fn new(
        uuid: String,
        password: String,
        alpn: Vec<String>,
        allow_insecure: bool,
    ) -> Self {
        Self {
            uuid,
            password,
            alpn,
            allow_insecure,
            endpoint: None,
            connection: None,
            assoc_id: fastrand::u16(1..=u16::MAX),
            fragments: QuicUdpFragmentBuffer::default(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.ensure_open(proxy).await?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "TUIC QUIC connection is not initialized".to_owned())?;
        let packet_id = fastrand::u16(1..=u16::MAX);
        let request =
            build_tuic_packet_frame(self.assoc_id, packet_id, &original_dst.to_string(), payload)?;
        connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| format!("send TUIC UDP datagram: {err}"))?;
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let connection = match self.connection.as_ref() {
            Some(connection) => connection,
            None => return Ok(None),
        };
        let read = connection.read_datagram();
        tokio::pin!(read);
        let response = poll_fn(|cx| match read.as_mut().poll(cx) {
            Poll::Ready(response) => Poll::Ready(Some(response)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        let Some(response) = response else {
            return Ok(None);
        };
        let response = response.map_err(|err| format!("read TUIC UDP datagram: {err}"))?;
        let parsed = parse_tuic_packet_frame(&response)?;
        let Some(payload) = self.fragments.push(
            parsed.packet_id,
            parsed.frag_id,
            parsed.frag_total,
            parsed.payload,
            "TUIC",
        )?
        else {
            return Ok(None);
        };
        Ok(Some(
            UdpExchangeResult::new(payload, "quic-udp-datagram")
                .with_quic_underlay("quinn")
                .with_session_executor("tokio-quic-datagram-session")
                .with_underlay_reuse("quic-endpoint-and-connection-reused"),
        ))
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("quic-udp-datagram")
            .with_quic_underlay("quinn")
            .with_session_executor("tokio-quic-datagram-session")
            .with_underlay_reuse("quic-endpoint-and-connection-reused")
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.connection.is_some() {
            return Ok(());
        }
        let ResidentConnectedQuicEndpoint {
            endpoint,
            connection,
            ..
        } = open_tuic_quic_connection_candidates_async(
            proxy,
            proxy.mark,
            &self.alpn,
            self.allow_insecure,
            RESIDENT_UDP_RESPONSE_TIMEOUT,
        )
        .await?;
        time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            authenticate_tuic_connection(&connection, &self.uuid, &self.password),
        )
        .await
        .map_err(|_| "TUIC QUIC auth timeout".to_owned())?
        .map_err(|err| format!("authenticate TUIC QUIC connection: {err}"))?;
        self.connection = Some(connection);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"resident tuic udp session done");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.wait_idle().await;
        }
        self.fragments.clear();
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct JuicityQuicStreamPacketSession
{
    uuid: String,
    password: String,
    allow_insecure: bool,
    pinned_certchain_sha256: String,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    auth_stream: Option<dae_outbound::juicity::JuicityAuthStream>,
}

impl JuicityQuicStreamPacketSession {
    pub(super) fn new(
        uuid: String,
        password: String,
        allow_insecure: bool,
        pinned_certchain_sha256: String,
    ) -> Self {
        Self {
            uuid,
            password,
            allow_insecure,
            pinned_certchain_sha256,
            endpoint: None,
            connection: None,
            auth_stream: None,
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.ensure_open(proxy).await?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "Juicity QUIC connection is not initialized".to_owned())?;
        let request_frame = seal_stream_packet_frame(&original_dst.to_string(), payload)
            .map_err(|err| format!("build Juicity UDP stream packet: {err}"))?;
        let request =
            build_juicity_stream_packet_request(&original_dst.to_string(), &request_frame.encoded)?;
        let (mut send, mut recv) =
            time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.open_bi())
                .await
                .map_err(|_| "open Juicity UDP stream timeout".to_owned())?
                .map_err(|err| format!("open Juicity UDP stream: {err}"))?;
        time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, send.write_all(&request))
            .await
            .map_err(|_| "write Juicity UDP stream packet timeout".to_owned())?
            .map_err(|err| format!("write Juicity UDP stream packet: {err}"))?;
        send.finish()
            .map_err(|err| format!("finish Juicity UDP stream packet: {err}"))?;
        let response = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            read_juicity_stream_packet_response(&mut recv),
        )
        .await
        .map_err(|_| "read Juicity UDP stream response timeout".to_owned())??;
        let parsed = decode_stream_packet_frame(&response)
            .map_err(|err| format!("decode Juicity UDP stream packet: {err}"))?;
        Ok(
            UdpExchangeResult::new(parsed.payload, "quic-udp-stream-packet")
                .with_quic_underlay("quinn-h3")
                .with_session_executor("tokio-quic-stream-packet-session")
                .with_underlay_reuse("quic-endpoint-connection-and-auth-stream-reused"),
        )
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.connection.is_some() && self.auth_stream.is_some() {
            return Ok(());
        }
        let ResidentConnectedQuicEndpoint {
            endpoint,
            connection,
            ..
        } = open_juicity_quic_connection_candidates_async(
            proxy,
            proxy.mark,
            self.allow_insecure,
            &self.pinned_certchain_sha256,
            RESIDENT_UDP_RESPONSE_TIMEOUT,
        )
        .await?;
        let (_auth_report, auth_stream) = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            authenticate_juicity_connection(&connection, &self.uuid, &self.password),
        )
        .await
        .map_err(|_| "Juicity QUIC auth timeout".to_owned())?
        .map_err(|err| format!("authenticate Juicity QUIC connection: {err}"))?;
        self.auth_stream = Some(auth_stream);
        self.connection = Some(connection);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(auth_stream) = self.auth_stream.as_mut() {
            let _ = auth_stream.finish().await;
        }
        self.auth_stream.take();
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"resident juicity udp session done");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.wait_idle().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_datagram_pending_results_do_not_forward_empty_reply() {
        let hysteria2 = Hysteria2QuicDatagramSession::new(
            "auth".to_owned(),
            false,
            String::new(),
            0,
            ResidentHysteria2ObfsPlan::none(),
            Vec::new(),
        )
        .pending_response_result();
        assert!(!hysteria2.reply_forwarded);
        assert!(hysteria2.payload.is_empty());
        assert_eq!(hysteria2.execution_label, "quic-udp-datagram");
        assert_eq!(hysteria2.quic_underlay, Some("quinn-h3"));
        assert_eq!(
            hysteria2.underlay_reuse,
            Some("quic-endpoint-and-connection-reused")
        );

        let tuic = TuicQuicDatagramSession::new(
            "uuid".to_owned(),
            "password".to_owned(),
            Vec::new(),
            true,
        )
        .pending_response_result();
        assert!(!tuic.reply_forwarded);
        assert!(tuic.payload.is_empty());
        assert_eq!(tuic.execution_label, "quic-udp-datagram");
        assert_eq!(tuic.quic_underlay, Some("quinn"));
        assert_eq!(
            tuic.underlay_reuse,
            Some("quic-endpoint-and-connection-reused")
        );
    }

    #[test]
    fn quic_udp_fragment_buffer_reassembles_fragments_by_packet_id() {
        let mut buffer = QuicUdpFragmentBuffer::default();
        assert!(
            buffer
                .push(7, 1, 3, b"middle-".to_vec(), "Hysteria2")
                .unwrap()
                .is_none()
        );
        assert!(
            buffer
                .push(7, 2, 3, b"tail".to_vec(), "Hysteria2")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            buffer
                .push(7, 0, 3, b"head-".to_vec(), "Hysteria2")
                .unwrap()
                .unwrap(),
            b"head-middle-tail"
        );
    }
}
