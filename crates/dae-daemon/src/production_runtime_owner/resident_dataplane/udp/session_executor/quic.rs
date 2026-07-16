use super::*;
use std::future::poll_fn;
use std::task::Poll;

mod fragment_buffer;
mod packet_id;
use self::fragment_buffer::QuicUdpFragmentBuffer;
use self::packet_id::QuicUdpPacketIdAllocator;

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct Hysteria2QuicDatagramSession
{
    auth: String,
    tls_identity: dae_outbound::hysteria2::Hysteria2TlsIdentity,
    max_rx: u64,
    obfs: ResidentHysteria2ObfsPlan,
    port_hop_ports: Vec<u16>,
    endpoint: Option<ObservedQuicEndpoint>,
    connection: Option<quinn::Connection>,
    auth_session: Option<Hysteria2AuthenticatedSession>,
    session_id: u32,
    fragments: QuicUdpFragmentBuffer,
    packet_ids: QuicUdpPacketIdAllocator,
}

impl Hysteria2QuicDatagramSession {
    pub(super) fn new(
        auth: String,
        tls_identity: dae_outbound::hysteria2::Hysteria2TlsIdentity,
        max_rx: u64,
        obfs: ResidentHysteria2ObfsPlan,
        port_hop_ports: Vec<u16>,
    ) -> Self {
        Self {
            auth,
            tls_identity,
            max_rx,
            obfs,
            port_hop_ports,
            endpoint: None,
            connection: None,
            auth_session: None,
            session_id: fastrand::u32(1..=u32::MAX),
            fragments: QuicUdpFragmentBuffer::default(),
            packet_ids: QuicUdpPacketIdAllocator::default(),
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
        let packet_id = self.packet_ids.allocate()?;
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
        let response = {
            let connection = match self.connection.as_ref() {
                Some(connection) => connection,
                None => return Ok(None),
            };
            let read = connection.read_datagram();
            tokio::pin!(read);
            poll_fn(|cx| match read.as_mut().poll(cx) {
                Poll::Ready(response) => Poll::Ready(Some(response)),
                Poll::Pending => Poll::Ready(None),
            })
            .await
        };
        let Some(response) = response else {
            return Ok(None);
        };
        let response = response.map_err(|err| format!("read Hysteria2 UDP datagram: {err}"))?;
        self.decode_response(&response)
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "Hysteria2 QUIC connection is not initialized".to_owned())?;
        let response = connection
            .read_datagram()
            .await
            .map_err(|err| format!("read Hysteria2 UDP datagram: {err}"))?;
        self.decode_response(&response)
    }

    fn decode_response(&mut self, response: &[u8]) -> Result<Option<UdpExchangeResult>, String> {
        let parsed = parse_hysteria2_udp_message(response)?;
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
            &self.tls_identity,
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            QuicEndpointCallerClass::UdpData,
        )
        .await?;
        let auth_session = match time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            authenticate_hysteria2_connection(connection.clone(), &self.auth, self.max_rx),
        )
        .await
        {
            Err(_) => {
                endpoint.mark_failed();
                return Err("Hysteria2 QUIC auth timeout".to_owned());
            }
            Ok(Err(err)) => {
                endpoint.mark_failed();
                return Err(format!("authenticate Hysteria2 QUIC connection: {err}"));
            }
            Ok(Ok(session)) => session,
        };
        if !auth_session.report().auth_ok || !auth_session.report().udp_enabled {
            endpoint.mark_failed();
            connection.close(0x101_u32.into(), b"resident hysteria2 udp auth failed");
            endpoint.wait_idle().await;
            return Err(format!(
                "Hysteria2 UDP unavailable after auth: status={} udp_enabled={}",
                auth_session.report().status,
                auth_session.report().udp_enabled
            ));
        }
        endpoint.mark_ready();
        self.connection = Some(connection);
        self.endpoint = Some(endpoint);
        self.auth_session = Some(auth_session);
        Ok(())
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"resident hysteria2 udp session done");
        }
        self.auth_session = None;
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.wait_idle().await;
        }
        self.fragments.clear();
        self.packet_ids.clear();
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct TuicQuicDatagramSession {
    uuid: String,
    password: String,
    alpn: Vec<String>,
    allow_insecure: bool,
    endpoint: Option<ObservedQuicEndpoint>,
    connection: Option<quinn::Connection>,
    assoc_id: u16,
    fragments: QuicUdpFragmentBuffer,
    packet_ids: QuicUdpPacketIdAllocator,
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
            packet_ids: QuicUdpPacketIdAllocator::default(),
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
        let packet_id = self.packet_ids.allocate()?;
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
        let response = {
            let connection = match self.connection.as_ref() {
                Some(connection) => connection,
                None => return Ok(None),
            };
            let read = connection.read_datagram();
            tokio::pin!(read);
            poll_fn(|cx| match read.as_mut().poll(cx) {
                Poll::Ready(response) => Poll::Ready(Some(response)),
                Poll::Pending => Poll::Ready(None),
            })
            .await
        };
        let Some(response) = response else {
            return Ok(None);
        };
        let response = response.map_err(|err| format!("read TUIC UDP datagram: {err}"))?;
        self.decode_response(&response)
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "TUIC QUIC connection is not initialized".to_owned())?;
        let response = connection
            .read_datagram()
            .await
            .map_err(|err| format!("read TUIC UDP datagram: {err}"))?;
        self.decode_response(&response)
    }

    fn decode_response(&mut self, response: &[u8]) -> Result<Option<UdpExchangeResult>, String> {
        let parsed = parse_tuic_packet_frame(response)?;
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
            QuicEndpointCallerClass::UdpData,
        )
        .await?;
        match time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            authenticate_tuic_connection(&connection, &self.uuid, &self.password),
        )
        .await
        {
            Err(_) => {
                endpoint.mark_failed();
                return Err("TUIC QUIC auth timeout".to_owned());
            }
            Ok(Err(err)) => {
                endpoint.mark_failed();
                return Err(format!("authenticate TUIC QUIC connection: {err}"));
            }
            Ok(Ok(_)) => {}
        }
        endpoint.mark_ready();
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
        self.packet_ids.clear();
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct JuicityQuicStreamPacketSession
{
    uuid: String,
    password: String,
    allow_insecure: bool,
    pinned_certchain_sha256: String,
    endpoint: Option<ObservedQuicEndpoint>,
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
            QuicEndpointCallerClass::UdpData,
        )
        .await?;
        let (_auth_report, auth_stream) = match time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            authenticate_juicity_connection(&connection, &self.uuid, &self.password),
        )
        .await
        {
            Err(_) => {
                endpoint.mark_failed();
                return Err("Juicity QUIC auth timeout".to_owned());
            }
            Ok(Err(err)) => {
                endpoint.mark_failed();
                return Err(format!("authenticate Juicity QUIC connection: {err}"));
            }
            Ok(Ok(auth)) => auth,
        };
        endpoint.mark_ready();
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
            dae_outbound::hysteria2::Hysteria2TlsIdentity::from_node_and_global(
                "fixture.invalid",
                false,
                false,
                "",
            )
            .unwrap(),
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
}
