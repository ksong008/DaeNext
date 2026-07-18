use super::*;

use crate::production_runtime_owner::resident_dataplane::QuicUdpDatagramResourceProfile;

mod fragment_buffer;
mod hysteria2_datagram;
mod packet_id;
mod tuic_datagram;
use self::fragment_buffer::{QuicUdpFragmentBuffer, QuicUdpFragmentOutcome};
use self::hysteria2_datagram::send_hysteria2_udp_message;
use self::packet_id::QuicUdpPacketIdAllocator;
use self::tuic_datagram::send_tuic_udp_packet;

const TUIC_ASSOCIATION_IDENTITY_DOMAIN: &[u8] = b"tuic-v5-association";
const HYSTERIA2_SESSION_IDENTITY_DOMAIN: &[u8] = b"hysteria2-udp-session";

fn earliest_expiration(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(expiration), None) | (None, Some(expiration)) => Some(expiration),
        (None, None) => None,
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct Hysteria2QuicDatagramSession
{
    proxy: Option<Arc<ResidentProxyPlan>>,
    owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    udp_session: Option<Hysteria2UdpSessionLease>,
    session_id: u32,
    fragments: QuicUdpFragmentBuffer,
    packet_ids: QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
    fixed_target: UdpSessionFixedTarget,
}

impl Hysteria2QuicDatagramSession {
    pub(super) fn new(
        proxy: Arc<ResidentProxyPlan>,
        owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    ) -> Self {
        let resources = QuicUdpDatagramResourceProfile::selected();
        Self {
            proxy: Some(proxy),
            owner_registry,
            owner_deadline: None,
            udp_session: None,
            session_id: 0,
            fragments: QuicUdpFragmentBuffer::new(resources, HYSTERIA2_MAX_UDP_PAYLOAD_LENGTH),
            packet_ids: QuicUdpPacketIdAllocator::new(resources),
            resources,
            fixed_target: UdpSessionFixedTarget::default(),
        }
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        let resources = QuicUdpDatagramResourceProfile::selected();
        Self {
            proxy: None,
            owner_registry: None,
            owner_deadline: None,
            udp_session: None,
            session_id: 0,
            fragments: QuicUdpFragmentBuffer::new(resources, HYSTERIA2_MAX_UDP_PAYLOAD_LENGTH),
            packet_ids: QuicUdpPacketIdAllocator::new(resources),
            resources,
            fixed_target: UdpSessionFixedTarget::default(),
        }
    }

    pub(super) fn set_owner_deadline(&mut self, deadline: dae_runtime_control::AbsoluteDeadline) {
        if self.udp_session.is_none() {
            self.owner_deadline = Some(deadline);
        }
    }

    pub(super) async fn exchange(
        &mut self,
        _proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.fixed_target
            .bind(original_dst, "Hysteria2 UDP session")?;
        self.ensure_open().await?;
        let connection = self
            .udp_session
            .as_ref()
            .ok_or_else(|| "Hysteria2 UDP session lease is not initialized".to_owned())?
            .connection()
            .clone();
        let request = Hysteria2UdpMessage::new(self.session_id, original_dst.to_string(), payload)
            .map_err(|err| format!("build Hysteria2 UDP datagram: {err}"))?;
        send_hysteria2_udp_message(&connection, &request, &mut self.packet_ids, self.resources)?;
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.fragments.expire();
        self.packet_ids.expire();
        let response = match self.udp_session.as_mut() {
            Some(session) => session.try_receive()?,
            None => return Ok(None),
        };
        let Some(response) = response else {
            return Ok(None);
        };
        self.decode_response(response)
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if self.udp_session.is_none() {
            return Err("Hysteria2 UDP session lease is not initialized".to_owned());
        }
        let expiration = earliest_expiration(
            self.fragments.next_expiration(),
            self.packet_ids.next_expiration(),
        );
        let Some(response) = self
            .udp_session
            .as_mut()
            .expect("Hysteria2 UDP session was checked above")
            .receive_until(expiration)
            .await?
        else {
            self.fragments.expire();
            self.packet_ids.expire();
            return Ok(None);
        };
        self.decode_response(response)
    }

    fn decode_response(
        &mut self,
        parsed: Hysteria2UdpMessage,
    ) -> Result<Option<UdpExchangeResult>, String> {
        let observed_identity = UdpResponseIdentityToken::from_protocol_identity(
            HYSTERIA2_SESSION_IDENTITY_DOMAIN,
            &parsed.session_id().to_be_bytes(),
        )
        .expect("static Hysteria2 identity domain and session id are nonempty");
        let response = |payload| {
            UdpExchangeResult::new(payload, "quic-udp-datagram")
                .with_quic_underlay("quinn-h3")
                .with_session_executor("tokio-quic-datagram-session")
                .with_underlay_reuse("quic-endpoint-and-connection-reused")
        };
        if parsed.session_id() != self.session_id {
            return Ok(Some(
                response(parsed.into_payload())
                    .with_rejected_response_identity(UdpResponseDropReason::CrossSessionIdentity),
            ));
        }
        let source = match parsed.target().parse::<SocketAddr>() {
            Ok(source) => source,
            Err(_) => {
                return Ok(Some(
                    response(parsed.into_payload())
                        .with_rejected_response_identity(UdpResponseDropReason::MalformedIdentity),
                ));
            }
        };
        if self.fixed_target.source() != Some(source) {
            return Ok(Some(
                response(parsed.into_payload())
                    .with_rejected_response_identity(UdpResponseDropReason::UnexpectedWireSource),
            ));
        }
        let outcome = self.fragments.push(
            parsed.packet_id(),
            parsed.fragment_id(),
            parsed.fragment_count(),
            parsed.into_payload(),
            "Hysteria2",
        )?;
        match outcome {
            QuicUdpFragmentOutcome::Pending => Ok(None),
            QuicUdpFragmentOutcome::Complete(payload) => Ok(Some(
                response(payload)
                    .with_session_bound_response_identity(source, Some(observed_identity)),
            )),
            QuicUdpFragmentOutcome::Late(payload) => Ok(Some(
                response(payload)
                    .with_rejected_response_identity(UdpResponseDropReason::LateResponse),
            )),
        }
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("quic-udp-datagram")
            .with_quic_underlay("quinn-h3")
            .with_session_executor("tokio-quic-datagram-session")
            .with_underlay_reuse("quic-endpoint-and-connection-reused")
    }

    async fn ensure_open(&mut self) -> Result<(), String> {
        if self.udp_session.is_some() {
            return Ok(());
        }
        let owner_registry = self.owner_registry.as_ref().ok_or_else(|| {
            "Hysteria2 transport owner registry is unavailable for UDP session".to_owned()
        })?;
        let proxy = self
            .proxy
            .as_ref()
            .ok_or_else(|| "Hysteria2 proxy owner identity is unavailable".to_owned())?;
        let deadline = self.owner_deadline.take().unwrap_or_else(|| {
            dae_runtime_control::AbsoluteDeadline::from_now(
                Instant::now(),
                RESIDENT_UDP_RESPONSE_TIMEOUT,
            )
        });
        let transport = owner_registry
            .acquire(
                Arc::clone(proxy),
                QuicEndpointCallerClass::UdpData,
                deadline,
            )
            .await?;
        let udp_session = transport.open_udp_session()?;
        self.session_id = udp_session.session_id();
        self.udp_session = Some(udp_session);
        Ok(())
    }

    pub(super) async fn shutdown(&mut self) {
        self.udp_session = None;
        self.session_id = 0;
        self.fragments.clear();
        self.packet_ids.clear();
        self.fixed_target.clear();
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct TuicQuicDatagramSession {
    proxy: Option<Arc<ResidentProxyPlan>>,
    owner_registry: Option<TuicOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    udp_association: Option<TuicUdpAssociationLease>,
    assoc_id: u16,
    fragments: QuicUdpFragmentBuffer,
    fragment_sources: std::collections::BTreeMap<u16, SocketAddr>,
    packet_ids: QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
    fixed_target: UdpSessionFixedTarget,
}

impl TuicQuicDatagramSession {
    pub(super) fn new(
        proxy: Arc<ResidentProxyPlan>,
        owner_registry: Option<TuicOwnerRegistryHandle>,
    ) -> Self {
        let resources = QuicUdpDatagramResourceProfile::selected();
        Self {
            proxy: Some(proxy),
            owner_registry,
            owner_deadline: None,
            udp_association: None,
            assoc_id: 0,
            fragments: QuicUdpFragmentBuffer::new(resources, u16::MAX as usize),
            fragment_sources: std::collections::BTreeMap::new(),
            packet_ids: QuicUdpPacketIdAllocator::new(resources),
            resources,
            fixed_target: UdpSessionFixedTarget::default(),
        }
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        let resources = QuicUdpDatagramResourceProfile::selected();
        Self {
            proxy: None,
            owner_registry: None,
            owner_deadline: None,
            udp_association: None,
            assoc_id: 0,
            fragments: QuicUdpFragmentBuffer::new(resources, u16::MAX as usize),
            fragment_sources: std::collections::BTreeMap::new(),
            packet_ids: QuicUdpPacketIdAllocator::new(resources),
            resources,
            fixed_target: UdpSessionFixedTarget::default(),
        }
    }

    pub(super) fn set_owner_deadline(&mut self, deadline: dae_runtime_control::AbsoluteDeadline) {
        if self.udp_association.is_none() {
            self.owner_deadline = Some(deadline);
        }
    }

    pub(super) async fn exchange(
        &mut self,
        _proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.fixed_target
            .bind(original_dst, "TUIC UDP association")?;
        self.ensure_open().await?;
        let connection = self
            .udp_association
            .as_ref()
            .ok_or_else(|| "TUIC UDP association is not initialized".to_owned())?
            .connection();
        let packet_id = self.packet_ids.allocate()?;
        let request =
            TuicUdpPacket::new(self.assoc_id, packet_id, original_dst.to_string(), payload)
                .map_err(|err| format!("build TUIC UDP packet: {err}"))?;
        send_tuic_udp_packet(connection, &request, &mut self.packet_ids, self.resources)?;
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.fragments.expire();
        self.prune_fragment_sources();
        self.packet_ids.expire();
        let response = {
            let association = match self.udp_association.as_mut() {
                Some(association) => association,
                None => return Ok(None),
            };
            association.try_receive()?
        };
        let Some(response) = response else {
            return Ok(None);
        };
        self.decode_response(response)
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if self.udp_association.is_none() {
            return Err("TUIC UDP association is not initialized".to_owned());
        }
        let expiration = earliest_expiration(
            self.fragments.next_expiration(),
            self.packet_ids.next_expiration(),
        );
        let Some(response) = self
            .udp_association
            .as_mut()
            .expect("TUIC UDP association was checked above")
            .receive_until(expiration)
            .await?
        else {
            self.fragments.expire();
            self.prune_fragment_sources();
            self.packet_ids.expire();
            return Ok(None);
        };
        self.decode_response(response)
    }

    fn decode_response(
        &mut self,
        parsed: TuicUdpPacket,
    ) -> Result<Option<UdpExchangeResult>, String> {
        let observed_identity = UdpResponseIdentityToken::from_protocol_identity(
            TUIC_ASSOCIATION_IDENTITY_DOMAIN,
            &parsed.association_id().to_be_bytes(),
        )
        .expect("static TUIC identity domain and association id are nonempty");
        let base_response = |payload| {
            UdpExchangeResult::new(payload, "quic-udp-datagram")
                .with_quic_underlay("quinn")
                .with_session_executor("tokio-quic-datagram-session")
                .with_underlay_reuse("quic-endpoint-and-connection-reused")
        };
        if parsed.association_id() != self.assoc_id {
            return Ok(Some(
                base_response(parsed.into_payload())
                    .with_rejected_response_identity(UdpResponseDropReason::CrossSessionIdentity),
            ));
        }
        let source = match parsed.target() {
            Some(target) => match target.parse::<SocketAddr>() {
                Ok(source) => Some(source),
                Err(_) => {
                    return Ok(Some(
                        base_response(parsed.into_payload()).with_rejected_response_identity(
                            UdpResponseDropReason::MalformedIdentity,
                        ),
                    ));
                }
            },
            None => None,
        };
        if source.is_some_and(|source| self.fixed_target.source() != Some(source)) {
            return Ok(Some(
                base_response(parsed.into_payload())
                    .with_rejected_response_identity(UdpResponseDropReason::UnexpectedWireSource),
            ));
        }
        let packet_id = parsed.packet_id();
        let fragment_count = parsed.fragment_count();
        if fragment_count > 1
            && let Some(source) = source
        {
            self.fragment_sources.insert(packet_id, source);
        }
        let outcome = self.fragments.push(
            packet_id,
            parsed.fragment_id(),
            fragment_count,
            parsed.into_payload(),
            "TUIC",
        );
        if outcome.is_err() {
            self.prune_fragment_sources();
        }
        let outcome = outcome?;
        match outcome {
            QuicUdpFragmentOutcome::Pending => Ok(None),
            QuicUdpFragmentOutcome::Complete(payload) => {
                let source = if fragment_count == 1 {
                    source
                } else {
                    self.fragment_sources.remove(&packet_id)
                };
                let Some(source) = source else {
                    return Ok(Some(
                        base_response(payload).with_rejected_response_identity(
                            UdpResponseDropReason::MalformedIdentity,
                        ),
                    ));
                };
                Ok(Some(
                    base_response(payload)
                        .with_session_bound_response_identity(source, Some(observed_identity)),
                ))
            }
            QuicUdpFragmentOutcome::Late(payload) => {
                self.prune_fragment_sources();
                Ok(Some(
                    base_response(payload)
                        .with_rejected_response_identity(UdpResponseDropReason::LateResponse),
                ))
            }
        }
    }

    fn prune_fragment_sources(&mut self) {
        self.fragment_sources
            .retain(|packet_id, _| self.fragments.contains_pending(*packet_id));
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("quic-udp-datagram")
            .with_quic_underlay("quinn")
            .with_session_executor("tokio-quic-datagram-session")
            .with_underlay_reuse("quic-endpoint-and-connection-reused")
    }

    async fn ensure_open(&mut self) -> Result<(), String> {
        if self.udp_association.is_some() {
            return Ok(());
        }
        let owner_registry = self.owner_registry.as_ref().ok_or_else(|| {
            "TUIC transport owner registry is unavailable for UDP association".to_owned()
        })?;
        let proxy = self
            .proxy
            .as_ref()
            .ok_or_else(|| "TUIC proxy owner identity is unavailable".to_owned())?;
        let deadline = self.owner_deadline.take().unwrap_or_else(|| {
            dae_runtime_control::AbsoluteDeadline::from_now(
                Instant::now(),
                RESIDENT_UDP_RESPONSE_TIMEOUT,
            )
        });
        let transport = owner_registry
            .acquire(
                Arc::clone(proxy),
                QuicEndpointCallerClass::UdpData,
                deadline,
            )
            .await?;
        let udp_association = transport.open_udp_association()?;
        self.assoc_id = udp_association.association_id();
        self.udp_association = Some(udp_association);
        Ok(())
    }

    pub(super) async fn shutdown(&mut self) {
        self.udp_association = None;
        self.assoc_id = 0;
        self.fragments.clear();
        self.fragment_sources.clear();
        self.packet_ids.clear();
        self.fixed_target.clear();
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
        Ok(juicity_udp_response_result(parsed.target, parsed.payload))
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

fn juicity_udp_response_result(target: String, payload: Vec<u8>) -> UdpExchangeResult {
    let result = UdpExchangeResult::new(payload, "quic-udp-stream-packet")
        .with_quic_underlay("quinn-h3")
        .with_session_executor("tokio-quic-stream-packet-session")
        .with_underlay_reuse("quic-endpoint-connection-and-auth-stream-reused");
    match target.parse::<SocketAddr>() {
        Ok(source) => result.with_decoded_response_identity(Some(source), None),
        Err(_) => result.with_rejected_response_identity(UdpResponseDropReason::MalformedIdentity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_datagram_pending_results_do_not_forward_empty_reply() {
        let hysteria2 = Hysteria2QuicDatagramSession::new_for_test().pending_response_result();
        assert!(!hysteria2.reply_forwarded);
        assert!(hysteria2.payload_for_test().is_empty());
        assert_eq!(hysteria2.execution_label, "quic-udp-datagram");
        assert_eq!(hysteria2.quic_underlay, Some("quinn-h3"));
        assert_eq!(
            hysteria2.underlay_reuse,
            Some("quic-endpoint-and-connection-reused")
        );

        let tuic = TuicQuicDatagramSession::new_for_test().pending_response_result();
        assert!(!tuic.reply_forwarded);
        assert!(tuic.payload_for_test().is_empty());
        assert_eq!(tuic.execution_label, "quic-udp-datagram");
        assert_eq!(tuic.quic_underlay, Some("quinn"));
        assert_eq!(
            tuic.underlay_reuse,
            Some("quic-endpoint-and-connection-reused")
        );
    }

    #[test]
    fn hysteria2_rejects_cross_session_and_wrong_target_before_reassembly() {
        let target: SocketAddr = "192.0.2.10:53".parse().unwrap();
        let other: SocketAddr = "192.0.2.11:53".parse().unwrap();
        let mut session = Hysteria2QuicDatagramSession::new_for_test();
        session.session_id = 7;
        session
            .fixed_target
            .bind(target, "Hysteria2 UDP session")
            .unwrap();

        for (message, reason) in [
            (
                Hysteria2UdpMessage::new(8, target.to_string(), b"cross-session").unwrap(),
                UdpResponseDropReason::CrossSessionIdentity,
            ),
            (
                Hysteria2UdpMessage::new(7, other.to_string(), b"wrong-target").unwrap(),
                UdpResponseDropReason::UnexpectedWireSource,
            ),
        ] {
            let mut response = session.decode_response(message).unwrap().unwrap();
            let expectation = response.fixed_target_expectation(target);
            assert_eq!(
                response.take_fixed_target_payload(expectation).validation(),
                UdpFixedTargetValidation::Dropped(reason)
            );
            assert_eq!(session.fragments.snapshot().pending_packets, 0);
            assert_eq!(session.fragments.snapshot().pending_bytes, 0);
        }

        let message = Hysteria2UdpMessage::new(7, target.to_string(), b"response").unwrap();
        let mut response = session.decode_response(message).unwrap().unwrap();
        let expectation = response.fixed_target_expectation(target);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Validated
        );
    }

    #[test]
    fn hysteria2_validates_every_fragment_identity_before_buffering() {
        let target: SocketAddr = "[2001:db8::10]:5353".parse().unwrap();
        let other: SocketAddr = "[2001:db8::11]:5353".parse().unwrap();
        let mut session = Hysteria2QuicDatagramSession::new_for_test();
        session.session_id = 9;
        session
            .fixed_target
            .bind(target, "Hysteria2 UDP session")
            .unwrap();

        let wrong = Hysteria2UdpMessage::new(9, other.to_string(), vec![1; 1_500]).unwrap();
        let wrong_fragment = fragment_hysteria2_udp_message(&wrong, 1, 1_200).unwrap();
        let mut response = session
            .decode_response(wrong_fragment[0].clone())
            .unwrap()
            .unwrap();
        let expectation = response.fixed_target_expectation(target);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
        );
        assert_eq!(session.fragments.snapshot().pending_packets, 0);

        let message = Hysteria2UdpMessage::new(9, target.to_string(), vec![5; 1_500]).unwrap();
        let fragments = fragment_hysteria2_udp_message(&message, 2, 1_200).unwrap();
        assert!(
            session
                .decode_response(fragments[1].clone())
                .unwrap()
                .is_none()
        );
        let mut response = session
            .decode_response(fragments[0].clone())
            .unwrap()
            .unwrap();
        let expectation = response.fixed_target_expectation(target);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Validated
        );
        assert_eq!(session.fragments.snapshot().pending_bytes, 0);
    }

    #[test]
    fn tuic_rejects_cross_association_and_wrong_target_before_reassembly() {
        let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let mut session = TuicQuicDatagramSession::new_for_test();
        session.assoc_id = 7;
        session
            .fixed_target
            .bind(target, "TUIC UDP association")
            .unwrap();

        for (packet, reason) in [
            (
                TuicUdpPacket::new(8, 1, target.to_string(), b"cross-session").unwrap(),
                UdpResponseDropReason::CrossSessionIdentity,
            ),
            (
                TuicUdpPacket::new(7, 2, other.to_string(), b"wrong-target").unwrap(),
                UdpResponseDropReason::UnexpectedWireSource,
            ),
        ] {
            let mut response = session.decode_response(packet).unwrap().unwrap();
            let expectation = response.fixed_target_expectation(target);
            assert_eq!(
                response.take_fixed_target_payload(expectation).validation(),
                UdpFixedTargetValidation::Dropped(reason)
            );
        }

        let packet = TuicUdpPacket::new(7, 3, target.to_string(), b"response").unwrap();
        let mut response = session.decode_response(packet).unwrap().unwrap();
        let expectation = response.fixed_target_expectation(target);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Validated
        );
    }

    #[test]
    fn tuic_reassembles_out_of_order_fragments_with_first_fragment_source() {
        let target: SocketAddr = "[2001:db8::20]:5353".parse().unwrap();
        let other: SocketAddr = "[2001:db8::21]:5353".parse().unwrap();
        let mut session = TuicQuicDatagramSession::new_for_test();
        session.assoc_id = 7;
        session
            .fixed_target
            .bind(target, "TUIC UDP association")
            .unwrap();

        let wrong = TuicUdpPacket::new(7, 1, other.to_string(), vec![1; 1_500]).unwrap();
        let wrong_fragments = fragment_tuic_udp_packet(&wrong, 2, 1_000).unwrap();
        let mut rejected = session
            .decode_response(wrong_fragments[0].clone())
            .unwrap()
            .unwrap();
        let expectation = rejected.fixed_target_expectation(target);
        assert_eq!(
            rejected.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
        );
        assert_eq!(session.fragments.snapshot().pending_packets, 0);

        let payload = vec![5; 1_500];
        let packet = TuicUdpPacket::new(7, 3, target.to_string(), &payload).unwrap();
        let fragments = fragment_tuic_udp_packet(&packet, 4, 1_000).unwrap();
        assert!(
            session
                .decode_response(fragments[1].clone())
                .unwrap()
                .is_none()
        );
        assert!(session.fragment_sources.is_empty());

        let mut response = session
            .decode_response(fragments[0].clone())
            .unwrap()
            .unwrap();
        let expectation = response.fixed_target_expectation(target);
        let validated = response.take_fixed_target_payload(expectation);
        assert_eq!(validated.validation(), UdpFixedTargetValidation::Validated);
        assert_eq!(validated.into_payload().unwrap(), payload);
        assert!(session.fragment_sources.is_empty());
        assert_eq!(session.fragments.snapshot().pending_bytes, 0);
    }

    #[test]
    fn juicity_stream_packet_response_source_is_verified() {
        let expected: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let frame = seal_stream_packet_frame(&other.to_string(), b"response").unwrap();
        let parsed = decode_stream_packet_frame(&frame.encoded).unwrap();
        let mut response = juicity_udp_response_result(parsed.target, parsed.payload);
        let expectation = response.fixed_target_expectation(expected);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
        );
    }
}
