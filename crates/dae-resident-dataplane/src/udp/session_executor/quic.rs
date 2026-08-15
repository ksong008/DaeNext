use super::*;

use crate::QuicUdpDatagramResourceProfile;

mod fragment_buffer;
mod hysteria2_datagram;
mod packet_id;
mod tuic_datagram;
mod tuic_stream;
use self::fragment_buffer::{QuicUdpFragmentBuffer, QuicUdpFragmentOutcome};
use self::hysteria2_datagram::send_hysteria2_udp_payload;
use self::packet_id::QuicUdpPacketIdAllocator;
use self::tuic_datagram::send_tuic_udp_payload;
use self::tuic_stream::send_tuic_udp_stream_payload;

const TUIC_ASSOCIATION_IDENTITY_DOMAIN: &[u8] = b"tuic-v5-association";
const HYSTERIA2_SESSION_IDENTITY_DOMAIN: &[u8] = b"hysteria2-udp-session";

fn earliest_expiration(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(expiration), None) | (None, Some(expiration)) => Some(expiration),
        (None, None) => None,
    }
}

pub(in crate::udp) struct Hysteria2QuicDatagramSession {
    binding: Option<ResidentProxyBinding>,
    owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    udp_session: Option<Hysteria2UdpSessionLease>,
    session_id: u32,
    fragments: QuicUdpFragmentBuffer,
    packet_ids: QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
    fixed_target: UdpSessionFixedTarget,
    wire_target: String,
}

impl Hysteria2QuicDatagramSession {
    pub(super) fn new(
        binding: ResidentProxyBinding,
        owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    ) -> Self {
        let resources = QuicUdpDatagramResourceProfile::selected();
        Self {
            binding: Some(binding),
            owner_registry,
            owner_deadline: None,
            udp_session: None,
            session_id: 0,
            fragments: QuicUdpFragmentBuffer::new(resources, HYSTERIA2_MAX_UDP_PAYLOAD_LENGTH),
            packet_ids: QuicUdpPacketIdAllocator::new(resources),
            resources,
            fixed_target: UdpSessionFixedTarget::default(),
            wire_target: String::new(),
        }
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        let resources = QuicUdpDatagramResourceProfile::selected();
        Self {
            binding: None,
            owner_registry: None,
            owner_deadline: None,
            udp_session: None,
            session_id: 0,
            fragments: QuicUdpFragmentBuffer::new(resources, HYSTERIA2_MAX_UDP_PAYLOAD_LENGTH),
            packet_ids: QuicUdpPacketIdAllocator::new(resources),
            resources,
            fixed_target: UdpSessionFixedTarget::default(),
            wire_target: String::new(),
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
        if self.wire_target.is_empty() {
            self.wire_target = original_dst.to_string();
        }
        self.ensure_open().await?;
        let connection = self
            .udp_session
            .as_ref()
            .ok_or_else(|| "Hysteria2 UDP session lease is not initialized".to_owned())?
            .connection()
            .clone();
        send_hysteria2_udp_payload(
            &connection,
            self.session_id,
            &self.wire_target,
            payload,
            &mut self.packet_ids,
            self.resources,
        )?;
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
        let reassembly_limit = hysteria2_udp_payload_capacity(parsed.target())
            .map_err(|err| format!("derive Hysteria2 UDP reassembly limit: {err}"))?;
        let outcome = self.fragments.push_with_reassembly_limit(
            parsed.packet_id(),
            parsed.fragment_id(),
            parsed.fragment_count(),
            parsed.into_payload(),
            reassembly_limit,
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
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| "Hysteria2 proxy owner identity is unavailable".to_owned())?;
        let deadline = self.owner_deadline.take().unwrap_or_else(|| {
            dae_runtime_control::AbsoluteDeadline::from_now(
                Instant::now(),
                RESIDENT_UDP_RESPONSE_TIMEOUT,
            )
        });
        let transport = owner_registry
            .acquire(binding.clone(), QuicEndpointCallerClass::UdpData, deadline)
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
        self.wire_target.clear();
    }
}

pub(in crate::udp) struct TuicQuicPacketSession {
    binding: Option<ResidentProxyBinding>,
    owner_registry: Option<TuicOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    udp_association: Option<TuicUdpAssociationLease>,
    assoc_id: u16,
    fragments: QuicUdpFragmentBuffer,
    fragment_sources: std::collections::BTreeMap<u16, SocketAddr>,
    packet_ids: QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
    fixed_target: UdpSessionFixedTarget,
    udp_relay_mode: TuicUdpRelayMode,
    wire_target: String,
}

impl TuicQuicPacketSession {
    pub(super) fn new(
        binding: ResidentProxyBinding,
        owner_registry: Option<TuicOwnerRegistryHandle>,
        udp_relay_mode: TuicUdpRelayMode,
    ) -> Self {
        let resources = QuicUdpDatagramResourceProfile::selected();
        Self {
            binding: Some(binding),
            owner_registry,
            owner_deadline: None,
            udp_association: None,
            assoc_id: 0,
            fragments: QuicUdpFragmentBuffer::new(resources, u16::MAX as usize),
            fragment_sources: std::collections::BTreeMap::new(),
            packet_ids: QuicUdpPacketIdAllocator::new(resources),
            resources,
            fixed_target: UdpSessionFixedTarget::default(),
            udp_relay_mode,
            wire_target: String::new(),
        }
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        let resources = QuicUdpDatagramResourceProfile::selected();
        Self {
            binding: None,
            owner_registry: None,
            owner_deadline: None,
            udp_association: None,
            assoc_id: 0,
            fragments: QuicUdpFragmentBuffer::new(resources, u16::MAX as usize),
            fragment_sources: std::collections::BTreeMap::new(),
            packet_ids: QuicUdpPacketIdAllocator::new(resources),
            resources,
            fixed_target: UdpSessionFixedTarget::default(),
            udp_relay_mode: TuicUdpRelayMode::Native,
            wire_target: String::new(),
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
        if self.wire_target.is_empty() {
            self.wire_target = original_dst.to_string();
        }
        let deadline = self.owner_deadline.take().unwrap_or_else(|| {
            dae_runtime_control::AbsoluteDeadline::from_now(
                Instant::now(),
                RESIDENT_UDP_RESPONSE_TIMEOUT,
            )
        });
        self.ensure_open(deadline).await?;
        let connection = self
            .udp_association
            .as_ref()
            .ok_or_else(|| "TUIC UDP association is not initialized".to_owned())?
            .connection();
        let packet_id = self.packet_ids.allocate()?;
        match self.udp_relay_mode {
            TuicUdpRelayMode::Native => {
                send_tuic_udp_payload(
                    connection,
                    self.assoc_id,
                    packet_id,
                    &self.wire_target,
                    payload,
                    &mut self.packet_ids,
                    self.resources,
                )?;
            }
            TuicUdpRelayMode::Quic => {
                send_tuic_udp_stream_payload(
                    connection,
                    self.assoc_id,
                    packet_id,
                    &self.wire_target,
                    payload,
                    deadline,
                )
                .await?;
            }
        }
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
        let execution_label = self.execution_label();
        let session_executor = self.session_executor_label();
        let base_response = |payload| {
            UdpExchangeResult::new(payload, execution_label)
                .with_quic_underlay("quinn")
                .with_session_executor(session_executor)
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
        UdpExchangeResult::pending_response(self.execution_label())
            .with_quic_underlay("quinn")
            .with_session_executor(self.session_executor_label())
            .with_underlay_reuse("quic-endpoint-and-connection-reused")
    }

    fn execution_label(&self) -> &'static str {
        match self.udp_relay_mode {
            TuicUdpRelayMode::Native => "quic-udp-datagram",
            TuicUdpRelayMode::Quic => "quic-udp-unidirectional-stream-packet",
        }
    }

    fn session_executor_label(&self) -> &'static str {
        match self.udp_relay_mode {
            TuicUdpRelayMode::Native => "tokio-quic-datagram-session",
            TuicUdpRelayMode::Quic => "tokio-quic-unidirectional-stream-packet-session",
        }
    }

    async fn ensure_open(
        &mut self,
        deadline: dae_runtime_control::AbsoluteDeadline,
    ) -> Result<(), String> {
        if self.udp_association.is_some() {
            return Ok(());
        }
        let owner_registry = self.owner_registry.as_ref().ok_or_else(|| {
            "TUIC transport owner registry is unavailable for UDP association".to_owned()
        })?;
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| "TUIC proxy owner identity is unavailable".to_owned())?;
        let transport = owner_registry
            .acquire(binding.clone(), QuicEndpointCallerClass::UdpData, deadline)
            .await?;
        let udp_association = transport.open_udp_association()?;
        if udp_association.udp_relay_mode() != self.udp_relay_mode {
            return Err(
                "TUIC UDP association relay mode does not match the session plan".to_owned(),
            );
        }
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
        self.wire_target.clear();
    }
}

pub(in crate::udp) struct JuicityQuicStreamPacketSession {
    binding: ResidentProxyBinding,
    owner_registry: Option<JuicityOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    transport: Option<JuicityTransportLease>,
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
    response_buffer: Vec<u8>,
    first_packet: bool,
    fixed_target: UdpSessionFixedTarget,
    wire_target: String,
}

impl JuicityQuicStreamPacketSession {
    pub(super) fn new(
        binding: ResidentProxyBinding,
        owner_registry: Option<JuicityOwnerRegistryHandle>,
    ) -> Self {
        Self {
            binding,
            owner_registry,
            owner_deadline: None,
            transport: None,
            send: None,
            recv: None,
            response_buffer: Vec::new(),
            first_packet: true,
            fixed_target: UdpSessionFixedTarget::default(),
            wire_target: String::new(),
        }
    }

    pub(super) fn set_owner_deadline(&mut self, deadline: dae_runtime_control::AbsoluteDeadline) {
        if self.transport.is_none() {
            self.owner_deadline = Some(deadline);
        }
    }

    pub(super) async fn exchange(
        &mut self,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if binding.plan().graph_link_hash != self.binding.plan().graph_link_hash {
            return Err("Juicity UDP session proxy identity changed".to_owned());
        }
        self.fixed_target
            .bind(original_dst, "Juicity UDP stream session")?;
        if self.wire_target.is_empty() {
            self.wire_target = original_dst.to_string();
        }
        let deadline = self.owner_deadline.take().unwrap_or_else(|| {
            dae_runtime_control::AbsoluteDeadline::from_now(
                Instant::now(),
                RESIDENT_UDP_RESPONSE_TIMEOUT,
            )
        });
        self.ensure_open(deadline).await?;
        let request_frame = seal_stream_packet_frame(&self.wire_target, payload)
            .map_err(|err| format!("build Juicity UDP stream packet: {err}"))?;
        let request = if self.first_packet {
            build_juicity_stream_packet_request(&self.wire_target, &request_frame.encoded)?
        } else {
            request_frame.encoded
        };
        let remaining = deadline
            .remaining_at(Instant::now())
            .ok_or_else(|| "write Juicity UDP stream packet deadline elapsed".to_owned())?;
        let send = self
            .send
            .as_mut()
            .ok_or_else(|| "Juicity UDP stream writer is not initialized".to_owned())?;
        match time::timeout(remaining, send.write_all(&request)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                self.reset_stream();
                return Err(format!("write Juicity UDP stream packet: {err}"));
            }
            Err(_) => {
                self.reset_stream();
                return Err("write Juicity UDP stream packet deadline elapsed".to_owned());
            }
        }
        self.first_packet = false;
        Ok(self.pending_response_result())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::ReadyOnly).await
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if self.recv.is_none() {
            return Err("Juicity UDP stream reader is not initialized".to_owned());
        }
        self.read_response(UdpStreamReadMode::Wait).await
    }

    async fn read_response(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<UdpExchangeResult>, String> {
        let response = {
            let Some(recv) = self.recv.as_mut() else {
                return Ok(None);
            };
            read_juicity_stream_packet_response(recv, &mut self.response_buffer, mode).await
        };
        match response {
            Ok(Some(response)) => Ok(Some(juicity_udp_response_result(
                response.target,
                response.payload,
            ))),
            Ok(None) => Ok(None),
            Err(err) => {
                self.reset_stream();
                Err(err)
            }
        }
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("quic-udp-stream-packet")
            .with_quic_underlay("quinn-h3")
            .with_session_executor("tokio-quic-stream-packet-session")
            .with_underlay_reuse("quic-endpoint-connection-and-auth-stream-reused")
    }

    async fn ensure_open(
        &mut self,
        deadline: dae_runtime_control::AbsoluteDeadline,
    ) -> Result<(), String> {
        if self.transport.is_some() && self.send.is_some() && self.recv.is_some() {
            return Ok(());
        }
        let registry = self.owner_registry.as_ref().ok_or_else(|| {
            "Juicity transport owner registry is unavailable for UDP session".to_owned()
        })?;
        let transport = registry
            .acquire(
                self.binding.clone(),
                QuicEndpointCallerClass::UdpData,
                deadline,
            )
            .await?;
        let (send, recv) = transport.open_stream(deadline).await?;
        self.transport = Some(transport);
        self.send = Some(send);
        self.recv = Some(recv);
        self.first_packet = true;
        Ok(())
    }

    fn reset_stream(&mut self) {
        self.send.take();
        self.recv.take();
        self.transport.take();
        self.response_buffer.clear();
        self.first_packet = true;
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(mut send) = self.send.take() {
            let _ = send.finish();
        }
        self.recv.take();
        self.transport.take();
        self.response_buffer.clear();
        self.first_packet = true;
        self.fixed_target.clear();
        self.wire_target.clear();
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
pub(crate) async fn exercise_juicity_udp_stream_session(
    binding: ResidentProxyBinding,
    registry: JuicityOwnerRegistryHandle,
    target: SocketAddr,
    payloads: &[&[u8]],
) -> Result<(u64, Vec<Vec<u8>>), String> {
    let exchange_binding = binding.clone();
    let mut session = JuicityQuicStreamPacketSession::new(binding, Some(registry));
    let mut responses = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let response = session.exchange(&exchange_binding, target, payload).await?;
        if response.reply_forwarded {
            return Err(
                "Juicity stream write unexpectedly produced a synchronous reply".to_owned(),
            );
        }
    }
    for _ in payloads {
        let mut response = session
            .wait_response()
            .await?
            .ok_or_else(|| "Juicity stream response reader returned no frame".to_owned())?;
        let expectation = response.fixed_target_expectation(target);
        let payload = response
            .take_fixed_target_payload(expectation)
            .into_payload()
            .map_err(|validation| {
                format!("Juicity test response validation failed: {validation:?}")
            })?;
        responses.push(payload);
    }
    let owner_id = session
        .transport
        .as_ref()
        .map(JuicityTransportLease::physical_owner_id)
        .ok_or_else(|| "Juicity test session did not retain its transport lease".to_owned())?;
    session.shutdown().await;
    Ok((owner_id, responses))
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

        let tuic = TuicQuicPacketSession::new_for_test().pending_response_result();
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
    fn hysteria2_reassembles_the_largest_valid_wire_message() {
        let target: SocketAddr = "127.0.0.1:39452".parse().unwrap();
        let target_text = target.to_string();
        let payload_capacity = hysteria2_udp_payload_capacity(&target_text).unwrap();
        assert_eq!(payload_capacity, 4_072);
        let payload = vec![0x5a; payload_capacity];
        let message = Hysteria2UdpMessage::new(11, &target_text, &payload).unwrap();
        let fragments = fragment_hysteria2_udp_message(&message, 19, 1_200).unwrap();
        assert!(fragments.len() > 1);
        assert!(
            fragments
                .iter()
                .all(|fragment| { encode_hysteria2_udp_message(fragment).unwrap().len() <= 1_200 })
        );

        let mut session = Hysteria2QuicDatagramSession::new_for_test();
        session.session_id = 11;
        session
            .fixed_target
            .bind(target, "Hysteria2 UDP session")
            .unwrap();
        for fragment in &fragments[..fragments.len() - 1] {
            assert!(session.decode_response(fragment.clone()).unwrap().is_none());
        }
        let mut response = session
            .decode_response(fragments.last().unwrap().clone())
            .unwrap()
            .unwrap();
        let expectation = response.fixed_target_expectation(target);
        let validated = response.take_fixed_target_payload(expectation);
        assert_eq!(validated.validation(), UdpFixedTargetValidation::Validated);
        assert_eq!(validated.into_payload().unwrap(), payload);
        let snapshot = session.fragments.snapshot();
        assert_eq!(snapshot.pending_packets, 0);
        assert_eq!(snapshot.pending_bytes, 0);
        assert_eq!(snapshot.quarantined_packets, 1);
    }

    #[test]
    fn hysteria2_packet_limit_cannot_expand_across_equivalent_target_text() {
        let short_target = "[2001:db8::1]:5353";
        let long_target = "[2001:0db8:0000:0000:0000:0000:0000:0001]:5353";
        let target: SocketAddr = short_target.parse().unwrap();
        assert_eq!(long_target.parse::<SocketAddr>().unwrap(), target);
        let short_capacity = hysteria2_udp_payload_capacity(short_target).unwrap();
        let long_capacity = hysteria2_udp_payload_capacity(long_target).unwrap();
        assert!(short_capacity > long_capacity);

        let fragment_payload = long_capacity / 3 + 1;
        let max_wire_size = HYSTERIA2_MAX_UDP_MESSAGE_LENGTH - short_capacity + fragment_payload;
        let short = Hysteria2UdpMessage::new(13, short_target, vec![1; short_capacity]).unwrap();
        let long = Hysteria2UdpMessage::new(13, long_target, vec![2; long_capacity]).unwrap();
        let short_fragments = fragment_hysteria2_udp_message(&short, 23, max_wire_size).unwrap();
        let long_fragments = fragment_hysteria2_udp_message(&long, 23, max_wire_size).unwrap();
        assert_eq!(short_fragments.len(), 4);
        assert_eq!(long_fragments.len(), 4);
        assert!(
            short_fragments[..3]
                .iter()
                .map(|fragment| fragment.payload().len())
                .sum::<usize>()
                > long_capacity
        );

        let mut session = Hysteria2QuicDatagramSession::new_for_test();
        session.session_id = 13;
        session
            .fixed_target
            .bind(target, "Hysteria2 UDP session")
            .unwrap();
        for fragment in &short_fragments[..3] {
            assert!(session.decode_response(fragment.clone()).unwrap().is_none());
        }
        let error = session
            .decode_response(long_fragments[3].clone())
            .unwrap_err();
        assert!(error.contains("decreased below buffered payload"));
        let snapshot = session.fragments.snapshot();
        assert_eq!(snapshot.pending_packets, 0);
        assert_eq!(snapshot.pending_bytes, 0);
        assert_eq!(snapshot.quarantined_packets, 1);
        assert_eq!(snapshot.rejected_fragments, 1);
    }

    #[test]
    fn tuic_rejects_cross_association_and_wrong_target_before_reassembly() {
        let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let mut session = TuicQuicPacketSession::new_for_test();
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
        let mut session = TuicQuicPacketSession::new_for_test();
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
