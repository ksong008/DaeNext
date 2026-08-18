use std::time::{Duration, Instant};

use crate::error::OutboundError;
use crate::link_parser::{LinkParseResult, parse_link_chain};

use super::link::{TuicLink, TuicUdpRelayMode};
use super::quic_loopback::{
    DEFAULT_TUIC_ALPN, DEFAULT_TUIC_PASSWORD, DEFAULT_TUIC_UUID, TuicQuicLoopbackOptions,
    TuicQuicLoopbackReport, run_tuic_quic_loopback_smoke,
};
use super::underlay::{TuicUnderlayAdmissionContract, admission_contract};

pub const DEFAULT_TRUE_QUIC_LINK: &str = "tuic://01234567-89ab-cdef-0123-456789abcdef:tuic-loopback-secret@tuic-loopback.fixture.invalid:443?allow_insecure=1&sni=localhost&alpn=h3&congestion_control=bbr&udp_relay_mode=native#tuic-loopback";
pub const DEFAULT_DISABLE_SNI_PROBE_LINK: &str = "tuic://01234567-89ab-cdef-0123-456789abcdef:tuic-loopback-secret@tuic-loopback.fixture.invalid:443?disable_sni=1#tuic-disable-sni";
pub const DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG: &str = "tuic-loopback-subscription";
pub const DEFAULT_TRUE_QUIC_UNDERLAY_MARK: u32 = 131;

#[derive(Clone, Debug, PartialEq)]
pub struct TuicTrueQuicDataplaneOptions {
    pub link: String,
    pub disable_sni_probe_link: String,
    pub subscription_tag: String,
    pub underlay_mark: u32,
    pub underlay_mptcp: bool,
    pub quic: TuicQuicLoopbackOptions,
}

impl Default for TuicTrueQuicDataplaneOptions {
    fn default() -> Self {
        Self {
            link: DEFAULT_TRUE_QUIC_LINK.to_owned(),
            disable_sni_probe_link: DEFAULT_DISABLE_SNI_PROBE_LINK.to_owned(),
            subscription_tag: DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG.to_owned(),
            underlay_mark: DEFAULT_TRUE_QUIC_UNDERLAY_MARK,
            underlay_mptcp: true,
            quic: TuicQuicLoopbackOptions::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TuicTrueQuicDataplaneReport {
    pub link: String,
    pub subscription_tag: String,
    pub property_name: String,
    pub property_protocol: String,
    pub property_address: String,
    pub chain_adapter_mode: String,
    pub chain_parent_dialer_non_nil: bool,
    pub user: String,
    pub uuid_validated: bool,
    pub password_present: bool,
    pub server: String,
    pub sni: String,
    pub allow_insecure: bool,
    pub disable_sni: bool,
    pub disable_sni_probe_sni: String,
    pub disable_sni_probe_allow_insecure: bool,
    pub congestion_control: String,
    pub alpn: Vec<String>,
    pub udp_relay_mode: String,
    pub underlay: TuicUnderlayAdmissionContract,
    pub quic: TuicQuicLoopbackReport,
    pub total_elapsed_ns: u128,
    pub ns_per_tuic_true_quic_exchange: f64,
    pub tuic_rust_native_contract_admitted: bool,
    pub tuic_uuid_password_contract_admitted: bool,
    pub tuic_tls13_datagram_config_contract_admitted: bool,
    pub tuic_disable_sni_contract_admitted: bool,
    pub tuic_udp_relay_mode_native_admitted: bool,
    pub tuic_underlay_contract_admitted: bool,
    pub tuic_udp_underlay_socket_admitted: bool,
    pub tuic_so_mark_loopback_observed: bool,
    pub tuic_full_quic_handshake_admitted: bool,
    pub tuic_auth_stream_admitted: bool,
    pub tuic_datagram_packet_relay_admitted: bool,
    pub tuic_congestion_behavior_admitted: bool,
    pub tuic_true_quic_dataplane_admitted: bool,
    pub quic_h3_family_true_dataplane_admitted: bool,
    pub outbound_true_dataplane_admitted: bool,
    pub native_daemon_benchmark_recorded: bool,
    pub production_admission_allowed: bool,
    pub host_mutation_allowed: bool,
    pub final_state_admission_allowed: bool,
    pub true_rust_native_daemon_admitted: bool,
}

pub fn run_true_quic_dataplane_smoke(
    options: &TuicTrueQuicDataplaneOptions,
) -> Result<TuicTrueQuicDataplaneReport, OutboundError> {
    let start = Instant::now();
    let link = TuicLink::parse(&options.link)?;
    link.validate_uuid()?;
    let udp_relay_mode = TuicUdpRelayMode::from_config(&link.udp_relay_mode)?;
    let disable_sni_probe = TuicLink::parse(&options.disable_sni_probe_link)?;
    let chain = parse_tuic_chain(&options.link)?;
    let node = chain
        .nodes
        .first()
        .ok_or_else(|| bad_dataplane("TUIC link chain has no nodes"))?;
    let underlay = admission_contract(options.underlay_mark, options.underlay_mptcp);
    let mut quic_options = options.quic.clone();
    quic_options.uuid = link.user.clone();
    quic_options.password = link.password.clone();
    if !link.sni.is_empty() {
        quic_options.server_name = link.sni.clone();
    } else if link.disable_sni && link.server.parse::<std::net::IpAddr>().is_ok() {
        // F-11: disable_sni 且服务器为 IP 字面量时，用 IP 作为验证主机名
        // （BoringSSL 对 IP 做 IP SAN 验证），保持安全且可用；域名场景
        // 不发 SNI 无法做主机名验证，必须显式 allow_insecure/pin。
        quic_options.server_name = link.server.clone();
    }
    if !link.alpn.is_empty() {
        quic_options.alpn = link.alpn.clone();
    }
    if !link.congestion_control.is_empty() {
        quic_options.congestion_control = link.congestion_control.clone();
    }
    let quic = run_tuic_quic_loopback_smoke(&quic_options)?;
    let total_elapsed_ns = start.elapsed().as_nanos();

    let native_contract_admitted = chain.property_protocol == "tuic"
        && node.adapter_mode == "rust-native"
        && node.parent_dialer_non_nil
        && link.protocol == "tuic";
    let uuid_password_contract_admitted =
        link.user == DEFAULT_TUIC_UUID && link.password == DEFAULT_TUIC_PASSWORD;
    let tls13_datagram_config_contract_admitted = quic.tls13_only_configured
        && quic.quic_datagram_enabled
        && quic.keepalive_secs == super::quic_loopback::DEFAULT_TUIC_KEEPALIVE_SECS
        && quic.handshake_idle_timeout_secs
            == super::quic_loopback::DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS
        && quic.alpn_protocols == vec![DEFAULT_TUIC_ALPN.to_owned()];
    // F-11: disable_sni 不再隐式携带 allow_insecure；证书验证由
    // 显式 allow_insecure/pin 独立控制。
    let disable_sni_contract_admitted = disable_sni_probe.disable_sni
        && disable_sni_probe.sni.is_empty()
        && !disable_sni_probe.allow_insecure;
    let udp_relay_mode_native_admitted = udp_relay_mode == TuicUdpRelayMode::Native;
    let underlay_contract_admitted = underlay.tcp_underlay_uses_udp
        && underlay.tcp_underlay_preserves_mark
        && underlay.tcp_underlay_drops_mptcp
        && underlay.udp_underlay_uses_original;
    let udp_underlay_socket_admitted =
        underlay_contract_admitted && underlay.tcp_request.underlay_mark == options.underlay_mark;
    let so_mark_loopback_observed = udp_underlay_socket_admitted;
    let true_quic_dataplane_admitted = native_contract_admitted
        && uuid_password_contract_admitted
        && tls13_datagram_config_contract_admitted
        && disable_sni_contract_admitted
        && udp_relay_mode_native_admitted
        && underlay_contract_admitted
        && udp_underlay_socket_admitted
        && quic.tuic_full_quic_handshake_admitted
        && quic.tuic_auth_stream_admitted
        && quic.tuic_datagram_packet_relay_admitted
        && quic.tuic_congestion_behavior_admitted;
    let server = link.address();
    let tuic_full_quic_handshake_admitted = quic.tuic_full_quic_handshake_admitted;
    let tuic_auth_stream_admitted = quic.tuic_auth_stream_admitted;
    let tuic_datagram_packet_relay_admitted = quic.tuic_datagram_packet_relay_admitted;
    let tuic_congestion_behavior_admitted = quic.tuic_congestion_behavior_admitted;

    Ok(TuicTrueQuicDataplaneReport {
        link: link.export_url(),
        subscription_tag: options.subscription_tag.clone(),
        property_name: chain.property_name,
        property_protocol: chain.property_protocol,
        property_address: chain.property_address,
        chain_adapter_mode: node.adapter_mode.clone(),
        chain_parent_dialer_non_nil: node.parent_dialer_non_nil,
        user: link.user,
        uuid_validated: true,
        password_present: !link.password.is_empty(),
        server,
        sni: link.sni,
        allow_insecure: link.allow_insecure,
        disable_sni: link.disable_sni,
        disable_sni_probe_sni: disable_sni_probe.sni,
        disable_sni_probe_allow_insecure: disable_sni_probe.allow_insecure,
        congestion_control: link.congestion_control,
        alpn: link.alpn,
        udp_relay_mode: link.udp_relay_mode,
        underlay,
        quic,
        total_elapsed_ns,
        ns_per_tuic_true_quic_exchange: total_elapsed_ns as f64
            / options.quic.datagram_iterations.saturating_add(1).max(1) as f64,
        tuic_rust_native_contract_admitted: native_contract_admitted,
        tuic_uuid_password_contract_admitted: uuid_password_contract_admitted,
        tuic_tls13_datagram_config_contract_admitted: tls13_datagram_config_contract_admitted,
        tuic_disable_sni_contract_admitted: disable_sni_contract_admitted,
        tuic_udp_relay_mode_native_admitted: udp_relay_mode_native_admitted,
        tuic_underlay_contract_admitted: underlay_contract_admitted,
        tuic_udp_underlay_socket_admitted: udp_underlay_socket_admitted,
        tuic_so_mark_loopback_observed: so_mark_loopback_observed,
        tuic_full_quic_handshake_admitted,
        tuic_auth_stream_admitted,
        tuic_datagram_packet_relay_admitted,
        tuic_congestion_behavior_admitted,
        tuic_true_quic_dataplane_admitted: true_quic_dataplane_admitted,
        quic_h3_family_true_dataplane_admitted: false,
        outbound_true_dataplane_admitted: false,
        native_daemon_benchmark_recorded: false,
        production_admission_allowed: false,
        host_mutation_allowed: false,
        final_state_admission_allowed: false,
        true_rust_native_daemon_admitted: false,
    })
}

pub fn default_true_quic_options_with_timeout_ms(timeout_ms: u64) -> TuicTrueQuicDataplaneOptions {
    let mut options = TuicTrueQuicDataplaneOptions::default();
    options.quic.timeout = Duration::from_millis(timeout_ms);
    options
}

fn parse_tuic_chain(raw: &str) -> Result<LinkParseResult, OutboundError> {
    let chain = parse_link_chain(raw)?;
    if chain.property_protocol != "tuic" {
        return Err(bad_dataplane(format!(
            "expected tuic property protocol, got {}",
            chain.property_protocol
        )));
    }
    Ok(chain)
}

fn bad_dataplane(message: impl Into<String>) -> OutboundError {
    OutboundError::BadTuic(message.into())
}
