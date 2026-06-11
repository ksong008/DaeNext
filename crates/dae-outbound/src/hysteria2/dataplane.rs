use std::time::{Duration, Instant};

use crate::error::OutboundError;
use crate::link_parser::{LinkParseResult, parse_link_chain};

use super::link::Hysteria2Link;
use super::port_hopping::{Hysteria2PortHopSchedule, build_port_hop_schedule};
use super::quic_loopback::{
    Hysteria2QuicLoopbackOptions, Hysteria2QuicLoopbackReport, run_hysteria2_quic_loopback_smoke,
};
use super::underlay::{Hysteria2UnderlayContract, underlay_contract};

pub const DEFAULT_TRUE_QUIC_LINK: &str = "hysteria2://hysteria2-auth:hysteria2-pass@hysteria2-loopback.fixture.invalid:443,8443-8444?insecure=1&sni=localhost&maxTx=1048576&maxRx=2097152#hysteria2-loopback";
pub const DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG: &str = "hysteria2-loopback-subscription";
pub const DEFAULT_TRUE_QUIC_UNDERLAY_MARK: u32 = 130;
pub const DEFAULT_TRUE_QUIC_UDP_HOP_INTERVAL_MS: u64 = 30_000;
pub const DEFAULT_TRUE_QUIC_PORT_HOP_ITERATIONS: usize = 4;

#[derive(Clone, Debug, PartialEq)]
pub struct Hysteria2TrueQuicDataplaneOptions {
    pub link: String,
    pub subscription_tag: String,
    pub underlay_mark: u32,
    pub underlay_mptcp: bool,
    pub udp_hop_interval_ms: u64,
    pub port_hop_iterations: usize,
    pub quic: Hysteria2QuicLoopbackOptions,
}

impl Default for Hysteria2TrueQuicDataplaneOptions {
    fn default() -> Self {
        Self {
            link: DEFAULT_TRUE_QUIC_LINK.to_owned(),
            subscription_tag: DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG.to_owned(),
            underlay_mark: DEFAULT_TRUE_QUIC_UNDERLAY_MARK,
            underlay_mptcp: true,
            udp_hop_interval_ms: DEFAULT_TRUE_QUIC_UDP_HOP_INTERVAL_MS,
            port_hop_iterations: DEFAULT_TRUE_QUIC_PORT_HOP_ITERATIONS,
            quic: Hysteria2QuicLoopbackOptions::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hysteria2TrueQuicDataplaneReport {
    pub link: String,
    pub subscription_tag: String,
    pub property_name: String,
    pub property_protocol: String,
    pub property_address: String,
    pub chain_adapter_mode: String,
    pub chain_parent_dialer_non_nil: bool,
    pub user: String,
    pub password_present: bool,
    pub server: String,
    pub sni: String,
    pub insecure: bool,
    pub max_tx: u64,
    pub max_rx: u64,
    pub underlay: Hysteria2UnderlayContract,
    pub port_hopping: Hysteria2PortHopSchedule,
    pub quic: Hysteria2QuicLoopbackReport,
    pub total_elapsed_ns: u128,
    pub ns_per_hysteria2_true_quic_exchange: f64,
    pub hysteria2_rust_native_contract_admitted: bool,
    pub hysteria2_udp_underlay_admitted: bool,
    pub hysteria2_full_quic_handshake_admitted: bool,
    pub hysteria2_stream_mux_admitted: bool,
    pub hysteria2_packet_datagram_admitted: bool,
    pub hysteria2_port_hopping_scheduler_admitted: bool,
    pub hysteria2_tcp_target_over_quic_admitted: bool,
    pub hysteria2_udp_target_over_quic_admitted: bool,
    pub hysteria2_true_quic_dataplane_admitted: bool,
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
    options: &Hysteria2TrueQuicDataplaneOptions,
) -> Result<Hysteria2TrueQuicDataplaneReport, OutboundError> {
    let start = Instant::now();
    if options.udp_hop_interval_ms == 0 {
        return Err(bad_dataplane(
            "Hysteria2 UDP hop interval must be greater than zero",
        ));
    }
    let link = Hysteria2Link::parse(&options.link)?;
    let chain = parse_hysteria2_chain(&options.link)?;
    let node = chain
        .nodes
        .first()
        .ok_or_else(|| bad_dataplane("Hysteria2 link chain has no nodes"))?;
    let underlay = underlay_contract(
        "tcp",
        &link.server,
        options.underlay_mark,
        options.underlay_mptcp,
        options.udp_hop_interval_ms,
    );
    let port_hopping = build_port_hop_schedule(
        &link.server,
        options.udp_hop_interval_ms,
        options.port_hop_iterations,
    )?;
    let mut quic_options = options.quic.clone();
    if !link.sni.is_empty() {
        quic_options.server_name = link.sni.clone();
    }
    let quic = run_hysteria2_quic_loopback_smoke(&quic_options)?;
    let total_elapsed_ns = start.elapsed().as_nanos();

    let native_contract_admitted = chain.property_protocol == "hysteria2"
        && node.adapter_mode == "rust-native"
        && node.parent_dialer_non_nil
        && link.max_tx > 0
        && link.max_rx > 0;
    let udp_underlay_admitted = underlay.underlay_network == "udp"
        && underlay.underlay_mark == options.underlay_mark
        && underlay.route_cache_key_network == "udp"
        && underlay.server.port_hopping
        && !underlay.udp_mptcp_effective;
    let full_quic_handshake_admitted = quic.hysteria2_full_quic_handshake_admitted
        && quic.raw_cert_pin_matched
        && quic.certificate_callback_observed
        && quic.quic_datagram_enabled;
    let stream_mux_admitted = quic.hysteria2_stream_mux_admitted;
    let packet_datagram_admitted = quic.hysteria2_packet_datagram_admitted;
    let port_hopping_scheduler_admitted = port_hopping.scheduler_admitted;
    let true_quic_dataplane_admitted = native_contract_admitted
        && udp_underlay_admitted
        && full_quic_handshake_admitted
        && stream_mux_admitted
        && packet_datagram_admitted
        && port_hopping_scheduler_admitted;

    Ok(Hysteria2TrueQuicDataplaneReport {
        link: link.export_url(),
        subscription_tag: options.subscription_tag.clone(),
        property_name: chain.property_name,
        property_protocol: chain.property_protocol,
        property_address: chain.property_address,
        chain_adapter_mode: node.adapter_mode.clone(),
        chain_parent_dialer_non_nil: node.parent_dialer_non_nil,
        user: link.user,
        password_present: !link.password.is_empty(),
        server: link.server,
        sni: link.sni,
        insecure: link.insecure,
        max_tx: link.max_tx,
        max_rx: link.max_rx,
        underlay,
        port_hopping,
        quic,
        total_elapsed_ns,
        ns_per_hysteria2_true_quic_exchange: total_elapsed_ns as f64
            / options
                .quic
                .stream_iterations
                .saturating_add(options.quic.datagram_iterations)
                .max(1) as f64,
        hysteria2_rust_native_contract_admitted: native_contract_admitted,
        hysteria2_udp_underlay_admitted: udp_underlay_admitted,
        hysteria2_full_quic_handshake_admitted: full_quic_handshake_admitted,
        hysteria2_stream_mux_admitted: stream_mux_admitted,
        hysteria2_packet_datagram_admitted: packet_datagram_admitted,
        hysteria2_port_hopping_scheduler_admitted: port_hopping_scheduler_admitted,
        hysteria2_tcp_target_over_quic_admitted: stream_mux_admitted,
        hysteria2_udp_target_over_quic_admitted: packet_datagram_admitted,
        hysteria2_true_quic_dataplane_admitted: true_quic_dataplane_admitted,
        tuic_true_quic_dataplane_admitted: false,
        quic_h3_family_true_dataplane_admitted: false,
        outbound_true_dataplane_admitted: false,
        native_daemon_benchmark_recorded: false,
        production_admission_allowed: false,
        host_mutation_allowed: false,
        final_state_admission_allowed: false,
        true_rust_native_daemon_admitted: false,
    })
}

pub fn default_true_quic_options_with_timeout_ms(
    timeout_ms: u64,
) -> Hysteria2TrueQuicDataplaneOptions {
    let mut options = Hysteria2TrueQuicDataplaneOptions::default();
    options.quic.timeout = Duration::from_millis(timeout_ms);
    options
}

fn parse_hysteria2_chain(raw: &str) -> Result<LinkParseResult, OutboundError> {
    let chain = parse_link_chain(raw)?;
    if chain.property_protocol != "hysteria2" {
        return Err(bad_dataplane(format!(
            "expected hysteria2 property protocol, got {}",
            chain.property_protocol
        )));
    }
    Ok(chain)
}

fn bad_dataplane(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}
