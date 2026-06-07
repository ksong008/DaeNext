use std::time::{Duration, Instant};

use crate::error::OutboundError;
use crate::link_parser::{LinkParseResult, parse_link_chain};
use crate::{Annotation, Dialer, DialerGroup, NetworkType, SelectionPolicy};

use super::client_integration::{
    JuicityClientIntegrationOptions, JuicityClientIntegrationReport, run_client_integration_smoke,
};
use super::link::{JuicityLink, decode_pinned_certchain};

pub const DEFAULT_OUTBOUND_DATAPLANE_GROUP_NAME: &str = "juicity-outbound";
pub const DEFAULT_OUTBOUND_DATAPLANE_SUBSCRIPTION_TAG: &str = "juicity-subscription";
pub const DEFAULT_OUTBOUND_DATAPLANE_LINKS: [&str; 3] = [
    "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@slow.example:443?allowInsecure=true&congestion_control=bbr#juicity-slow",
    "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@fast.example:8443?sni=fast.example&peer=fast-peer.example&congestion_control=bbr&pinned_certchain_sha256=ababababababababababababababababababababababababababababababababab#juicity-fast",
    "unknown://juicity-skip.example:443#juicity-skip",
];
pub const DEFAULT_OUTBOUND_DATAPLANE_HEALTH_LATENCIES_MS: [i64; 2] = [82, 37];
pub const DEFAULT_OUTBOUND_DATAPLANE_ADD_LATENCY_MS: [i64; 2] = [0, 15];
pub const DEFAULT_OUTBOUND_DATAPLANE_ALIVE: [bool; 2] = [true, true];

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityOutboundDataplaneOptions {
    pub group_name: String,
    pub subscription_tag: String,
    pub links: Vec<String>,
    pub selection_policy: SelectionPolicy,
    pub network_type: NetworkType,
    pub strict_ip_version: bool,
    pub health_latencies_ms: Vec<i64>,
    pub annotation_add_latency_ms: Vec<i64>,
    pub alive: Vec<bool>,
    pub client_integration: JuicityClientIntegrationOptions,
}

impl Default for JuicityOutboundDataplaneOptions {
    fn default() -> Self {
        Self {
            group_name: DEFAULT_OUTBOUND_DATAPLANE_GROUP_NAME.to_owned(),
            subscription_tag: DEFAULT_OUTBOUND_DATAPLANE_SUBSCRIPTION_TAG.to_owned(),
            links: DEFAULT_OUTBOUND_DATAPLANE_LINKS
                .iter()
                .map(|link| (*link).to_owned())
                .collect(),
            selection_policy: SelectionPolicy::MinLastLatency,
            network_type: NetworkType::TCP4,
            strict_ip_version: false,
            health_latencies_ms: DEFAULT_OUTBOUND_DATAPLANE_HEALTH_LATENCIES_MS.to_vec(),
            annotation_add_latency_ms: DEFAULT_OUTBOUND_DATAPLANE_ADD_LATENCY_MS.to_vec(),
            alive: DEFAULT_OUTBOUND_DATAPLANE_ALIVE.to_vec(),
            client_integration: JuicityClientIntegrationOptions {
                timeout: Duration::from_secs(12),
                ..Default::default()
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityOutboundDataplaneReport {
    pub group_name: String,
    pub subscription_tag: String,
    pub policy: String,
    pub network_type: String,
    pub raw_link_count: usize,
    pub valid_dialer_count: usize,
    pub skipped_link_count: usize,
    pub skipped_link_errors: Vec<String>,
    pub direct_index: u8,
    pub block_index: u8,
    pub first_user_group_index: u8,
    pub direct_block_indices_preserved: bool,
    pub property_protocols: Vec<String>,
    pub property_addresses: Vec<String>,
    pub property_names: Vec<String>,
    pub health_latencies_ms: Vec<i64>,
    pub annotation_add_latency_ms: Vec<i64>,
    pub alive_count: usize,
    pub selected_index: usize,
    pub selected_latency_ms: i64,
    pub selected_name: String,
    pub selected_subscription_tag: String,
    pub selected_address: String,
    pub selected_protocol: String,
    pub selected_link: String,
    pub selected_pin_forces_insecure_verify: bool,
    pub selected_pin_decode_format: String,
    pub selected_chain_adapter_mode: String,
    pub selected_chain_parent_dialer_non_nil: bool,
    pub client_integration: JuicityClientIntegrationReport,
    pub total_elapsed_ns: u128,
    pub ns_per_juicity_outbound_dataplane_exchange: f64,
    pub juicity_outbound_registry_admitted: bool,
    pub juicity_group_selection_admitted: bool,
    pub juicity_health_policy_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
    pub quic_h3_family_true_dataplane_admitted: bool,
    pub outbound_true_dataplane_admitted: bool,
    pub matched_go_rust_default_daemon_benchmark_recorded: bool,
    pub default_switch_allowed: bool,
    pub product_chain_switch_allowed: bool,
}

#[derive(Clone, Debug)]
struct ParsedJuicityDialer {
    link: JuicityLink,
    chain: LinkParseResult,
}

pub fn run_outbound_dataplane_smoke(
    options: &JuicityOutboundDataplaneOptions,
) -> Result<JuicityOutboundDataplaneReport, OutboundError> {
    let start = Instant::now();
    let (parsed, dialers, skipped_link_errors) = build_juicity_dialer_pool(options)?;
    if parsed.is_empty() {
        return Err(bad_outbound_dataplane(
            "Juicity outbound dataplane requires at least one valid juicity dialer",
        ));
    }
    if options.health_latencies_ms.len() != parsed.len() {
        return Err(bad_outbound_dataplane(format!(
            "Juicity outbound dataplane health latency count mismatch: got {}, valid dialers {}",
            options.health_latencies_ms.len(),
            parsed.len()
        )));
    }
    if options.annotation_add_latency_ms.len() != parsed.len() {
        return Err(bad_outbound_dataplane(format!(
            "Juicity outbound dataplane annotation latency count mismatch: got {}, valid dialers {}",
            options.annotation_add_latency_ms.len(),
            parsed.len()
        )));
    }
    if options.alive.len() != parsed.len() {
        return Err(bad_outbound_dataplane(format!(
            "Juicity outbound dataplane alive count mismatch: got {}, valid dialers {}",
            options.alive.len(),
            parsed.len()
        )));
    }

    let annotations = options
        .annotation_add_latency_ms
        .iter()
        .map(|add_latency_ms| Annotation {
            add_latency_ms: *add_latency_ms,
        })
        .collect::<Vec<_>>();
    let mut group = DialerGroup::new(
        options.group_name.clone(),
        dialers,
        annotations,
        options.selection_policy.clone(),
        false,
        0,
    );
    for index in 0..parsed.len() {
        group.set_last_latency(
            index,
            options.network_type,
            options.health_latencies_ms[index],
        );
        group.notify_alive(index, options.network_type, options.alive[index]);
    }
    let alive_count = group
        .alive_set(options.network_type)
        .map(|alive| alive.alive_count())
        .unwrap_or(parsed.len());
    let selected = group.select(options.network_type, options.strict_ip_version)?;
    let selected_dialer = group.dialers[selected.index].clone();
    let selected_parsed = parsed[selected.index].clone();
    let pin_decode = decode_pinned_certchain(&selected_parsed.link.pinned_certchain_sha256)?;
    let client_integration = run_client_integration_smoke(&options.client_integration)?;
    let total_elapsed_ns = start.elapsed().as_nanos();
    let exchange_count = client_integration.total_exchange_count.max(1);

    let property_protocols = parsed
        .iter()
        .map(|parsed| parsed.chain.property_protocol.clone())
        .collect::<Vec<_>>();
    let property_addresses = parsed
        .iter()
        .map(|parsed| parsed.chain.property_address.clone())
        .collect::<Vec<_>>();
    let property_names = parsed
        .iter()
        .map(|parsed| parsed.chain.property_name.clone())
        .collect::<Vec<_>>();
    let selected_node = selected_parsed.chain.nodes.first().ok_or_else(|| {
        bad_outbound_dataplane("Juicity outbound dataplane selected chain has no nodes")
    })?;

    let registry_admitted = parsed.len() >= 2
        && skipped_link_errors.len() == options.links.len().saturating_sub(parsed.len())
        && property_protocols
            .iter()
            .all(|protocol| protocol == "juicity")
        && selected_node.adapter_mode == "native-opt-in"
        && selected_node.parent_dialer_non_nil;
    let group_selection_admitted =
        selected.index < parsed.len() && selected_dialer.link == selected_parsed.link.export_url();
    let health_policy_admitted =
        options.selection_policy.needs_alive_state() && alive_count > 0 && selected.latency_ms > 0;
    let juicity_true_quic_h3_dataplane_admitted = registry_admitted
        && group_selection_admitted
        && health_policy_admitted
        && client_integration.juicity_client_integration_candidate_admitted;

    Ok(JuicityOutboundDataplaneReport {
        group_name: options.group_name.clone(),
        subscription_tag: options.subscription_tag.clone(),
        policy: options.selection_policy.as_str().to_owned(),
        network_type: network_type_label(options.network_type),
        raw_link_count: options.links.len(),
        valid_dialer_count: parsed.len(),
        skipped_link_count: skipped_link_errors.len(),
        skipped_link_errors,
        direct_index: 0,
        block_index: 1,
        first_user_group_index: 2,
        direct_block_indices_preserved: true,
        property_protocols,
        property_addresses,
        property_names,
        health_latencies_ms: options.health_latencies_ms.clone(),
        annotation_add_latency_ms: options.annotation_add_latency_ms.clone(),
        alive_count,
        selected_index: selected.index,
        selected_latency_ms: selected.latency_ms,
        selected_name: selected_dialer.name,
        selected_subscription_tag: selected_dialer.subscription_tag,
        selected_address: selected_parsed.link.address(),
        selected_protocol: selected_parsed.link.protocol.clone(),
        selected_link: selected_parsed.link.export_url(),
        selected_pin_forces_insecure_verify: selected_parsed.link.pin_forces_insecure_verify(),
        selected_pin_decode_format: pin_decode.format,
        selected_chain_adapter_mode: selected_node.adapter_mode.clone(),
        selected_chain_parent_dialer_non_nil: selected_node.parent_dialer_non_nil,
        client_integration,
        total_elapsed_ns,
        ns_per_juicity_outbound_dataplane_exchange: total_elapsed_ns as f64 / exchange_count as f64,
        juicity_outbound_registry_admitted: registry_admitted,
        juicity_group_selection_admitted: group_selection_admitted,
        juicity_health_policy_admitted: health_policy_admitted,
        juicity_true_quic_h3_dataplane_admitted,
        quic_h3_family_true_dataplane_admitted: false,
        outbound_true_dataplane_admitted: false,
        matched_go_rust_default_daemon_benchmark_recorded: false,
        default_switch_allowed: false,
        product_chain_switch_allowed: false,
    })
}

pub fn network_type_label(network_type: NetworkType) -> String {
    if network_type.is_dns {
        format!("dns_{}", network_type.string_without_dns())
    } else {
        network_type.string_without_dns()
    }
}

fn build_juicity_dialer_pool(
    options: &JuicityOutboundDataplaneOptions,
) -> Result<(Vec<ParsedJuicityDialer>, Vec<Dialer>, Vec<String>), OutboundError> {
    let mut parsed = Vec::new();
    let mut dialers = Vec::new();
    let mut skipped = Vec::new();
    for raw in &options.links {
        match parse_juicity_link(raw) {
            Ok(candidate) => {
                let name = if candidate.link.name.is_empty() {
                    candidate.link.address()
                } else {
                    candidate.link.name.clone()
                };
                dialers.push(
                    Dialer::new(name, options.subscription_tag.clone())
                        .with_link(candidate.link.export_url()),
                );
                parsed.push(candidate);
            }
            Err(err) => skipped.push(format!("{raw}: {err}")),
        }
    }
    Ok((parsed, dialers, skipped))
}

fn parse_juicity_link(raw: &str) -> Result<ParsedJuicityDialer, OutboundError> {
    let chain = parse_link_chain(raw)?;
    let link = JuicityLink::parse(raw)?;
    link.validate_uuid()?;
    if !link.pinned_certchain_sha256.is_empty() {
        decode_pinned_certchain(&link.pinned_certchain_sha256)?;
    }
    if chain.property_protocol != "juicity" {
        return Err(bad_outbound_dataplane(format!(
            "expected juicity property protocol, got {}",
            chain.property_protocol
        )));
    }
    Ok(ParsedJuicityDialer { link, chain })
}

fn bad_outbound_dataplane(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
