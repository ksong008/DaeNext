use dae_outbound::{
    MaterializedChain, MaterializedChainUdp, MaterializedPassthroughUdp, MaterializedPortHopping,
    MaterializedQuicVerification, MaterializedSourceImport, MaterializedSourceShape,
    MaterializedTlsFeatures, MaterializedWrapper, MaterializedXhttpMode, MaterializedXhttpSettings,
    SourceShapeReconciliationKind, SourceShapeRegistryRow, VMessLink, VMessSourceFormat,
    parse_link_chain, source_shape_reconciliation,
};
use url::Url;

use super::*;

pub(crate) fn materialized_source_shape(
    proxy: &plan::ResidentProxyPlan,
    source_link: &str,
) -> MaterializedSourceShape {
    let execution = materialized_source_execution_shape(proxy);
    let source = source_metadata(source_link);
    let chain_admission = plan::resident_udp_chain_admission(proxy);
    MaterializedSourceShape {
        protocol: execution.protocol,
        security: execution.security,
        tls_features: materialized_tls_features(execution.security, proxy),
        wrapper: execution.wrapper,
        udp: execution.udp,
        chain: if proxy.chain_parent.is_some() {
            MaterializedChain::ParentConnect
        } else {
            MaterializedChain::Standalone
        },
        chain_udp: match chain_admission {
            plan::ResidentUdpChainAdmission::NotChained => MaterializedChainUdp::NotChained,
            plan::ResidentUdpChainAdmission::ParentStream => MaterializedChainUdp::ParentStream,
            plan::ResidentUdpChainAdmission::Unsupported(_) => MaterializedChainUdp::PolicyClosed,
        },
        xhttp_mode: xhttp_mode(execution.wrapper, proxy.xhttp_mode),
        xhttp_settings: xhttp_settings(execution.wrapper, proxy),
        quic_verification: quic_verification(execution.wrapper, proxy),
        port_hopping: port_hopping(proxy),
        source_import: source.import,
        passthrough_udp: source.passthrough_udp,
    }
}

fn materialized_tls_features(
    security: dae_outbound::MaterializedSecurity,
    proxy: &plan::ResidentProxyPlan,
) -> MaterializedTlsFeatures {
    match security {
        dae_outbound::MaterializedSecurity::StandardTls
        | dae_outbound::MaterializedSecurity::InsecureTls
        | dae_outbound::MaterializedSecurity::FragmentedTls
        | dae_outbound::MaterializedSecurity::FingerprintAwareTls => MaterializedTlsFeatures::new(
            proxy.allow_insecure,
            proxy.tls_fragment.is_some(),
            proxy.utls_fingerprint.is_some(),
        ),
        dae_outbound::MaterializedSecurity::RealityFingerprint => {
            MaterializedTlsFeatures::FINGERPRINT
        }
        _ => MaterializedTlsFeatures::NONE,
    }
}

pub(crate) fn source_shape_matches_materialization(
    row: &SourceShapeRegistryRow,
    proxy: &plan::ResidentProxyPlan,
    source_link: &str,
) -> bool {
    source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| {
        reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
            && reconciliation.matches(materialized_source_shape(proxy, source_link))
            && source_and_materialized_ownership_agree(row, proxy)
    })
}

pub(crate) fn source_shape_classifies_materialization(
    row: &SourceShapeRegistryRow,
    proxy: &plan::ResidentProxyPlan,
    source_link: &str,
) -> bool {
    source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| {
        reconciliation.kind != SourceShapeReconciliationKind::ProductionWitness
            && reconciliation.classifies(materialized_source_shape(proxy, source_link))
            && source_and_materialized_ownership_agree(row, proxy)
    })
}

#[cfg(test)]
pub(crate) fn materialized_source_runtime_ownership_model(
    proxy: &plan::ResidentProxyPlan,
) -> dae_outbound::RuntimeOwnershipModel {
    effective_materialized_runtime_ownership(proxy).model
}

pub(crate) fn source_shape_candidate_is_relevant(
    row: &SourceShapeRegistryRow,
    node: &plan::ResidentNodeLinkShape,
) -> bool {
    let Some(reconciliation) = source_shape_reconciliation(row.shape_id) else {
        return false;
    };
    if reconciliation.kind != SourceShapeReconciliationKind::ProductionWitness
        || !row.link_schemes.contains(&node.scheme.as_str())
    {
        return false;
    }

    let Ok(parsed) = parse_link_chain(&node.link) else {
        return true;
    };
    let materialized_chain = if parsed.nodes.len() > 1 {
        MaterializedChain::ParentConnect
    } else {
        MaterializedChain::Standalone
    };
    reconciliation
        .selectors
        .iter()
        .any(|selector| selector.chain == materialized_chain)
}

pub(super) fn source_shape_reconciliation_status(row: &SourceShapeRegistryRow) -> Value {
    source_shape_reconciliation(row.shape_id)
        .map(|reconciliation| reconciliation.to_value())
        .unwrap_or_else(|| {
            json!({
                "schemaVersion": 1,
                "kind": "missing",
                "selectorCount": 0,
                "contributesProductionWitness": false,
            })
        })
}

pub(super) fn source_shape_materialization_mismatch_reason(
    row: &SourceShapeRegistryRow,
) -> &'static str {
    match source_shape_reconciliation(row.shape_id).map(|reconciliation| reconciliation.kind) {
        Some(SourceShapeReconciliationKind::AggregateCapability) => {
            "aggregate capability row does not contribute a production materialization witness"
        }
        Some(SourceShapeReconciliationKind::DeferredCapability) => {
            "deferred source shape does not contribute a production materialization witness"
        }
        Some(SourceShapeReconciliationKind::SourceRejected) => {
            "source shape is rejected by source admission before materialization"
        }
        Some(SourceShapeReconciliationKind::ProductionWitness) => {
            "materialized resident shape does not match the typed source selector"
        }
        None => "source shape has no typed reconciliation contract",
    }
}

#[derive(Clone, Copy)]
struct SourceMetadata {
    import: MaterializedSourceImport,
    passthrough_udp: MaterializedPassthroughUdp,
}

fn source_metadata(source_link: &str) -> SourceMetadata {
    let Ok(parsed) = parse_link_chain(source_link) else {
        return SourceMetadata {
            import: MaterializedSourceImport::Unrecognized,
            passthrough_udp: MaterializedPassthroughUdp::NotRequested,
        };
    };
    let import = match parsed.nodes.last() {
        Some(node) if node.protocol == "vmess" => {
            match VMessLink::parse_with_source_format(&node.raw) {
                Ok((_, VMessSourceFormat::Json)) => MaterializedSourceImport::Canonical,
                Ok((_, VMessSourceFormat::Legacy)) => MaterializedSourceImport::LegacyVmess,
                Err(_) => MaterializedSourceImport::Unrecognized,
            }
        }
        Some(_) => MaterializedSourceImport::Canonical,
        None => MaterializedSourceImport::Unrecognized,
    };
    let passthrough_udp = if parsed.nodes.iter().any(|node| {
        Url::parse(&node.raw).is_ok_and(|url| {
            url.query_pairs().any(|(key, value)| {
                key == dae_outbound::shared_transport::contract::UDP_PASSTHROUGH_KEY
                    && value.eq_ignore_ascii_case("true")
            })
        })
    }) {
        MaterializedPassthroughUdp::Requested
    } else {
        MaterializedPassthroughUdp::NotRequested
    };
    SourceMetadata {
        import,
        passthrough_udp,
    }
}

fn xhttp_mode(
    wrapper: MaterializedWrapper,
    mode: plan::ResidentXhttpMode,
) -> MaterializedXhttpMode {
    if !matches!(
        wrapper,
        MaterializedWrapper::XhttpH1 | MaterializedWrapper::XhttpH2 | MaterializedWrapper::XhttpH3
    ) {
        return MaterializedXhttpMode::NotApplicable;
    }
    match mode {
        plan::ResidentXhttpMode::PacketUp => MaterializedXhttpMode::PacketUp,
        plan::ResidentXhttpMode::StreamUp => MaterializedXhttpMode::StreamUp,
        plan::ResidentXhttpMode::StreamOne => MaterializedXhttpMode::StreamOne,
    }
}

fn xhttp_settings(
    wrapper: MaterializedWrapper,
    proxy: &plan::ResidentProxyPlan,
) -> MaterializedXhttpSettings {
    if !matches!(
        wrapper,
        MaterializedWrapper::XhttpH1 | MaterializedWrapper::XhttpH2 | MaterializedWrapper::XhttpH3
    ) {
        return MaterializedXhttpSettings::NotApplicable;
    }
    if proxy.xhttp_settings != plan::ResidentXhttpSettingsPlan::official_default()
        || proxy.xhttp_download.is_some()
        || proxy
            .xhttp_xmux
            .as_ref()
            .is_some_and(|xmux| !xhttp_xmux_uses_default_source_settings(xmux))
    {
        MaterializedXhttpSettings::Extended
    } else {
        MaterializedXhttpSettings::Default
    }
}

fn xhttp_xmux_uses_default_source_settings(xmux: &plan::ResidentXhttpXmuxPlan) -> bool {
    let default = plan::ResidentXhttpXmuxPlan::official_default().official_normalized();
    xmux.max_concurrency == default.max_concurrency
        && xmux.max_connections == default.max_connections
        && xmux.c_max_reuse_times == default.c_max_reuse_times
        && xmux.h_max_request_times == default.h_max_request_times
        && xmux.h_max_reusable_secs == default.h_max_reusable_secs
        && xmux.h_keep_alive_period == default.h_keep_alive_period
}

fn quic_verification(
    wrapper: MaterializedWrapper,
    proxy: &plan::ResidentProxyPlan,
) -> MaterializedQuicVerification {
    if wrapper == MaterializedWrapper::XhttpH3 {
        return if proxy.allow_insecure {
            MaterializedQuicVerification::Insecure
        } else {
            MaterializedQuicVerification::WebPki
        };
    }

    match &proxy.handler {
        plan::ResidentProxyProtocolPlan::Hysteria2QuicTcp { tls_identity, .. } => {
            match (
                tls_identity.policy().allow_insecure(),
                tls_identity.policy().has_leaf_certificate_pin(),
            ) {
                (false, false) => MaterializedQuicVerification::WebPki,
                (false, true) => MaterializedQuicVerification::WebPkiAndPin,
                (true, false) => MaterializedQuicVerification::Insecure,
                (true, true) => MaterializedQuicVerification::PinOnly,
            }
        }
        plan::ResidentProxyProtocolPlan::TuicQuicTcp { allow_insecure, .. } => {
            if *allow_insecure {
                MaterializedQuicVerification::Insecure
            } else {
                MaterializedQuicVerification::WebPki
            }
        }
        plan::ResidentProxyProtocolPlan::JuicityQuicTcp {
            allow_insecure,
            pinned_certchain_sha256,
            ..
        } => match (*allow_insecure, pinned_certchain_sha256.is_empty()) {
            (false, true) => MaterializedQuicVerification::WebPki,
            (false, false) => MaterializedQuicVerification::WebPkiAndPin,
            (true, true) => MaterializedQuicVerification::Insecure,
            (true, false) => MaterializedQuicVerification::PinOnly,
        },
        _ => MaterializedQuicVerification::NotApplicable,
    }
}

fn port_hopping(proxy: &plan::ResidentProxyPlan) -> MaterializedPortHopping {
    match &proxy.handler {
        plan::ResidentProxyProtocolPlan::Hysteria2QuicTcp { port_hop_ports, .. } => {
            if port_hop_ports.is_empty() {
                MaterializedPortHopping::Disabled
            } else {
                MaterializedPortHopping::Enabled
            }
        }
        _ => MaterializedPortHopping::NotApplicable,
    }
}
