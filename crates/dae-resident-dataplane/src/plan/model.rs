use super::*;

mod binding;
mod execution;
mod protocol;
mod security;
mod wrapper;
mod xhttp;

pub(crate) use binding::ResidentProxyBinding;
#[cfg(test)]
pub(crate) use binding::ResidentXhttpReusePolicy;
pub(crate) use execution::{
    RESIDENT_UDP_CLEANUP_OWNER, RESIDENT_UDP_CLEANUP_POLICY, ResidentExecutionPlan,
    ResidentProtocolShape, ResidentStreamPacketTransport, ResidentTcpCarrierOwnership,
    ResidentTcpProbeDispatch, ResidentTcpRuntimeDispatch, ResidentUdpExecutionAgreement,
    ResidentUdpExecutionDisposition, ResidentUdpExecutorFactory, ResidentUdpPolicyClosedReason,
    ResidentUdpSourceContract, ResidentUdpWireIdentityContract, UdpPacketSemantics,
};
pub(crate) use protocol::ResidentProtocolExecutorContract;
pub(crate) use protocol::{ResidentHysteria2ObfsPlan, ResidentProxyProtocolPlan};
pub(crate) use security::ResidentSecurityUnderlayPlan;
pub(crate) use wrapper::ResidentStreamWrapperPlan;
pub(crate) use xhttp::{
    ResidentEchPlan, ResidentRealityUnderlayPlan, ResidentUtlsFingerprintPlan,
    ResidentXhttpEndpointPlan, ResidentXhttpQuicTlsProvider,
};
pub(crate) use xhttp::{
    ResidentXhttpHttpVersion, ResidentXhttpMetaPlacement, ResidentXhttpMode,
    ResidentXhttpPaddingMethod, ResidentXhttpPaddingPlacement, ResidentXhttpSettingsPlan,
    ResidentXhttpUplinkDataPlacement, ResidentXhttpXmuxPlan,
};
pub(crate) const RESIDENT_CONTROL_PLANE_SO_MARK: u32 = 0x100;

pub(crate) fn effective_so_mark_from_dae(configured: u32) -> u32 {
    if configured == 0 {
        RESIDENT_CONTROL_PLANE_SO_MARK
    } else {
        configured
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectedGroupNode {
    pub(crate) match_index: usize,
    pub(crate) tag: String,
    pub(crate) link: String,
    pub(crate) annotation_add_latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentNodeLinkShape {
    pub(crate) tag: String,
    pub(crate) scheme: String,
    pub(crate) link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GroupNodeSelection {
    Selected(Vec<SelectedGroupNode>),
    NoCandidate {
        explicit_name_filter: bool,
        unresolved_names: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentProxyPlan {
    pub(crate) graph_id: String,
    pub(crate) graph_link_hash: String,
    pub(crate) redacted_link_source: String,
    pub(crate) protocol: &'static str,
    pub(crate) group_name: String,
    pub(crate) group_policy: String,
    pub(crate) node_tag: String,
    pub(crate) server_host: String,
    pub(crate) server_port: u16,
    pub(crate) server_name: String,
    pub(crate) alpn: Vec<String>,
    pub(crate) flow: String,
    pub(crate) net: String,
    pub(crate) stream_host: String,
    pub(crate) stream_path: String,
    pub(crate) grpc_mode: GrpcMode,
    pub(crate) xhttp_download: Option<ResidentXhttpEndpointPlan>,
    pub(crate) xhttp_mode: ResidentXhttpMode,
    pub(crate) xhttp_settings: ResidentXhttpSettingsPlan,
    pub(crate) xhttp_xmux: Option<ResidentXhttpXmuxPlan>,
    pub(crate) tls: String,
    pub(crate) allow_insecure: bool,
    pub(crate) tls_fragment: Option<TlsFragmentOptions>,
    pub(crate) utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    pub(crate) ech: Option<ResidentEchPlan>,
    pub(crate) reality: Option<ResidentRealityUnderlayPlan>,
    pub(crate) handler: ResidentProxyProtocolPlan,
    pub(crate) execution: Option<ResidentExecutionPlan>,
    pub(crate) chain_parent: Option<Arc<ResidentProxyPlan>>,
    pub(crate) mark: u32,
    pub(crate) mptcp: bool,
}

impl ResidentProxyPlan {
    pub(crate) fn executor_contract(&self) -> ResidentProtocolExecutorContract {
        self.execution_plan().executor_contract()
    }

    pub(crate) fn execution_plan(&self) -> ResidentExecutionPlan {
        self.execution
            .expect("resident proxy execution must be materialized before use")
    }

    pub(crate) fn materialized_execution(&self) -> Result<ResidentExecutionPlan, String> {
        self.execution.ok_or_else(|| {
            format!(
                "resident proxy {} node {} has no materialized execution plan",
                self.protocol, self.node_tag
            )
        })
    }

    pub(crate) fn materialize_execution(&mut self) {
        self.execution = Some(ResidentExecutionPlan::from_proxy(self));
    }

    pub(crate) fn xhttp_primary_http_version(&self) -> ResidentXhttpHttpVersion {
        match self.execution_plan().wrapper {
            ResidentStreamWrapperPlan::Xhttp(version) => version,
            _ => ResidentXhttpHttpVersion::H2,
        }
    }

    pub(crate) fn requires_xhttp_xmux_owner(&self) -> bool {
        self.xhttp_xmux.is_some()
            || self
                .xhttp_download
                .as_ref()
                .is_some_and(|download| download.xmux.is_some())
            || self
                .chain_parent
                .as_ref()
                .is_some_and(|parent| parent.requires_xhttp_xmux_owner())
    }

    pub(crate) fn requires_anytls_transport_owner(&self) -> bool {
        matches!(
            &self.handler,
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        )
    }

    pub(crate) fn requires_h2_carrier_owner(&self) -> bool {
        let execution = self.execution_plan();
        (execution.security.is_tls_stream()
            && matches!(
                execution.wrapper,
                ResidentStreamWrapperPlan::Grpc | ResidentStreamWrapperPlan::H2
            ))
            || (execution.protocol == ResidentProtocolShape::VmessAead
                && execution.security == ResidentSecurityUnderlayPlan::None
                && execution.wrapper == ResidentStreamWrapperPlan::Grpc)
    }

    pub(crate) fn requires_meek_transport_owner(&self) -> bool {
        let execution = self.execution_plan();
        execution.security.is_tls_stream() && execution.wrapper == ResidentStreamWrapperPlan::Meek
    }

    pub(crate) fn requires_vless_mux_owner(&self) -> bool {
        let execution = self.execution_plan();
        execution.protocol == ResidentProtocolShape::VlessMux
            && execution.security.is_tls_stream()
            && execution.wrapper == ResidentStreamWrapperPlan::Mux
    }

    pub(crate) fn compact_allocations(&mut self) {
        compact_string(&mut self.graph_id);
        compact_string(&mut self.graph_link_hash);
        compact_string(&mut self.redacted_link_source);
        compact_string(&mut self.group_name);
        compact_string(&mut self.group_policy);
        compact_string(&mut self.node_tag);
        compact_string(&mut self.server_host);
        compact_string(&mut self.server_name);
        compact_string_vec(&mut self.alpn);
        compact_string(&mut self.flow);
        compact_string(&mut self.net);
        compact_string(&mut self.stream_host);
        compact_string(&mut self.stream_path);
        if let Some(download) = &mut self.xhttp_download {
            download.compact_allocations();
        }
        self.xhttp_settings.compact_allocations();
        compact_string(&mut self.tls);
        if let Some(fingerprint) = &mut self.utls_fingerprint {
            fingerprint.compact_allocations();
        }
        if let Some(reality) = &mut self.reality {
            reality.compact_allocations();
        }
        self.handler.compact_allocations();
    }

    pub(crate) fn apply_effective_so_mark_from_dae(&mut self) {
        self.mark = effective_so_mark_from_dae(self.mark);
        if let Some(parent) = self.chain_parent.as_mut() {
            Arc::make_mut(parent).apply_effective_so_mark_from_dae();
        }
    }

    pub(crate) fn executable_graph_descriptor(&self) -> ResidentExecutableGraphDescriptor {
        ResidentExecutableGraphDescriptor::from_proxy(self)
    }

    pub(crate) fn executable_graph_value(&self) -> Value {
        self.executable_graph_descriptor().to_value()
    }

    pub(crate) fn executable_graph_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .to_value_for_reload_generation(reload_generation)
    }

    pub(crate) fn runtime_component_evidence_value(&self) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value()
    }

    pub(crate) fn runtime_component_evidence_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value_for_reload_generation(reload_generation)
    }

    pub(crate) fn vless_key(&self) -> Result<[u8; 16], String> {
        match self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key, .. }
            | ResidentProxyProtocolPlan::VlessMuxTcpTls { key, .. } => Ok(key),
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }

    pub(crate) fn vless_encryption(
        &self,
    ) -> Result<Option<dae_outbound::vless::VlessEncryptionClient>, String> {
        match &self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { encryption, .. }
            | ResidentProxyProtocolPlan::VlessMuxTcpTls { encryption, .. } => {
                Ok(encryption.clone())
            }
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }
}

fn compact_string(value: &mut String) {
    value.shrink_to_fit();
}

fn compact_string_vec(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        compact_string(value);
    }
    values.shrink_to_fit();
}
