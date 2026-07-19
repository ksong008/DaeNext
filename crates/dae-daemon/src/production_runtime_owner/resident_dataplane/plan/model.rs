use super::*;

mod execution;
mod protocol;
mod security;
mod wrapper;
mod xhttp;

pub(in crate::production_runtime_owner::resident_dataplane) use execution::{
    RESIDENT_UDP_CLEANUP_OWNER, RESIDENT_UDP_CLEANUP_POLICY, ResidentExecutionPlan,
    ResidentProtocolShape, ResidentStreamPacketTransport, ResidentTcpProbeDispatch,
    ResidentTcpRuntimeDispatch, ResidentUdpExecutionAgreement, ResidentUdpExecutionDisposition,
    ResidentUdpExecutorFactory, ResidentUdpPolicyClosedReason, ResidentUdpSourceContract,
    ResidentUdpWireIdentityContract, UdpPacketSemantics,
};
pub(in crate::production_runtime_owner::resident_dataplane) use protocol::ResidentProtocolExecutorContract;
pub(crate) use protocol::{ResidentHysteria2ObfsPlan, ResidentProxyProtocolPlan};
pub(in crate::production_runtime_owner::resident_dataplane) use security::ResidentSecurityUnderlayPlan;
pub(in crate::production_runtime_owner::resident_dataplane) use wrapper::ResidentStreamWrapperPlan;
pub(crate) use xhttp::{
    ResidentRealityUnderlayPlan, ResidentUtlsFingerprintPlan, ResidentXhttpEndpointPlan,
    ResidentXhttpQuicTlsProvider,
};
pub(in crate::production_runtime_owner::resident_dataplane) use xhttp::{
    ResidentXhttpHttpVersion, ResidentXhttpMetaPlacement, ResidentXhttpMode,
    ResidentXhttpPaddingMethod, ResidentXhttpPaddingPlacement, ResidentXhttpSettingsPlan,
    ResidentXhttpUplinkDataPlacement, ResidentXhttpXmuxPlan,
};
pub(in crate::production_runtime_owner::resident_dataplane) const RESIDENT_CONTROL_PLANE_SO_MARK:
    u32 = 0x100;

pub(in crate::production_runtime_owner::resident_dataplane) fn effective_so_mark_from_dae(
    configured: u32,
) -> u32 {
    if configured == 0 {
        RESIDENT_CONTROL_PLANE_SO_MARK
    } else {
        configured
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectedGroupNode {
    pub(in crate::production_runtime_owner::resident_dataplane) match_index: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
    pub(in crate::production_runtime_owner::resident_dataplane) annotation_add_latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentNodeLinkShape {
    pub(in crate::production_runtime_owner::resident_dataplane) tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) scheme: String,
    pub(in crate::production_runtime_owner::resident_dataplane) link: String,
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
    pub(in crate::production_runtime_owner::resident_dataplane) graph_id: String,
    pub(in crate::production_runtime_owner::resident_dataplane) graph_link_hash: String,
    pub(in crate::production_runtime_owner::resident_dataplane) redacted_link_source: String,
    pub(in crate::production_runtime_owner::resident_dataplane) protocol: &'static str,
    pub(in crate::production_runtime_owner::resident_dataplane) group_name: String,
    pub(in crate::production_runtime_owner::resident_dataplane) group_policy: String,
    pub(in crate::production_runtime_owner::resident_dataplane) node_tag: String,
    pub(in crate::production_runtime_owner::resident_dataplane) server_host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) server_port: u16,
    pub(in crate::production_runtime_owner::resident_dataplane) server_name: String,
    pub(in crate::production_runtime_owner::resident_dataplane) alpn: Vec<String>,
    pub(in crate::production_runtime_owner::resident_dataplane) flow: String,
    pub(in crate::production_runtime_owner::resident_dataplane) net: String,
    pub(in crate::production_runtime_owner::resident_dataplane) stream_host: String,
    pub(in crate::production_runtime_owner::resident_dataplane) stream_path: String,
    pub(in crate::production_runtime_owner::resident_dataplane) xhttp_download:
        Option<ResidentXhttpEndpointPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) xhttp_mode: ResidentXhttpMode,
    pub(in crate::production_runtime_owner::resident_dataplane) xhttp_settings:
        ResidentXhttpSettingsPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) xhttp_xmux:
        Option<ResidentXhttpXmuxPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) tls: String,
    pub(in crate::production_runtime_owner::resident_dataplane) allow_insecure: bool,
    pub(in crate::production_runtime_owner::resident_dataplane) tls_fragment:
        Option<TlsFragmentOptions>,
    pub(in crate::production_runtime_owner::resident_dataplane) utls_fingerprint:
        Option<ResidentUtlsFingerprintPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) reality:
        Option<ResidentRealityUnderlayPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) handler: ResidentProxyProtocolPlan,
    pub(in crate::production_runtime_owner::resident_dataplane) execution:
        Option<ResidentExecutionPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) chain_parent:
        Option<Arc<ResidentProxyPlan>>,
    pub(in crate::production_runtime_owner::resident_dataplane) mark: u32,
    pub(in crate::production_runtime_owner::resident_dataplane) mptcp: bool,
}

impl ResidentProxyPlan {
    pub(in crate::production_runtime_owner::resident_dataplane) fn executor_contract(
        &self,
    ) -> ResidentProtocolExecutorContract {
        self.execution_plan().executor_contract()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn execution_plan(
        &self,
    ) -> ResidentExecutionPlan {
        self.execution
            .unwrap_or_else(|| ResidentExecutionPlan::from_proxy(self))
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn materialize_execution(
        &mut self,
    ) {
        self.execution = Some(ResidentExecutionPlan::from_proxy(self));
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn xhttp_primary_http_version(
        &self,
    ) -> ResidentXhttpHttpVersion {
        match self.execution_plan().wrapper {
            ResidentStreamWrapperPlan::Xhttp(version) => version,
            _ => ResidentXhttpHttpVersion::H2,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn requires_xhttp_xmux_owner(
        &self,
    ) -> bool {
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn requires_anytls_transport_owner(
        &self,
    ) -> bool {
        matches!(
            &self.handler,
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn requires_h2_carrier_owner(
        &self,
    ) -> bool {
        let execution = self.execution_plan();
        execution.security.is_tls_stream()
            && matches!(
                execution.wrapper,
                ResidentStreamWrapperPlan::Grpc | ResidentStreamWrapperPlan::H2
            )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn requires_meek_transport_owner(
        &self,
    ) -> bool {
        let execution = self.execution_plan();
        execution.security.is_tls_stream() && execution.wrapper == ResidentStreamWrapperPlan::Meek
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn requires_vless_mux_owner(
        &self,
    ) -> bool {
        let execution = self.execution_plan();
        execution.protocol == ResidentProtocolShape::VlessMux
            && execution.security.is_tls_stream()
            && execution.wrapper == ResidentStreamWrapperPlan::Mux
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn compact_allocations(&mut self) {
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn disable_latency_probe_persistent_caches(
        &mut self,
    ) {
        self.xhttp_xmux = None;
        if let Some(download) = &mut self.xhttp_download {
            download.xmux = None;
        }
        if let Some(parent) = self.chain_parent.as_mut() {
            Arc::make_mut(parent).disable_latency_probe_persistent_caches();
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_runtime_generation(
        &mut self,
        runtime_generation: u64,
    ) {
        self.execution = Some(self.execution_plan().with_runtime_generation(
            dae_runtime_control::OwnerGeneration::new(runtime_generation),
        ));
        if let Some(xmux) = &mut self.xhttp_xmux {
            xmux.apply_runtime_generation(runtime_generation);
        }
        if let Some(download) = &mut self.xhttp_download
            && let Some(xmux) = &mut download.xmux
        {
            xmux.apply_runtime_generation(runtime_generation);
        }
        if let Some(parent) = self.chain_parent.as_mut() {
            Arc::make_mut(parent).apply_runtime_generation(runtime_generation);
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_effective_so_mark_from_dae(
        &mut self,
    ) {
        self.mark = effective_so_mark_from_dae(self.mark);
        if let Some(parent) = self.chain_parent.as_mut() {
            Arc::make_mut(parent).apply_effective_so_mark_from_dae();
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn apply_latency_probe_control_mark(
        &mut self,
        mark: u32,
    ) {
        if mark == 0 {
            return;
        }
        if self.mark == 0 {
            self.mark = mark;
        }
        if let Some(parent) = self.chain_parent.as_mut() {
            Arc::make_mut(parent).apply_latency_probe_control_mark(mark);
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn latency_probe_proxy(
        &self,
    ) -> Self {
        let mut proxy = self.clone();
        proxy.disable_latency_probe_persistent_caches();
        proxy.compact_allocations();
        proxy
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executable_graph_descriptor(
        &self,
    ) -> ResidentExecutableGraphDescriptor {
        ResidentExecutableGraphDescriptor::from_proxy(self)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executable_graph_value(
        &self,
    ) -> Value {
        self.executable_graph_descriptor().to_value()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executable_graph_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .to_value_for_reload_generation(reload_generation)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn runtime_component_evidence_value(
        &self,
    ) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn runtime_component_evidence_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value_for_reload_generation(reload_generation)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn vless_key(
        &self,
    ) -> Result<[u8; 16], String> {
        match self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key }
            | ResidentProxyProtocolPlan::VlessMuxTcpTls { key } => Ok(key),
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
