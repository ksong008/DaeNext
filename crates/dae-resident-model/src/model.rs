use super::*;
use crate::executable_graph::ResidentExecutableGraphDescriptor;

mod binding;
mod execution;
mod protocol;
mod security;
mod wrapper;
mod xhttp;

pub use binding::ResidentProxyBinding;
#[cfg(any(test, feature = "test-support"))]
pub use binding::{ResidentProxyBindingScope, ResidentXhttpReusePolicy};
pub use execution::{
    RESIDENT_UDP_CLEANUP_OWNER, RESIDENT_UDP_CLEANUP_POLICY, ResidentExecutionPlan,
    ResidentProtocolShape, ResidentStreamPacketTransport, ResidentTcpCarrierOwnership,
    ResidentTcpProbeDispatch, ResidentTcpRuntimeDispatch, ResidentUdpExecutionAgreement,
    ResidentUdpExecutionDisposition, ResidentUdpExecutorFactory, ResidentUdpPolicyClosedReason,
    ResidentUdpSourceContract, ResidentUdpWireIdentityContract, UdpPacketSemantics,
};
pub use protocol::ResidentProtocolExecutorContract;
pub use protocol::{ResidentHysteria2ObfsPlan, ResidentProxyProtocolPlan};
pub use security::ResidentSecurityUnderlayPlan;
pub use wrapper::ResidentStreamWrapperPlan;
pub use xhttp::{
    ResidentEchPlan, ResidentRealityUnderlayPlan, ResidentUtlsFingerprintPlan,
    ResidentXhttpEndpointPlan, ResidentXhttpQuicTlsProvider,
};
pub use xhttp::{
    ResidentXhttpHttpVersion, ResidentXhttpMetaPlacement, ResidentXhttpMode,
    ResidentXhttpPaddingMethod, ResidentXhttpPaddingPlacement, ResidentXhttpSettingsPlan,
    ResidentXhttpUplinkDataPlacement, ResidentXhttpXmuxPlan,
};
pub const RESIDENT_CONTROL_PLANE_SO_MARK: u32 = 0x100;

pub fn effective_so_mark_from_dae(configured: u32) -> u32 {
    if configured == 0 {
        RESIDENT_CONTROL_PLANE_SO_MARK
    } else {
        configured
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedGroupNode {
    pub match_index: usize,
    pub tag: String,
    pub link: String,
    pub annotation_add_latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentNodeLinkShape {
    pub tag: String,
    pub scheme: String,
    pub link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupNodeSelection {
    Selected(Vec<SelectedGroupNode>),
    NoCandidate {
        explicit_name_filter: bool,
        unresolved_names: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub struct ResidentProxyPlan {
    pub graph_id: String,
    pub graph_link_hash: String,
    pub redacted_link_source: String,
    pub protocol: &'static str,
    pub group_name: String,
    pub group_policy: String,
    pub node_tag: String,
    pub server_host: String,
    pub server_port: u16,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub flow: String,
    pub net: String,
    pub stream_host: String,
    pub stream_path: String,
    pub grpc_mode: GrpcMode,
    pub xhttp_download: Option<ResidentXhttpEndpointPlan>,
    pub xhttp_mode: ResidentXhttpMode,
    pub xhttp_settings: ResidentXhttpSettingsPlan,
    pub xhttp_xmux: Option<ResidentXhttpXmuxPlan>,
    pub tls: String,
    pub allow_insecure: bool,
    pub tls_fragment: Option<TlsFragmentOptions>,
    pub utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    pub ech: Option<ResidentEchPlan>,
    pub reality: Option<ResidentRealityUnderlayPlan>,
    pub handler: ResidentProxyProtocolPlan,
    pub execution: Option<ResidentExecutionPlan>,
    pub chain_parent: Option<Arc<ResidentProxyPlan>>,
    pub mark: u32,
    pub mptcp: bool,
}

impl ResidentProxyPlan {
    pub fn executor_contract(&self) -> ResidentProtocolExecutorContract {
        self.execution_plan().executor_contract()
    }

    pub fn execution_plan(&self) -> ResidentExecutionPlan {
        self.execution
            .expect("resident proxy execution must be materialized before use")
    }

    pub fn materialized_execution(&self) -> Result<ResidentExecutionPlan, String> {
        self.execution.ok_or_else(|| {
            format!(
                "resident proxy {} node {} has no materialized execution plan",
                self.protocol, self.node_tag
            )
        })
    }

    pub fn materialize_execution(&mut self) {
        self.execution = Some(ResidentExecutionPlan::from_proxy(self));
    }

    pub fn xhttp_primary_http_version(&self) -> ResidentXhttpHttpVersion {
        match self.execution_plan().wrapper {
            ResidentStreamWrapperPlan::Xhttp(version) => version,
            _ => ResidentXhttpHttpVersion::H2,
        }
    }

    pub fn requires_xhttp_xmux_owner(&self) -> bool {
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

    pub fn requires_anytls_transport_owner(&self) -> bool {
        matches!(
            &self.handler,
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        )
    }

    pub fn requires_h2_carrier_owner(&self) -> bool {
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

    pub fn requires_meek_transport_owner(&self) -> bool {
        let execution = self.execution_plan();
        execution.security.is_tls_stream() && execution.wrapper == ResidentStreamWrapperPlan::Meek
    }

    pub fn requires_vless_mux_owner(&self) -> bool {
        let execution = self.execution_plan();
        execution.protocol == ResidentProtocolShape::VlessMux
            && execution.security.is_tls_stream()
            && execution.wrapper == ResidentStreamWrapperPlan::Mux
    }

    pub fn compact_allocations(&mut self) {
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

    pub fn apply_effective_so_mark_from_dae(&mut self) {
        self.mark = effective_so_mark_from_dae(self.mark);
        if let Some(parent) = self.chain_parent.as_mut() {
            Arc::make_mut(parent).apply_effective_so_mark_from_dae();
        }
    }

    pub fn executable_graph_descriptor(&self) -> ResidentExecutableGraphDescriptor {
        ResidentExecutableGraphDescriptor::from_proxy(self)
    }

    pub fn executable_graph_value(&self) -> Value {
        self.executable_graph_descriptor().to_value()
    }

    pub fn executable_graph_value_for_reload_generation(&self, reload_generation: u64) -> Value {
        self.executable_graph_descriptor()
            .to_value_for_reload_generation(reload_generation)
    }

    pub fn runtime_component_evidence_value(&self) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value()
    }

    pub fn runtime_component_evidence_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value_for_reload_generation(reload_generation)
    }

    pub fn vless_key(&self) -> Result<[u8; 16], String> {
        match self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key, .. }
            | ResidentProxyProtocolPlan::VlessMuxTcpTls { key, .. } => Ok(key),
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }

    pub fn vless_encryption(&self) -> Result<Option<VlessEncryptionClient>, String> {
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
