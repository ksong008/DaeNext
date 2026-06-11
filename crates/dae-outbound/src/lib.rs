pub mod alive;
pub mod annotation;
pub mod anytls;
pub mod connectivity;
pub mod dialer;
pub mod direct;
pub mod error;
pub mod filter;
pub mod group;
pub mod group_override;
pub mod http_proxy;
pub mod hysteria2;
pub mod juicity;
pub mod latency;
pub mod link_parser;
pub mod matrix_extension_capability;
pub mod policy;
pub mod production_matrix;
pub mod security_underlay_capability;
pub mod shadowsocks;
pub mod shared_transport;
pub mod socks5;
pub mod source_shape_registry;
pub mod stream_wrapper_capability;
pub mod surface;
pub mod trojan;
pub mod tuic;
pub mod types;
pub mod vless;
pub mod vmess;

#[cfg(test)]
mod tests;

pub use alive::AliveDialerSet;
pub use annotation::Annotation;
pub use anytls::AnyTLSLink;
pub use connectivity::{ConnectivityMap, OutboundConnectivityKey};
pub use dialer::{Collection, Dialer};
pub use direct::{DirectOption, ResolverChoice, select_direct_resolver};
pub use error::OutboundError;
pub use filter::{
    CompiledFilterGroups, DialerSet, Filter, FilterParam, MatchedDialer, MatchedDialerRef,
};
pub use group::{DialerGroup, SelectedDialer};
pub use group_override::{GroupOverrideCloneCache, HealthProfile, string_slice_profile_key};
pub use http_proxy::{HttpConnectOptions, HttpProxyLink, HttpScheme, HttpTransportMode};
pub use hysteria2::Hysteria2Link;
pub use juicity::JuicityLink;
pub use latency::LatenciesN;
pub use link_parser::{LinkNode, LinkParseResult, parse_link_chain};
pub use matrix_extension_capability::{
    ExpandedLiveMatrixValidationBoundaryContract, ExtensionLayerCapabilityContract,
    ExtensionLayerCapabilityRow, PacketSemanticsCapabilityContract, PacketSemanticsCapabilityRow,
    TransportOptionCapabilityContract, TransportOptionCapabilityRow,
    expanded_live_matrix_validation_boundary_contract, extension_layer_capability_contract,
    extension_layer_capability_rows, packet_semantics_capability_contract,
    packet_semantics_capability_rows, transport_option_capability_contract,
    transport_option_capability_rows,
};
pub use policy::SelectionPolicy;
pub use production_matrix::{
    OutboundProductionMatrixContract, OutboundProductionMatrixEntry,
    outbound_production_matrix_contract, production_matrix_entries,
};
pub use security_underlay_capability::{
    SecurityUnderlayCapabilityContract, SecurityUnderlayCapabilityRow,
    security_underlay_capability_contract, security_underlay_capability_rows,
};
pub use shadowsocks::{
    CipherFamily, CipherInfo, ShadowsocksLink, ShadowsocksMetadata, Sip003, Sip003Opts,
};
pub use socks5::{AddressKind, ServerReply, Socks5Address, Socks5Command, Socks5UdpDatagram};
pub use source_shape_registry::{
    CapabilityLedger, ComponentExecutorProof, ExpandedLiveMatrixLedger,
    ProductionReadinessReconciliation, RuntimeSelectionLedger, ScopedExpandedSourceMatrixEvidence,
    ShapeStateLedger, SourceShapeRegistryContract, SourceShapeRegistryRow,
    capability_reason_taxonomy, official_common_fixture_requirements,
    official_common_source_shape_ids, source_shape_registry_contract, source_shape_registry_rows,
};
pub use stream_wrapper_capability::{
    StreamWrapperCapabilityContract, StreamWrapperCapabilityRow,
    stream_wrapper_capability_contract, stream_wrapper_capability_rows,
};
pub use surface::{
    OutboundDependencyBoundary, OutboundDependencyContract, OutboundModuleContract,
    OutboundSplitDecision, OutboundSurface, RuntimeOwnerSurface, RuntimeOwnership,
    RuntimeOwnershipContract, TEST_SUPPORT_DEPENDENCIES, crate_split_decision,
    dependency_boundary_contract, module_boundary_contract, public_api_contract,
    runtime_ownership_contract,
};
pub use trojan::{
    TrojanLink, TrojanMetadata, TrojanNetwork, TrojanTcpExchangeReport, TrojanTcpRequest,
    TrojanTransportType, TrojanUdpOverTcpExchangeReport, TrojanUdpPacket,
};
pub use tuic::TuicLink;
pub use types::{IpVersion, L4Proto, NetworkType};
pub use vless::{
    VLESSLink, VlessMuxExchangeReport, VlessMuxRequest, VlessTcpExchangeReport, VlessTcpRequest,
    VlessUdpOverTcpExchangeReport, VlessUdpRequest,
};
pub use vmess::{
    VMessLink, VMessMetadata, VMessMetadataType, VMessNetwork,
    dataplane::{
        VMESS_AEAD_SECURITY_AES_128_GCM, VMessAeadTcpExchangeReport, VMessAeadTcpRequest,
        VMessAeadUdpOverTcpExchangeReport, VMessAeadUdpOverTcpRequest,
        aead_tcp_exchange_over_stream, aead_tcp_response_packet,
        aead_udp_over_tcp_client_session_start, aead_udp_over_tcp_exchange_over_stream,
        read_aead_tcp_request_from_stream, read_aead_udp_over_tcp_request_from_stream,
        vmess_cmd_key_from_uuid,
    },
};
