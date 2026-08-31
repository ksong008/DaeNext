pub mod anytls;
pub mod http_proxy;
pub mod hysteria2;
pub mod juicity;
pub mod link_identity;
pub mod link_parser;
pub mod shadowsocks;
pub mod shared_transport;
pub mod socks5;
pub use dae_outbound_core::stream_wrapper_capability;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod vmess;

pub use dae_outbound_core::alive;
pub use dae_outbound_core::annotation;
pub use dae_outbound_core::connectivity;
pub use dae_outbound_core::dialer;
pub use dae_outbound_core::direct;
pub use dae_outbound_core::error;
pub use dae_outbound_core::filter;
pub use dae_outbound_core::group;
pub use dae_outbound_core::group_override;
pub use dae_outbound_core::latency;
pub use dae_outbound_core::matrix_extension_capability;
pub use dae_outbound_core::policy;
pub use dae_outbound_core::production_matrix;
pub use dae_outbound_core::security_underlay_capability;
pub use dae_outbound_core::source_shape_registry;
pub use dae_outbound_core::surface;
pub use dae_outbound_core::types;

#[cfg(test)]
mod tests;

pub use anytls::AnyTLSLink;
pub use dae_outbound_core::Annotation;
pub use dae_outbound_core::matrix_extension_capability::{
    ExpandedLiveMatrixValidationBoundaryContract, ExtensionLayerCapabilityContract,
    ExtensionLayerCapabilityRow, PacketSemanticsCapabilityContract, PacketSemanticsCapabilityRow,
    TransportOptionCapabilityContract, TransportOptionCapabilityRow,
    expanded_live_matrix_validation_boundary_contract, extension_layer_capability_contract,
    extension_layer_capability_rows, packet_semantics_capability_contract,
    packet_semantics_capability_rows, transport_option_capability_contract,
    transport_option_capability_rows,
};
pub use dae_outbound_core::production_matrix::{
    OutboundProductionMatrixContract, OutboundProductionMatrixEntry,
    outbound_production_matrix_contract, production_matrix_dataplane_declarations_match_registry,
    production_matrix_entries, production_matrix_entries_are_source_registry_backed,
};
pub use dae_outbound_core::security_underlay_capability::{
    SecurityUnderlayCapabilityContract, SecurityUnderlayCapabilityRow,
    security_underlay_capability_contract, security_underlay_capability_rows,
};
pub use dae_outbound_core::source_shape_registry::{
    CONFIGURED_HTTP_OWNERSHIP, CapabilityLedger, ComponentExecutorProof, ExecutorKind,
    ExpandedLiveMatrixLedger, FLOW_STREAM_ASSOCIATION_OWNERSHIP, FLOW_STREAM_PACKET_OWNERSHIP,
    FLOW_STREAM_POLICY_CLOSED_OWNERSHIP, GENERATION_CONNECT_UDP_OWNERSHIP,
    GENERATION_OWNED_ANYTLS_OWNERSHIP, GENERATION_OWNED_H2_PACKET_OWNERSHIP,
    GENERATION_OWNED_H2_POLICY_CLOSED_OWNERSHIP, GENERATION_OWNED_HYSTERIA2_OWNERSHIP,
    GENERATION_OWNED_JUICITY_OWNERSHIP, GENERATION_OWNED_MEEK_OWNERSHIP,
    GENERATION_OWNED_TUIC_OWNERSHIP, GENERATION_OWNED_VLESS_MUX_OWNERSHIP,
    GENERATION_OWNED_XHTTP_OWNERSHIP, LogicalLeaseKind, MATERIALIZED_CHAIN_OWNERSHIP,
    MATERIALIZED_SHAPE_REJECTED_OWNERSHIP, MATERIALIZED_STREAM_SECURITY_OWNERSHIP,
    MaterializedChain, MaterializedChainUdp, MaterializedExecutionShape,
    MaterializedPassthroughUdp, MaterializedPolicyClosedReason, MaterializedPortHopping,
    MaterializedProtocol, MaterializedQuicVerification, MaterializedSecurity,
    MaterializedSourceImport, MaterializedSourceShape, MaterializedStreamPacketTransport,
    MaterializedTlsFeatures, MaterializedTlsVariant, MaterializedUdp, MaterializedWrapper,
    MaterializedXhttpMode, MaterializedXhttpSettings, PacketSemantics, PhysicalCarrierKind,
    PhysicalOwnerKeyContract, ProductionReadinessReconciliation, ProtocolFraming,
    QUIC_FAMILY_MATERIALIZED_OWNERSHIP, RuntimeBudgetContract, RuntimeCallerClass,
    RuntimeLifecycleOwner, RuntimeOwnerRoute, RuntimeOwnershipDisposition, RuntimeOwnershipModel,
    RuntimeOwnershipProfile, RuntimeRouteAdmission, RuntimeSelectionLedger,
    SOURCE_REJECTED_OWNERSHIP, ScopedExpandedSourceMatrixEvidence, SecurityUnderlay,
    SecurityUnderlayPolicyContract, ShapeStateLedger, SourceShapeReconciliation,
    SourceShapeReconciliationKind, SourceShapeRegistryContract, SourceShapeRegistryRow,
    SourceShapeSelector, SourceShapeState, StreamWrapper, TypedCapabilityContract,
    capability_reason_taxonomy, official_common_fixture_requirements,
    official_common_source_shape_ids, source_shape_reconciliation, source_shape_reconciliations,
    source_shape_registry_contract, source_shape_registry_rows,
};
pub use dae_outbound_core::stream_wrapper_capability::{
    StreamWrapperCapabilityContract, StreamWrapperCapabilityRow,
    stream_wrapper_capability_contract, stream_wrapper_capability_rows,
};
pub use dae_outbound_core::surface::{
    OutboundDependencyBoundary, OutboundDependencyContract, OutboundModuleContract,
    OutboundSplitDecision, OutboundSurface, RuntimeOwnerSurface, RuntimeOwnership,
    RuntimeOwnershipContract, TEST_SUPPORT_DEPENDENCIES, crate_split_decision,
    dependency_boundary_contract, module_boundary_contract, public_api_contract,
    runtime_ownership_contract,
};
pub use dae_outbound_core::{
    AliveDialerSet, Collection, CompiledFilterGroups, ConnectivityMap, Dialer, DialerGroup,
    DialerHealthSnapshot, DialerSet, DirectOption, Filter, FilterParam, GroupOverrideCloneCache,
    HealthProfile, HealthState, IpVersion, L4Proto, LatenciesN, MatchedDialer, MatchedDialerRef,
    NETWORK_TYPE_COLLECTION_COUNT, NetworkType, OutboundConnectivityKey, OutboundError,
    ResolverChoice, SelectedDialer, SelectionPolicy, select_direct_resolver,
    string_slice_profile_key,
};
pub use http_proxy::{HttpConnectOptions, HttpProxyLink, HttpScheme, HttpTransportMode};
pub use hysteria2::Hysteria2Link;
pub use juicity::JuicityLink;
pub use link_identity::canonical_link_without_display_name;
pub use link_parser::{LinkNode, LinkParseResult, parse_link_chain};
pub use shadowsocks::{
    CipherFamily, CipherInfo, ShadowsocksLink, ShadowsocksMetadata, Sip003, Sip003Opts,
};
pub use socks5::{AddressKind, ServerReply, Socks5Address, Socks5Command, Socks5UdpDatagram};
pub use trojan::{
    TrojanLink, TrojanMetadata, TrojanNetwork, TrojanTcpExchangeReport, TrojanTcpRequest,
    TrojanTransportType, TrojanUdpOverTcpExchangeReport, TrojanUdpPacket,
};
pub use tuic::TuicLink;
pub use vless::{
    VLESSLink, VlessMuxExchangeReport, VlessMuxRequest, VlessTcpExchangeReport, VlessTcpRequest,
    VlessUdpOverTcpExchangeReport, VlessUdpRequest,
};
pub use vmess::{
    VMessBodySecurity, VMessLink, VMessMetadata, VMessMetadataType, VMessNetwork,
    VMessSourceFormat,
    dataplane::{
        VMESS_AEAD_SECURITY_AES_128_GCM, VMessAeadTcpExchangeReport, VMessAeadTcpRequest,
        VMessAeadUdpOverTcpExchangeReport, VMessAeadUdpOverTcpRequest,
        aead_tcp_exchange_over_stream, aead_tcp_response_packet,
        aead_udp_over_tcp_client_session_start, aead_udp_over_tcp_exchange_over_stream,
        read_aead_tcp_request_from_stream, read_aead_udp_over_tcp_request_from_stream,
        vmess_cmd_key_from_uuid,
    },
};
