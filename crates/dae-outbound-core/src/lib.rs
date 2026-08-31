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
pub mod grpc;
pub mod http_proxy;
pub mod hysteria2;
pub mod juicity;
pub mod latency;
pub mod matrix_extension_capability;
pub mod policy;
pub mod production_matrix;
pub mod security_underlay_capability;
pub mod shadowsocks;
pub mod socks5;
pub mod source_shape_registry;
pub mod stream_wrapper_capability;
pub mod surface;
pub mod trojan;
pub mod tuic;
pub mod types;
pub mod vless;
pub mod vmess;

pub use alive::AliveDialerSet;
pub use annotation::Annotation;
pub use anytls::AnyTLSLink;
pub use connectivity::{ConnectivityMap, OutboundConnectivityKey};
pub use dialer::{Collection, Dialer, DialerHealthSnapshot, HealthState};
pub use direct::{DirectOption, ResolverChoice, select_direct_resolver};
pub use error::OutboundError;
pub use filter::{
    CompiledFilterGroups, DialerSet, Filter, FilterParam, MatchedDialer, MatchedDialerRef,
};
pub use group::{DialerGroup, SelectedDialer};
pub use group_override::{GroupOverrideCloneCache, HealthProfile, string_slice_profile_key};
pub use grpc::GrpcMode;
pub use http_proxy::{HttpProxyLink, HttpScheme};
pub use hysteria2::{
    Hysteria2ApplicationProtocol, Hysteria2BbrProfile, Hysteria2CertificateVerification,
    Hysteria2ClientCertificateIdentity, Hysteria2CongestionConfig, Hysteria2CongestionController,
    Hysteria2CongestionNegotiation, Hysteria2EffectiveCongestionController,
    Hysteria2EncryptedClientHelloIdentity, Hysteria2Link, Hysteria2ServerBandwidthResponse,
    Hysteria2TlsIdentity, Hysteria2TlsPolicy, Hysteria2TrustAnchorIdentity,
};
pub use juicity::{JuicityLink, JuicityPinDecode, JuicityUnderlayContract};
pub use latency::LatenciesN;
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
    outbound_production_matrix_contract, production_matrix_dataplane_declarations_match_registry,
    production_matrix_entries, production_matrix_entries_are_source_registry_backed,
};
pub use security_underlay_capability::{
    SecurityUnderlayCapabilityContract, SecurityUnderlayCapabilityRow,
    security_underlay_capability_contract, security_underlay_capability_rows,
};
pub use shadowsocks::{CipherFamily, CipherInfo, ShadowsocksLink, Sip003, Sip003Opts};
pub use socks5::{AddressKind, Socks5Address};
pub use source_shape_registry::{
    CONFIGURED_HTTP_OWNERSHIP, CapabilityLedger, ComponentExecutorProof, ExpandedLiveMatrixLedger,
    FLOW_STREAM_ASSOCIATION_OWNERSHIP, FLOW_STREAM_PACKET_OWNERSHIP,
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
pub use trojan::{TrojanLink, TrojanMetadata, TrojanNetwork, TrojanTransportType};
pub use tuic::{TuicLink, TuicUdpRelayMode, TuicUnderlayContract};
pub use types::{IpVersion, L4Proto, NETWORK_TYPE_COLLECTION_COUNT, NetworkType};
pub use vmess::{
    VMESS_AEAD_SECURITY_AES_128_GCM, VMESS_AEAD_SECURITY_CHACHA20_POLY1305,
    VMESS_AEAD_SECURITY_NONE, VMessBodySecurity, VMessMetadata, VMessMetadataType, VMessNetwork,
};
