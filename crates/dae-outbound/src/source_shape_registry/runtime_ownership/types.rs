use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOwnershipModel {
    FlowStreamAndPacketSession,
    FlowStreamWithPacketPolicyClosed,
    FlowStreamAndAssociation,
    GenerationOwnedHysteria2Transport,
    GenerationOwnedTuicTransport,
    CallerScopedJuicityTransport,
    GenerationConnectUdpTransport,
    ConfiguredHttpTransport,
    MaterializedProtocolTransport,
    // This is a materialized-ledger rejection, not a source parser rejection.
    MaterializedShapeRejected,
    SourceAdmissionRejected,
}

impl RuntimeOwnershipModel {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::FlowStreamAndPacketSession => "flow-stream-and-packet-session",
            Self::FlowStreamWithPacketPolicyClosed => "flow-stream-with-packet-policy-closed",
            Self::FlowStreamAndAssociation => "flow-stream-and-association",
            Self::GenerationOwnedHysteria2Transport => "generation-owned-hysteria2-transport",
            Self::GenerationOwnedTuicTransport => "generation-owned-tuic-transport",
            Self::CallerScopedJuicityTransport => "caller-scoped-juicity-transport",
            Self::GenerationConnectUdpTransport => "generation-connect-udp-transport",
            Self::ConfiguredHttpTransport => "configured-http-transport",
            Self::MaterializedProtocolTransport => "materialized-protocol-transport",
            Self::MaterializedShapeRejected => "materialized-shape-rejected",
            Self::SourceAdmissionRejected => "source-admission-rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOwnershipDisposition {
    Implemented,
    IntentionallyPerFlow,
    FailClosed,
    Blocked,
}

impl RuntimeOwnershipDisposition {
    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::IntentionallyPerFlow => "intentionally-per-flow",
            Self::FailClosed => "fail-closed",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCallerClass {
    DataTcp,
    DataUdp,
    HealthTcp,
    HealthDns,
    ManualProbe,
    ConfiguredDns,
    ForcedManagedDns,
}

impl RuntimeCallerClass {
    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::DataTcp => "data-tcp",
            Self::DataUdp => "data-udp",
            Self::HealthTcp => "health-tcp",
            Self::HealthDns => "health-dns",
            Self::ManualProbe => "manual-probe",
            Self::ConfiguredDns => "configured-dns",
            Self::ForcedManagedDns => "forced-managed-dns",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeRouteAdmission {
    Admitted,
    NotApplicable,
    FailClosed,
    Blocked,
}

impl RuntimeRouteAdmission {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::NotApplicable => "not-applicable",
            Self::FailClosed => "fail-closed",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalCarrierKind {
    PerFlowStream,
    StreamOrDatagramTransport,
    SocksAssociation,
    QuicEndpointAndConnection,
    ConnectUdpHttpConnection,
    ConfiguredHttpConnection,
    MaterializedTransport,
    None,
    External,
}

impl PhysicalCarrierKind {
    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::PerFlowStream => "per-flow-stream",
            Self::StreamOrDatagramTransport => "stream-or-datagram-transport",
            Self::SocksAssociation => "socks-association",
            Self::QuicEndpointAndConnection => "quic-endpoint-and-connection",
            Self::ConnectUdpHttpConnection => "connect-udp-http-connection",
            Self::ConfiguredHttpConnection => "configured-http-connection",
            Self::MaterializedTransport => "materialized-transport",
            Self::None => "none",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalLeaseKind {
    ByteStream,
    PacketSession,
    PacketAssociation,
    QuicStream,
    Hysteria2Session,
    TuicAssociation,
    JuicityPacketStream,
    MaterializedQuicLease,
    ConnectUdpContext,
    HttpStreamOrExchange,
    MaterializedLease,
    None,
}

impl LogicalLeaseKind {
    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::ByteStream => "byte-stream",
            Self::PacketSession => "packet-session",
            Self::PacketAssociation => "packet-association",
            Self::QuicStream => "quic-stream",
            Self::Hysteria2Session => "hysteria2-session",
            Self::TuicAssociation => "tuic-association",
            Self::JuicityPacketStream => "juicity-packet-stream",
            Self::MaterializedQuicLease => "materialized-quic-lease",
            Self::ConnectUdpContext => "connect-udp-context",
            Self::HttpStreamOrExchange => "http-stream-or-exchange",
            Self::MaterializedLease => "materialized-lease",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLifecycleOwner {
    Flow,
    UdpSessionManager,
    GenerationRuntime,
    HealthAttempt,
    ManualProbeJob,
    DnsRequest,
    ConfiguredDnsForwarder,
    GenerationOrCaller,
    ResolvedAtMaterialization,
    SourceAdmission,
}

impl RuntimeLifecycleOwner {
    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::Flow => "flow",
            Self::UdpSessionManager => "udp-session-manager",
            Self::GenerationRuntime => "generation-runtime-owner",
            Self::HealthAttempt => "health-attempt",
            Self::ManualProbeJob => "manual-probe-job",
            Self::DnsRequest => "dns-request",
            Self::ConfiguredDnsForwarder => "configured-dns-forwarder",
            Self::GenerationOrCaller => "generation-or-caller",
            Self::ResolvedAtMaterialization => "resolved-at-materialization",
            Self::SourceAdmission => "source-admission",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalOwnerKeyContract {
    FlowGraphTargetAndTransport,
    UdpSessionGraphTargetAndTransport,
    GenerationGraphAndTransport,
    ConfiguredPoolOrFlowGraphAndTransport,
    ResolvedAtMaterialization,
    None,
}

impl PhysicalOwnerKeyContract {
    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::FlowGraphTargetAndTransport => "flow-graph-target-and-transport",
            Self::UdpSessionGraphTargetAndTransport => "udp-session-graph-target-and-transport",
            Self::GenerationGraphAndTransport => "generation-graph-and-transport",
            Self::ConfiguredPoolOrFlowGraphAndTransport => {
                "configured-pool-or-flow-graph-and-transport"
            }
            Self::ResolvedAtMaterialization => "resolved-at-materialization",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeBudgetContract {
    FlowConcurrency,
    UdpSessionCountAndPayloadBytes,
    ConfiguredDnsActorCountAndPayloadBytes,
    PhysicalOwnerCountAndChargedBytes,
    PhysicalOwnerCountAndChargedBytesMissing,
    PoolCountAndChargedBytes,
    ConfiguredConnectionCountWithChargedBytesMissing,
    ResolvedAtMaterialization,
    NotApplicable,
}

impl RuntimeBudgetContract {
    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::FlowConcurrency => "flow-concurrency",
            Self::UdpSessionCountAndPayloadBytes => "udp-session-count-and-payload-bytes",
            Self::ConfiguredDnsActorCountAndPayloadBytes => {
                "configured-dns-actor-count-and-payload-bytes"
            }
            Self::PhysicalOwnerCountAndChargedBytes => "physical-owner-count-and-charged-bytes",
            Self::PhysicalOwnerCountAndChargedBytesMissing => {
                "physical-owner-count-and-charged-bytes-missing"
            }
            Self::PoolCountAndChargedBytes => "pool-count-and-charged-bytes",
            Self::ConfiguredConnectionCountWithChargedBytesMissing => {
                "configured-connection-count-with-charged-bytes-missing"
            }
            Self::ResolvedAtMaterialization => "resolved-at-materialization",
            Self::NotApplicable => "not-applicable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeOwnerRoute {
    pub caller: RuntimeCallerClass,
    pub admission: RuntimeRouteAdmission,
    pub physical_carrier: PhysicalCarrierKind,
    pub logical_lease: LogicalLeaseKind,
    pub lifecycle_owner: RuntimeLifecycleOwner,
    pub key_contract: PhysicalOwnerKeyContract,
    pub budget_contract: RuntimeBudgetContract,
}

impl RuntimeOwnerRoute {
    pub(super) fn to_value(self) -> Value {
        json!({
            "caller": self.caller.as_report_str(),
            "admission": self.admission.as_report_str(),
            "physicalCarrier": self.physical_carrier.as_report_str(),
            "logicalLease": self.logical_lease.as_report_str(),
            "lifecycleOwner": self.lifecycle_owner.as_report_str(),
            "keyContract": self.key_contract.as_report_str(),
            "budgetContract": self.budget_contract.as_report_str(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeOwnershipProfile {
    pub model: RuntimeOwnershipModel,
    pub allowed_materialized_models: &'static [RuntimeOwnershipModel],
    pub disposition: RuntimeOwnershipDisposition,
    pub data_tcp: RuntimeOwnerRoute,
    pub data_udp: RuntimeOwnerRoute,
    pub health_tcp: RuntimeOwnerRoute,
    pub health_dns: RuntimeOwnerRoute,
    pub manual: RuntimeOwnerRoute,
    pub configured_dns: RuntimeOwnerRoute,
    pub forced_managed_dns: RuntimeOwnerRoute,
}

impl RuntimeOwnershipProfile {
    pub fn accepts_materialized(self, materialized: RuntimeOwnershipModel) -> bool {
        self.allowed_materialized_models.contains(&materialized)
    }
}
