use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOwnershipModel {
    FlowStreamAndPacketSession,
    FlowStreamWithPacketPolicyClosed,
    FlowStreamAndAssociation,
    CallerScopedQuicTransport,
    GenerationConnectUdpTransport,
    ConfiguredHttpTransport,
    MaterializedProtocolTransport,
    SourceAdmissionRejected,
}

impl RuntimeOwnershipModel {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::FlowStreamAndPacketSession => "flow-stream-and-packet-session",
            Self::FlowStreamWithPacketPolicyClosed => "flow-stream-with-packet-policy-closed",
            Self::FlowStreamAndAssociation => "flow-stream-and-association",
            Self::CallerScopedQuicTransport => "caller-scoped-quic-transport",
            Self::GenerationConnectUdpTransport => "generation-connect-udp-transport",
            Self::ConfiguredHttpTransport => "configured-http-transport",
            Self::MaterializedProtocolTransport => "materialized-protocol-transport",
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
    TcpFlow,
    UdpFlow,
    HealthCheck,
    ManualProbe,
    ProxyDns,
    None,
}

impl RuntimeCallerClass {
    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::TcpFlow => "tcp-flow",
            Self::UdpFlow => "udp-flow",
            Self::HealthCheck => "health-check",
            Self::ManualProbe => "manual-probe",
            Self::ProxyDns => "proxy-dns",
            Self::None => "none",
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
    QuicPacketSession,
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
            Self::QuicPacketSession => "quic-packet-session",
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
    pub disposition: RuntimeOwnershipDisposition,
    pub tcp: RuntimeOwnerRoute,
    pub udp: RuntimeOwnerRoute,
    pub health: RuntimeOwnerRoute,
    pub manual: RuntimeOwnerRoute,
    pub dns: RuntimeOwnerRoute,
}

impl RuntimeOwnershipProfile {
    pub fn accepts_materialized(self, materialized: RuntimeOwnershipModel) -> bool {
        self.model == materialized
            || (self.model == RuntimeOwnershipModel::MaterializedProtocolTransport
                && materialized != RuntimeOwnershipModel::SourceAdmissionRejected)
    }
}
