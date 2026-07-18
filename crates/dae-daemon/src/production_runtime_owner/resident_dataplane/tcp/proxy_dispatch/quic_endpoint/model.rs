use std::future::Future;
use std::net::SocketAddr;

use dae_runtime_control::{OwnerGeneration, RedactedOwnerIdentity};
use sha2::{Digest, Sha256};

use crate::production_runtime_owner::resident_dataplane::plan::ResidentProxyPlan;

use super::charge::QuicEndpointCharge;

const QUIC_ENDPOINT_IDENTITY_NAMESPACE: &str = "quinn-endpoint";
const QUIC_ENDPOINT_IDENTITY_DOMAIN: &[u8] = b"dae/quinn-endpoint/provenance/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum QuicEndpointProtocol {
    Hysteria2,
    Tuic,
    Juicity,
    XhttpHttp3,
    DnsOverQuic,
    DnsOverHttp3,
}

impl QuicEndpointProtocol {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Juicity => "juicity",
            Self::XhttpHttp3 => "xhttp-h3",
            Self::DnsOverQuic => "doq",
            Self::DnsOverHttp3 => "doh3",
        }
    }

    pub(super) const fn uses_http3(self) -> bool {
        matches!(
            self,
            Self::Hysteria2 | Self::Juicity | Self::XhttpHttp3 | Self::DnsOverHttp3
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum QuicEndpointCallerClass {
    TcpData,
    UdpData,
    ConfiguredDns,
    ManagedDns,
    BackgroundHealth,
    ManualProbe,
}

impl QuicEndpointCallerClass {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::TcpData => "tcp-data",
            Self::UdpData => "udp-data",
            Self::ConfiguredDns => "configured-dns",
            Self::ManagedDns => "managed-dns",
            Self::BackgroundHealth => "background-health",
            Self::ManualProbe => "manual-probe",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum QuicEndpointIdentityRole {
    ProtocolCarrier,
    XhttpPrimary,
    XhttpDownload,
    ConfiguredDns,
    ManagedDnsOuter,
}

impl QuicEndpointIdentityRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolCarrier => "protocol-carrier",
            Self::XhttpPrimary => "xhttp-primary",
            Self::XhttpDownload => "xhttp-download",
            Self::ConfiguredDns => "configured-dns",
            Self::ManagedDnsOuter => "managed-dns-outer",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum QuicEndpointAddressFamily {
    Ipv4,
    Ipv6,
}

impl QuicEndpointAddressFamily {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum QuicEndpointUnderlay {
    Ordinary,
    Salamander,
    PortHopping { transition_socket_limit: usize },
    SalamanderPortHopping { transition_socket_limit: usize },
}

impl QuicEndpointUnderlay {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Salamander => "salamander",
            Self::PortHopping { .. } => "port-hopping",
            Self::SalamanderPortHopping { .. } => "salamander-port-hopping",
        }
    }

    pub(super) const fn uses_single_datagram_receive(self) -> bool {
        matches!(self, Self::Salamander | Self::SalamanderPortHopping { .. })
    }

    pub(super) const fn socket_charge_count(self) -> usize {
        match self {
            Self::Ordinary | Self::Salamander => 1,
            Self::PortHopping {
                transition_socket_limit,
            }
            | Self::SalamanderPortHopping {
                transition_socket_limit,
            } => transition_socket_limit,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct QuicEndpointTaskObservation {
    caller: QuicEndpointCallerClass,
    generation: Option<OwnerGeneration>,
}

tokio::task_local! {
    static QUIC_ENDPOINT_TASK_OBSERVATION: QuicEndpointTaskObservation;
}

pub(crate) async fn scope_quic_endpoint_observation<F>(
    caller: QuicEndpointCallerClass,
    generation: Option<OwnerGeneration>,
    future: F,
) -> F::Output
where
    F: Future,
{
    QUIC_ENDPOINT_TASK_OBSERVATION
        .scope(QuicEndpointTaskObservation { caller, generation }, future)
        .await
}

pub(crate) fn inherit_quic_endpoint_observation<F>(future: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    let observation = QUIC_ENDPOINT_TASK_OBSERVATION.try_with(|value| *value).ok();
    async move {
        match observation {
            Some(observation) => {
                QUIC_ENDPOINT_TASK_OBSERVATION
                    .scope(observation, future)
                    .await
            }
            None => future.await,
        }
    }
}

#[derive(Clone)]
pub(crate) struct QuicEndpointOpenContext {
    protocol: QuicEndpointProtocol,
    caller: QuicEndpointCallerClass,
    generation: Option<OwnerGeneration>,
    key_seed: [u8; 32],
}

impl std::fmt::Debug for QuicEndpointOpenContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicEndpointOpenContext")
            .field("protocol", &self.protocol)
            .field("caller", &self.caller)
            .field("generation", &self.generation)
            .field("key_seed", &"<redacted>")
            .finish()
    }
}

impl QuicEndpointOpenContext {
    pub(crate) fn for_proxy(
        protocol: QuicEndpointProtocol,
        default_caller: QuicEndpointCallerClass,
        proxy: &ResidentProxyPlan,
        role: QuicEndpointIdentityRole,
        additional_identity: &[&[u8]],
    ) -> Self {
        let mut identity = IdentityDigest::new();
        identity.part(protocol.as_str().as_bytes());
        identity.part(role.as_str().as_bytes());
        let mut current = Some(proxy);
        while let Some(node) = current {
            identity.part(node.graph_id.as_bytes());
            identity.part(node.graph_link_hash.as_bytes());
            current = node.chain_parent.as_deref();
        }
        for part in additional_identity {
            identity.part(part);
        }
        let task = QUIC_ENDPOINT_TASK_OBSERVATION.try_with(|value| *value).ok();
        Self {
            protocol,
            caller: task.map_or(default_caller, |value| value.caller),
            generation: task
                .and_then(|value| value.generation)
                .or(Some(proxy.execution_plan().runtime_generation())),
            key_seed: identity.finish(),
        }
    }

    pub(crate) fn from_identity_parts(
        protocol: QuicEndpointProtocol,
        default_caller: QuicEndpointCallerClass,
        generation: OwnerGeneration,
        role: QuicEndpointIdentityRole,
        identity_parts: &[&[u8]],
    ) -> Self {
        let mut identity = IdentityDigest::new();
        identity.part(protocol.as_str().as_bytes());
        identity.part(role.as_str().as_bytes());
        for part in identity_parts {
            identity.part(part);
        }
        let task = QUIC_ENDPOINT_TASK_OBSERVATION.try_with(|value| *value).ok();
        Self {
            protocol,
            caller: task.map_or(default_caller, |value| value.caller),
            generation: task.and_then(|value| value.generation).or(Some(generation)),
            key_seed: identity.finish(),
        }
    }

    #[cfg(test)]
    pub(super) fn isolated_test(
        protocol: QuicEndpointProtocol,
        caller: QuicEndpointCallerClass,
        generation: Option<OwnerGeneration>,
        identity_material: &[u8],
    ) -> Self {
        let mut identity = IdentityDigest::new();
        identity.part(protocol.as_str().as_bytes());
        identity.part(identity_material);
        Self {
            protocol,
            caller,
            generation,
            key_seed: identity.finish(),
        }
    }

    pub(super) const fn protocol(&self) -> QuicEndpointProtocol {
        self.protocol
    }

    pub(super) fn finalize(
        self,
        remote: SocketAddr,
        bind: SocketAddr,
        mark: u32,
        underlay: QuicEndpointUnderlay,
        charge: QuicEndpointCharge,
        admission_charge: QuicEndpointCharge,
    ) -> QuicEndpointProvenance {
        let family = if remote.is_ipv4() {
            QuicEndpointAddressFamily::Ipv4
        } else {
            QuicEndpointAddressFamily::Ipv6
        };
        let mut identity = IdentityDigest::new();
        identity.part(&self.key_seed);
        identity.part(remote.to_string().as_bytes());
        identity.part(bind.to_string().as_bytes());
        identity.part(&mark.to_be_bytes());
        identity.part(family.as_str().as_bytes());
        identity.part(underlay.as_str().as_bytes());
        let redacted_identity =
            RedactedOwnerIdentity::new(QUIC_ENDPOINT_IDENTITY_NAMESPACE, identity.finish())
                .expect("static QUIC endpoint identity namespace is valid");
        QuicEndpointProvenance {
            protocol: self.protocol,
            caller: self.caller,
            generation: self.generation,
            redacted_identity,
            family,
            underlay,
            charge,
            admission_charge,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct QuicEndpointProvenance {
    pub protocol: QuicEndpointProtocol,
    pub caller: QuicEndpointCallerClass,
    pub generation: Option<OwnerGeneration>,
    pub redacted_identity: RedactedOwnerIdentity,
    pub family: QuicEndpointAddressFamily,
    pub underlay: QuicEndpointUnderlay,
    pub charge: QuicEndpointCharge,
    pub admission_charge: QuicEndpointCharge,
}

struct IdentityDigest(Sha256);

impl IdentityDigest {
    fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(QUIC_ENDPOINT_IDENTITY_DOMAIN);
        Self(digest)
    }

    fn part(&mut self, part: &[u8]) {
        self.0.update((part.len() as u64).to_be_bytes());
        self.0.update(part);
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}
