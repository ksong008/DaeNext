use crate::geodata::GeodataResolver as ResidentGeodataStore;
use crate::host_routing_plan::build_resident_userspace_routing_matcher_with_geodata;
use crate::plan::{
    ResidentDnsProxyGroupSelector, SharedResidentProxyGroupMap, build_resident_dataplane_plan,
    share_resident_proxy_groups,
};
use crate::transport::quic_endpoint::{
    ResidentDnsQuicEndpointPolicy, open_marked_quic_endpoint_for_remote,
};
use crate::{resident_dns_proxy_tcp_transport, resident_dns_proxy_udp_transport};
use bytes::Bytes;
use dae_config::Config;
use dae_datapath::{OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT};
use dae_dns::*;
use dae_outbound_core::{L4Proto, NetworkType};
use dae_resident_core::*;
use dae_resident_dns::runtime::routing::*;
use dae_resident_dns::runtime::transport::{route::*, wire::*, *};
use dae_resident_dns::runtime::validate_dns_response_for_request;
use dae_resident_dns::runtime::*;
use dae_resident_dns::*;
use dae_resident_plan::*;
use dae_resident_transport::{
    ObservedQuicEndpoint, ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure,
    ProxyDnsRequestStage, QuicEndpointCallerClass, QuicEndpointIdentityRole,
    QuicEndpointOpenContext, QuicEndpointProtocol, ResidentTransportOwnerRegistries,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex as AsyncMutex, Semaphore},
    time,
};

mod plan;
mod transport;

pub fn test_resident_dns_forwarder_cache() -> ResidentDnsForwarderCache {
    let udp_runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let udp_executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        udp_runtime.clone(),
        Arc::clone(&metrics),
    ));
    let owners = ResidentTransportOwnerRegistries::default();
    ResidentDnsForwarderCache::new_with_proxy_transports(
        udp_runtime.clone(),
        Arc::clone(&metrics),
        tokio::runtime::Handle::try_current().ok(),
        Arc::clone(&udp_executor),
        resident_dns_proxy_tcp_transport(owners.clone()),
        resident_dns_proxy_udp_transport(udp_runtime, metrics, udp_executor, owners),
        Arc::new(ResidentDnsQuicEndpointPolicy),
    )
}
