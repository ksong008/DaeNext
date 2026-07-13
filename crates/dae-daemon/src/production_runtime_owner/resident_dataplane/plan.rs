use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::AtomicI64};
use std::time::Duration;

use dae_config::{Config, DynamicFunctionValue, Function, Group, Param};
use dae_core_types::OutboundIndex;
use dae_datapath::TcpDialMode;
use dae_outbound::{
    Annotation, AnyTLSLink, Dialer, DialerGroup, DialerHealthSnapshot, DialerSet, Filter,
    FilterParam, HealthState, NetworkType, OutboundError, SelectionPolicy,
    http_proxy::{HttpProxyLink, HttpScheme},
    hysteria2::{
        DEFAULT_TRUE_QUIC_UDP_HOP_INTERVAL_MS, Hysteria2Link, build_port_hop_schedule,
        server_contract as hysteria2_server_contract,
    },
    juicity::JuicityLink,
    masque::{MasqueAuthentication, MasqueLink, MasqueTransport},
    parse_link_chain,
    shadowsocks::ss2022::{cipher_conf, validate_psk_list},
    shadowsocks::{CipherFamily, classify_cipher},
    shadowsocks::{
        ShadowsocksLink, ShadowsocksRLink, cipher_spec, shadowsocksr_stream_cipher_supported,
    },
    shared_transport::{
        DEFAULT_UTLS_FINGERPRINT, MeekRoundTripOptions, TlsFragmentOptions, UTLS_ALPN_H2,
        UTLS_ALPN_HTTP_1_1, UtlsFingerprint, ir, resolve_utls_client_hello_id,
        utls_fingerprint_default_alpn_protocols,
    },
    trojan::{TrojanLink, TrojanTransportType},
    tuic::TuicLink,
    vless::{VLESSLink, contract::is_xtls_rprx_vision_flow, password_to_key},
    vmess::VMessLink,
};
use serde_json::Value;
use url::Url;

use super::super::resident_routing::ResidentGeodataStore;
#[cfg(test)]
use super::RESIDENT_TCP_LATENCY_PROBE_TIMEOUT;
use super::{
    dns::{ResidentDnsPlan, build_resident_dns_plan},
    execution_link_hash, link_hash, redacted_link_source,
    resident_tcp_latency_probe_timeout_from_config,
    resolve_host_addrs_with_configured_fallback_dns_ttl,
};

mod executable_graph;

use executable_graph::{ResidentExecutableGraphDescriptor, resident_graph_identity};

mod udp_chain;
pub(super) use self::udp_chain::*;

mod model;
pub(super) use self::model::*;
mod transport_defaults;
use self::transport_defaults::*;
mod group_plan;
pub(super) use self::group_plan::*;
mod health_target;
pub(super) use self::health_target::*;
mod dataplane_builder;
pub(super) use self::dataplane_builder::*;
mod group_selector;
use self::group_selector::*;
mod check_plans;
use self::check_plans::*;
mod proxy_builders;
use self::proxy_builders::*;
mod public_helpers;
pub(super) use self::public_helpers::*;
mod fingerprint_dial;
use self::fingerprint_dial::*;
mod selection_policy;
use self::selection_policy::*;
mod link_parsing;
use self::link_parsing::*;
#[cfg(test)]
mod tests;
