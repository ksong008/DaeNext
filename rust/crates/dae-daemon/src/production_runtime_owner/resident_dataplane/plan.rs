use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dae_config::{Config, DynamicFunctionValue, Function, Group, Param};
use dae_core_types::OutboundIndex;
use dae_datapath::TcpDialMode;
use dae_outbound::{
    Annotation, AnyTLSLink, Dialer, DialerGroup, DialerSet, Filter, FilterParam, NetworkType,
    SelectionPolicy,
    http_proxy::{HttpProxyLink, HttpScheme},
    hysteria2::{
        DEFAULT_TRUE_QUIC_UDP_HOP_INTERVAL_MS, Hysteria2Link, build_port_hop_schedule,
        server_contract as hysteria2_server_contract,
    },
    juicity::JuicityLink,
    parse_link_chain,
    shadowsocks::ss2022::{cipher_conf, validate_psk_list},
    shadowsocks::{CipherFamily, classify_cipher},
    shadowsocks::{ShadowsocksLink, cipher_spec},
    shared_transport::{MeekRoundTripOptions, UtlsFingerprint, ir, resolve_utls_client_hello_id},
    trojan::{TrojanLink, TrojanTransportType},
    tuic::TuicLink,
    vless::{VLESSLink, password_to_key},
    vmess::VMessLink,
};
use serde_json::Value;
use url::Url;

use super::{
    XTLS_RPRX_VISION,
    dns::{ResidentDnsPlan, build_resident_dns_plan},
    link_hash, redacted_link_source,
};

mod executable_graph;

use executable_graph::{ResidentExecutableGraphDescriptor, resident_graph_identity};

include!("plan/model.rs");
include!("plan/transport_defaults.rs");
include!("plan/group_plan.rs");
include!("plan/dataplane_builder.rs");
include!("plan/group_selector.rs");
include!("plan/check_plans.rs");
include!("plan/proxy_builders.rs");
include!("plan/public_helpers.rs");
include!("plan/fingerprint_dial.rs");
include!("plan/selection_policy.rs");
include!("plan/link_parsing.rs");
include!("plan/tests.rs");
