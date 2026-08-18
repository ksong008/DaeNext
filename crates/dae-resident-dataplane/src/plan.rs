use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::AtomicI64};
use std::time::{Duration, Instant};

use dae_config::{Config, DynamicFunctionValue, Function, Group, Param};
use dae_core_types::OutboundIndex;
use dae_datapath::TcpDialMode;
use dae_outbound::types::NETWORK_TYPE_COLLECTION_COUNT;
use dae_outbound::{
    Annotation, AnyTLSLink, Dialer, DialerGroup, DialerHealthSnapshot, DialerSet, Filter,
    FilterParam, HealthState, NetworkType, OutboundError, SelectionPolicy,
    http_proxy::{HttpProxyLink, HttpScheme},
    hysteria2::{
        HYSTERIA2_MIN_PORT_HOP_INTERVAL, Hysteria2Link, build_port_hop_schedule,
        parse_hysteria2_bandwidth, server_contract as hysteria2_server_contract,
    },
    juicity::JuicityLink,
    parse_link_chain,
    shadowsocks::ss2022::{cipher_conf, validate_psk_list},
    shadowsocks::{CipherFamily, classify_cipher},
    shadowsocks::{
        ShadowsocksLink, ShadowsocksRLink, cipher_spec, shadowsocksr_stream_cipher_supported,
    },
    shared_transport::{
        DEFAULT_UTLS_FINGERPRINT, GrpcMode, MeekRoundTripOptions, TlsFragmentOptions, UTLS_ALPN_H2,
        UTLS_ALPN_HTTP_1_1, UtlsFingerprint, ir, parse_optional_ech_config_list,
        parse_optional_mldsa65_verify_key, resolve_utls_client_hello_id,
        utls_fingerprint_default_alpn_protocols,
    },
    trojan::{TrojanLink, TrojanTransportType},
    tuic::TuicLink,
    vless::{
        VLESSLink, VlessEncryptionClient, contract::is_xtls_rprx_vision_flow, password_to_key,
    },
    vmess::VMessLink,
};
use serde_json::{Value, json};
use url::Url;

#[cfg(test)]
use super::RESIDENT_TCP_LATENCY_PROBE_TIMEOUT;
use super::geodata::GeodataResolver as ResidentGeodataStore;
use super::{
    ResidentRuntimeResourceConfig,
    dns::{ResidentDnsPlan, build_resident_dns_plan_with_refresh_interval},
    execution_link_hash, link_hash, redacted_link_source, resident_tcp_health_probe_timeout,
    resident_tcp_latency_probe_timeout_from_config,
    resolve_host_addrs_with_configured_fallback_dns_ttl,
};
#[cfg(test)]
use dae_outbound::{hysteria2::Hysteria2CongestionConfig, shared_transport::Mldsa65VerifyKey};

pub(crate) use dae_resident_plan::*;
mod transport_defaults;
use self::transport_defaults::*;
mod group_plan;
pub(super) use self::group_plan::*;
mod probe_plan;
pub(super) use self::probe_plan::*;
mod group_health_bootstrap;
use self::group_health_bootstrap::*;
mod health_target;
pub(super) use self::health_target::*;
mod dataplane_builder;
#[cfg(any(test, feature = "benchmark-support"))]
pub(crate) use self::dataplane_builder::ResidentDataplanePlan;
#[cfg(test)]
pub(crate) use self::dataplane_builder::build_resident_manual_probe_plans;
pub use self::dataplane_builder::{
    ResidentPreparedDataplane, build_resident_prepared_dataplane_with_geodata,
};
pub(crate) use self::dataplane_builder::{
    ResidentProtocolOwnerSpecs, build_resident_dataplane_plan,
    build_resident_manual_probe_plans_for_helper,
};
mod group_selector;
use self::group_selector::*;
mod check_plans;
use self::check_plans::*;
mod proxy_builders;
use self::proxy_builders::*;
mod public_helpers;
pub(super) use self::public_helpers::*;
mod source_admission;
pub use self::source_admission::{ResidentNodeSourceAdmission, resident_node_source_admissions};
mod fingerprint_dial;
use self::fingerprint_dial::*;
mod selection_policy;
use self::selection_policy::*;
mod link_parsing;
use self::link_parsing::*;
#[cfg(test)]
mod tests;
