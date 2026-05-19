use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use dae_control::{DomainRoutingOwnerSnapshot, DomainRoutingTracker};
use dae_datapath::{
    DEFAULT_NAT_TIMEOUT_MS, DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES, DNS_NAT_TIMEOUT_MS, MAX_RETRY,
    OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_USER_DEFINED_MIN, RouteDialTcpPlan,
    RouteDialTcpPlanInput, RouteRule, TcpDialMode, TcpDirectDialOptions, TcpDirectDialReport,
    TcpLoopbackListenerReport, UdpDirectPacketConn, UdpDirectSocketOptions, UdpDirectSocketReport,
    bind_loopback_tcp_listener, bind_loopback_tcp_listener_on_port, magic_network_bytes,
    magic_tcp_connect, route_dial_tcp_plan,
};
use dae_dns::{
    DnsCacheEntry, DnsCacheKey, DnsCacheStore, parse_message, validate_dns_response_for_request,
};
use dae_ebpf_support::{
    DaeParamInput, RuntimeMapInfo, build_dae_param, map_ids, map_info,
    open_live_loaded_tproxy_listen_socket_map_in_netns, open_map_fd,
    open_transparent_udp_socket_bound_in_netns, update_map_elem_bytes, write_param_aware_object,
};
use dae_netutil::parse_magic_network;
use dae_outbound::{Annotation, Dialer, DialerGroup, NetworkType, SelectionPolicy};
use serde_json::{Map, Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_STAGE50_ROOT: &str = "/tmp/dae-stage50-candidate";
const DEFAULT_STAGE50_SOURCE_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE50_PEER_SECTION: &str = "tc/dae0peer_ingress";
const DEFAULT_STAGE50_HOST_SECTION: &str = "tc/dae0_ingress";
const DEFAULT_STAGE50_LAN_SECTION: &str = "tc/lan_ingress_l2";
const DEFAULT_STAGE50_TPROXY_PORT: u16 = 35050;
const DEFAULT_STAGE50_DAE_NETNS_ID: u32 = 50;
const DEFAULT_STAGE50_TARGET_PORT: u16 = 18080;
const DEFAULT_STAGE50_CLIENT_IP: &str = "10.220.50.2";
const DEFAULT_STAGE50_LAN_GATEWAY_IP: &str = "10.220.50.1";
const DEFAULT_STAGE50_TARGET_IP: &str = "198.18.50.1";
const STAGE50_FILTER_PREF: &str = "49500";
const STAGE50_LAN_FILTER_PREF: &str = "49501";
const PRODUCTION_NETNS: &str = "daens";
const PRODUCTION_HOST_IFACE: &str = "dae0";
const PRODUCTION_PEER_IFACE: &str = "dae0peer";
const CLIENT_NETNS: &str = "dae50client";
const LAN_HOST_IFACE: &str = "dae50lan0";
const LAN_CLIENT_IFACE: &str = "dae50cli0";
const ROUTING_MAP_KERNEL_NAME: &str = "routing_map";
const LISTEN_SOCKET_MAP_KERNEL_NAME: &str = "listen_socket_m";
const MATCH_TYPE_FALLBACK: u8 = 10;
const OUTBOUND_STAGE50_PROXY: u8 = 2;
const TCP_PAYLOAD: &[u8] = b"stage50-tcp-ping";
const TCP_RESPONSE: &[u8] = b"stage50-tcp-ack";
const DEFAULT_STAGE51_ROOT: &str = "/tmp/dae-stage51-candidate";
const DEFAULT_STAGE51_TPROXY_PORT: u16 = 35151;
const DEFAULT_STAGE51_TARGET_PORT: u16 = 18081;
const DEFAULT_STAGE51_TARGET_IP: &str = "198.18.51.1";
const STAGE51_TCP_PAYLOAD: &[u8] = b"stage51-tcp-relay-ping";
const STAGE51_TCP_RESPONSE: &[u8] = b"stage51-tcp-relay-ack";
const DEFAULT_STAGE52_ROOT: &str = "/tmp/dae-stage52-candidate";
const DEFAULT_STAGE52_TPROXY_PORT: u16 = 35252;
const DEFAULT_STAGE52_TARGET_PORT: u16 = 18082;
const DEFAULT_STAGE52_TARGET_IP: &str = "198.18.52.1";
const DEFAULT_STAGE52_DOMAIN: &str = "127.0.0.1";
const STAGE52_TCP_PAYLOAD: &[u8] = b"stage52-route-group-ping";
const STAGE52_TCP_RESPONSE: &[u8] = b"stage52-route-group-ack";
const DEFAULT_STAGE53_ROOT: &str = "/tmp/dae-stage53-candidate";
const DEFAULT_STAGE53_TPROXY_PORT: u16 = 35353;
const DEFAULT_STAGE53_TARGET_PORT: u16 = 18083;
const DEFAULT_STAGE53_TARGET_IP: &str = "198.18.53.1";
const STAGE53_UDP_PAYLOAD: &[u8] = b"stage53-udp-tproxy-ping";
const STAGE53_UDP_RESPONSE: &[u8] = b"stage53-udp-tproxy-ack";
const DEFAULT_STAGE54_ROOT: &str = "/tmp/dae-stage54-candidate";
const DEFAULT_STAGE54_TPROXY_PORT: u16 = 35454;
const DEFAULT_STAGE54_TARGET_PORT: u16 = 53;
const DEFAULT_STAGE54_TARGET_IP: &str = "8.8.8.8";
const DEFAULT_STAGE54_UPSTREAM_IP: &str = "127.0.0.1";
const DEFAULT_STAGE54_UPSTREAM_PORT: u16 = 10530;
const DEFAULT_STAGE54_QNAME: &str = "stage54.example.";
const STAGE54_RESPONSE_IP_TEXT: &str = "203.0.113.54";
const STAGE54_RESPONSE_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 54);
const STAGE54_RESPONSE_TTL: u32 = 30;

pub(crate) fn run_stage50_active_tcp_tproxy_ingress_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage50Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage50_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "active_tcp_tproxy_ingress_smoke_passed",
    )
}

pub(crate) fn run_stage51_active_tcp_route_dial_relay_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage51Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage51_report(&opts);
    output_with_execution_status(
        report,
        opts.base.execute_smoke,
        "active_tcp_relay_smoke_passed",
    )
}

pub(crate) fn run_stage52_active_tcp_route_table_group_relay_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage52Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage52_report(&opts);
    output_with_execution_status(
        report,
        opts.base.execute_smoke,
        "active_tcp_route_table_group_relay_smoke_passed",
    )
}

pub(crate) fn run_stage53_active_udp_tproxy_endpoint_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage53Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage53_report(&opts);
    output_with_execution_status(
        report,
        opts.base.execute_smoke,
        "active_udp_tproxy_smoke_passed",
    )
}

pub(crate) fn run_stage54_active_dns_tproxy_cache_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage54Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage54_report(&opts);
    output_with_execution_status(
        report,
        opts.base.execute_smoke,
        "active_dns_tproxy_smoke_passed",
    )
}

fn output_with_execution_status(report: Value, executed: bool, pass_key: &str) -> RunnerOutput {
    let passed = report[pass_key].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if executed && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

mod attach_maps;
mod client_cleanup;
mod dns_probes;
mod json_models;
mod options_stage50;
mod options_stage51;
mod options_stage52;
mod options_stage53;
mod options_stage54;
mod stage50;
mod stage51;
mod stage52;
mod stage53;
mod stage54;
mod tcp_probes;
mod topology;
mod udp_probes;
mod utils;

use attach_maps::*;
use client_cleanup::*;
use dns_probes::*;
use json_models::*;
use options_stage50::*;
use options_stage51::*;
use options_stage52::*;
use options_stage53::*;
use options_stage54::*;
use stage50::*;
use stage51::*;
use stage52::*;
use stage53::*;
use stage54::*;
use tcp_probes::*;
use topology::*;
use udp_probes::*;
use utils::*;
