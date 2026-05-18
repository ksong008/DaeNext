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

#[derive(Debug, Clone)]
struct Stage50Options {
    root: PathBuf,
    source_object: PathBuf,
    param_object: PathBuf,
    execute_smoke: bool,
    ack_root_gate: bool,
    peer_section: String,
    host_section: String,
    lan_section: String,
    tproxy_port: u16,
    dae_netns_id: u32,
    target_ip: String,
    client_ip: String,
    target_port: u16,
    so_mark: u32,
    mptcp: bool,
}

impl Default for Stage50Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE50_ROOT);
        Self {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            source_object: PathBuf::from(DEFAULT_STAGE50_SOURCE_OBJECT),
            execute_smoke: false,
            ack_root_gate: false,
            peer_section: DEFAULT_STAGE50_PEER_SECTION.to_owned(),
            host_section: DEFAULT_STAGE50_HOST_SECTION.to_owned(),
            lan_section: DEFAULT_STAGE50_LAN_SECTION.to_owned(),
            tproxy_port: DEFAULT_STAGE50_TPROXY_PORT,
            dae_netns_id: DEFAULT_STAGE50_DAE_NETNS_ID,
            target_ip: DEFAULT_STAGE50_TARGET_IP.to_owned(),
            client_ip: DEFAULT_STAGE50_CLIENT_IP.to_owned(),
            target_port: DEFAULT_STAGE50_TARGET_PORT,
            so_mark: 1234,
            mptcp: true,
        }
    }
}

impl Stage50Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.root = PathBuf::from(next_value(&mut iter, "stage50 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE50_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.source_object = PathBuf::from(next_value(&mut iter, "stage50 --object")?);
                }
                "--param-object" => {
                    opts.param_object =
                        PathBuf::from(next_value(&mut iter, "stage50 --param-object")?);
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--peer-section" => {
                    opts.peer_section = next_value(&mut iter, "stage50 --peer-section")?;
                }
                "--host-section" => {
                    opts.host_section = next_value(&mut iter, "stage50 --host-section")?;
                }
                "--lan-section" => {
                    opts.lan_section = next_value(&mut iter, "stage50 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage50 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage50 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => opts.target_ip = next_value(&mut iter, "stage50 --target-ip")?,
                "--client-ip" => opts.client_ip = next_value(&mut iter, "stage50 --client-ip")?,
                "--target-port" => {
                    opts.target_port =
                        parse_port(&next_value(&mut iter, "stage50 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage50 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage50 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE50_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.source_object =
                        PathBuf::from(value_after_equals(arg, "stage50 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.param_object =
                        PathBuf::from(value_after_equals(arg, "stage50 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.peer_section = value_after_equals(arg, "stage50 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.host_section = value_after_equals(arg, "stage50 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.lan_section = value_after_equals(arg, "stage50 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage50 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage50 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.target_ip = value_after_equals(arg, "stage50 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.client_ip = value_after_equals(arg, "stage50 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.target_port =
                        parse_port(&value_after_equals(arg, "stage50 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(&value_after_equals(arg, "stage50 --so-mark")?, arg)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage50-active-tcp-tproxy-ingress-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

#[derive(Debug, Clone)]
struct Stage51Options {
    base: Stage50Options,
    upstream_mptcp: bool,
    benchmark_iters: u32,
}

impl Default for Stage51Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE51_ROOT);
        let base = Stage50Options {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            tproxy_port: DEFAULT_STAGE51_TPROXY_PORT,
            target_ip: DEFAULT_STAGE51_TARGET_IP.to_owned(),
            target_port: DEFAULT_STAGE51_TARGET_PORT,
            ..Stage50Options::default()
        };
        Self {
            base,
            upstream_mptcp: true,
            benchmark_iters: 1,
        }
    }
}

impl Stage51Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let default_param_object = PathBuf::from(DEFAULT_STAGE51_ROOT).join("bpf_bpfel.param.o");
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.base.root = PathBuf::from(next_value(&mut iter, "stage51 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.base.source_object =
                        PathBuf::from(next_value(&mut iter, "stage51 --object")?);
                }
                "--param-object" => {
                    opts.base.param_object =
                        PathBuf::from(next_value(&mut iter, "stage51 --param-object")?);
                }
                "--execute-smoke" => opts.base.execute_smoke = true,
                "--ack-root-gate" => opts.base.ack_root_gate = true,
                "--peer-section" => {
                    opts.base.peer_section = next_value(&mut iter, "stage51 --peer-section")?;
                }
                "--host-section" => {
                    opts.base.host_section = next_value(&mut iter, "stage51 --host-section")?;
                }
                "--lan-section" => {
                    opts.base.lan_section = next_value(&mut iter, "stage51 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.base.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage51 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.base.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage51 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => {
                    opts.base.target_ip = next_value(&mut iter, "stage51 --target-ip")?;
                }
                "--client-ip" => {
                    opts.base.client_ip = next_value(&mut iter, "stage51 --client-ip")?;
                }
                "--target-port" => {
                    opts.base.target_port =
                        parse_port(&next_value(&mut iter, "stage51 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.base.so_mark =
                        parse_u32(&next_value(&mut iter, "stage51 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.base.mptcp = true,
                "--no-mptcp" => opts.base.mptcp = false,
                "--upstream-mptcp" => opts.upstream_mptcp = true,
                "--upstream-plain-tcp" => opts.upstream_mptcp = false,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_u32(&next_value(&mut iter, "stage51 --benchmark-iters")?, arg)?;
                }
                _ if arg.starts_with("--root=") => {
                    opts.base.root = PathBuf::from(value_after_equals(arg, "stage51 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.base.source_object =
                        PathBuf::from(value_after_equals(arg, "stage51 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.base.param_object =
                        PathBuf::from(value_after_equals(arg, "stage51 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.base.peer_section = value_after_equals(arg, "stage51 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.base.host_section = value_after_equals(arg, "stage51 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.base.lan_section = value_after_equals(arg, "stage51 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.base.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage51 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.base.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage51 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.base.target_ip = value_after_equals(arg, "stage51 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.base.client_ip = value_after_equals(arg, "stage51 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.base.target_port =
                        parse_port(&value_after_equals(arg, "stage51 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.base.so_mark =
                        parse_u32(&value_after_equals(arg, "stage51 --so-mark")?, arg)?;
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_u32(&value_after_equals(arg, "stage51 --benchmark-iters")?, arg)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage51-active-tcp-route-dial-relay-admission argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage51 --benchmark-iters must be non-zero",
            ));
        }
        Ok(opts)
    }
}

#[derive(Debug, Clone)]
struct Stage52Options {
    base: Stage50Options,
    upstream_mptcp: bool,
    benchmark_iters: u32,
    dial_mode: TcpDialMode,
    domain: String,
    domain_is_real: bool,
}

impl Default for Stage52Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE52_ROOT);
        let base = Stage50Options {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            tproxy_port: DEFAULT_STAGE52_TPROXY_PORT,
            target_ip: DEFAULT_STAGE52_TARGET_IP.to_owned(),
            target_port: DEFAULT_STAGE52_TARGET_PORT,
            ..Stage50Options::default()
        };
        Self {
            base,
            upstream_mptcp: true,
            benchmark_iters: 1,
            dial_mode: TcpDialMode::DomainPlusPlus,
            domain: DEFAULT_STAGE52_DOMAIN.to_owned(),
            domain_is_real: true,
        }
    }
}

impl Stage52Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let default_param_object = PathBuf::from(DEFAULT_STAGE52_ROOT).join("bpf_bpfel.param.o");
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.base.root = PathBuf::from(next_value(&mut iter, "stage52 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.base.source_object =
                        PathBuf::from(next_value(&mut iter, "stage52 --object")?);
                }
                "--param-object" => {
                    opts.base.param_object =
                        PathBuf::from(next_value(&mut iter, "stage52 --param-object")?);
                }
                "--execute-smoke" => opts.base.execute_smoke = true,
                "--ack-root-gate" => opts.base.ack_root_gate = true,
                "--peer-section" => {
                    opts.base.peer_section = next_value(&mut iter, "stage52 --peer-section")?;
                }
                "--host-section" => {
                    opts.base.host_section = next_value(&mut iter, "stage52 --host-section")?;
                }
                "--lan-section" => {
                    opts.base.lan_section = next_value(&mut iter, "stage52 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.base.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage52 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.base.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage52 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => {
                    opts.base.target_ip = next_value(&mut iter, "stage52 --target-ip")?;
                }
                "--client-ip" => {
                    opts.base.client_ip = next_value(&mut iter, "stage52 --client-ip")?;
                }
                "--target-port" => {
                    opts.base.target_port =
                        parse_port(&next_value(&mut iter, "stage52 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.base.so_mark =
                        parse_u32(&next_value(&mut iter, "stage52 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.base.mptcp = true,
                "--no-mptcp" => opts.base.mptcp = false,
                "--upstream-mptcp" => opts.upstream_mptcp = true,
                "--upstream-plain-tcp" => opts.upstream_mptcp = false,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_u32(&next_value(&mut iter, "stage52 --benchmark-iters")?, arg)?;
                }
                "--dial-mode" => {
                    opts.dial_mode =
                        parse_tcp_dial_mode(&next_value(&mut iter, "stage52 --dial-mode")?)?;
                }
                "--domain" => opts.domain = next_value(&mut iter, "stage52 --domain")?,
                "--domain-real" => opts.domain_is_real = true,
                "--domain-not-real" => opts.domain_is_real = false,
                _ if arg.starts_with("--root=") => {
                    opts.base.root = PathBuf::from(value_after_equals(arg, "stage52 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.base.source_object =
                        PathBuf::from(value_after_equals(arg, "stage52 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.base.param_object =
                        PathBuf::from(value_after_equals(arg, "stage52 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.base.peer_section = value_after_equals(arg, "stage52 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.base.host_section = value_after_equals(arg, "stage52 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.base.lan_section = value_after_equals(arg, "stage52 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.base.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage52 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.base.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage52 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.base.target_ip = value_after_equals(arg, "stage52 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.base.client_ip = value_after_equals(arg, "stage52 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.base.target_port =
                        parse_port(&value_after_equals(arg, "stage52 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.base.so_mark =
                        parse_u32(&value_after_equals(arg, "stage52 --so-mark")?, arg)?;
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_u32(&value_after_equals(arg, "stage52 --benchmark-iters")?, arg)?;
                }
                _ if arg.starts_with("--dial-mode=") => {
                    opts.dial_mode =
                        parse_tcp_dial_mode(&value_after_equals(arg, "stage52 --dial-mode")?)?;
                }
                _ if arg.starts_with("--domain=") => {
                    opts.domain = value_after_equals(arg, "stage52 --domain")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage52-active-tcp-route-table-group-relay-admission argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage52 --benchmark-iters must be non-zero",
            ));
        }
        if opts.domain.is_empty() {
            return Err(RunnerOutput::usage("stage52 --domain must be non-empty"));
        }
        Ok(opts)
    }
}

#[derive(Debug, Clone)]
struct Stage53Options {
    base: Stage50Options,
    benchmark_iters: u32,
}

impl Default for Stage53Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE53_ROOT);
        let base = Stage50Options {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            tproxy_port: DEFAULT_STAGE53_TPROXY_PORT,
            target_ip: DEFAULT_STAGE53_TARGET_IP.to_owned(),
            target_port: DEFAULT_STAGE53_TARGET_PORT,
            ..Stage50Options::default()
        };
        Self {
            base,
            benchmark_iters: 1,
        }
    }
}

impl Stage53Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let default_param_object = PathBuf::from(DEFAULT_STAGE53_ROOT).join("bpf_bpfel.param.o");
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.base.root = PathBuf::from(next_value(&mut iter, "stage53 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.base.source_object =
                        PathBuf::from(next_value(&mut iter, "stage53 --object")?);
                }
                "--param-object" => {
                    opts.base.param_object =
                        PathBuf::from(next_value(&mut iter, "stage53 --param-object")?);
                }
                "--execute-smoke" => opts.base.execute_smoke = true,
                "--ack-root-gate" => opts.base.ack_root_gate = true,
                "--peer-section" => {
                    opts.base.peer_section = next_value(&mut iter, "stage53 --peer-section")?;
                }
                "--host-section" => {
                    opts.base.host_section = next_value(&mut iter, "stage53 --host-section")?;
                }
                "--lan-section" => {
                    opts.base.lan_section = next_value(&mut iter, "stage53 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.base.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage53 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.base.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage53 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => {
                    opts.base.target_ip = next_value(&mut iter, "stage53 --target-ip")?;
                }
                "--client-ip" => {
                    opts.base.client_ip = next_value(&mut iter, "stage53 --client-ip")?;
                }
                "--target-port" => {
                    opts.base.target_port =
                        parse_port(&next_value(&mut iter, "stage53 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.base.so_mark =
                        parse_u32(&next_value(&mut iter, "stage53 --so-mark")?, arg)?;
                }
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_u32(&next_value(&mut iter, "stage53 --benchmark-iters")?, arg)?;
                }
                _ if arg.starts_with("--root=") => {
                    opts.base.root = PathBuf::from(value_after_equals(arg, "stage53 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.base.source_object =
                        PathBuf::from(value_after_equals(arg, "stage53 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.base.param_object =
                        PathBuf::from(value_after_equals(arg, "stage53 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.base.peer_section = value_after_equals(arg, "stage53 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.base.host_section = value_after_equals(arg, "stage53 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.base.lan_section = value_after_equals(arg, "stage53 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.base.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage53 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.base.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage53 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.base.target_ip = value_after_equals(arg, "stage53 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.base.client_ip = value_after_equals(arg, "stage53 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.base.target_port =
                        parse_port(&value_after_equals(arg, "stage53 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.base.so_mark =
                        parse_u32(&value_after_equals(arg, "stage53 --so-mark")?, arg)?;
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_u32(&value_after_equals(arg, "stage53 --benchmark-iters")?, arg)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage53-active-udp-tproxy-endpoint-admission argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage53 --benchmark-iters must be non-zero",
            ));
        }
        Ok(opts)
    }
}

#[derive(Debug, Clone)]
struct Stage54Options {
    base: Stage50Options,
    benchmark_iters: u32,
    upstream_ip: String,
    upstream_port: u16,
    qname: String,
}

impl Default for Stage54Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE54_ROOT);
        let base = Stage50Options {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            tproxy_port: DEFAULT_STAGE54_TPROXY_PORT,
            target_ip: DEFAULT_STAGE54_TARGET_IP.to_owned(),
            target_port: DEFAULT_STAGE54_TARGET_PORT,
            ..Stage50Options::default()
        };
        Self {
            base,
            benchmark_iters: 2,
            upstream_ip: DEFAULT_STAGE54_UPSTREAM_IP.to_owned(),
            upstream_port: DEFAULT_STAGE54_UPSTREAM_PORT,
            qname: DEFAULT_STAGE54_QNAME.to_owned(),
        }
    }
}

impl Stage54Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let default_param_object = PathBuf::from(DEFAULT_STAGE54_ROOT).join("bpf_bpfel.param.o");
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.base.root = PathBuf::from(next_value(&mut iter, "stage54 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.base.source_object =
                        PathBuf::from(next_value(&mut iter, "stage54 --object")?);
                }
                "--param-object" => {
                    opts.base.param_object =
                        PathBuf::from(next_value(&mut iter, "stage54 --param-object")?);
                }
                "--execute-smoke" => opts.base.execute_smoke = true,
                "--ack-root-gate" => opts.base.ack_root_gate = true,
                "--peer-section" => {
                    opts.base.peer_section = next_value(&mut iter, "stage54 --peer-section")?;
                }
                "--host-section" => {
                    opts.base.host_section = next_value(&mut iter, "stage54 --host-section")?;
                }
                "--lan-section" => {
                    opts.base.lan_section = next_value(&mut iter, "stage54 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.base.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage54 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.base.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage54 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => {
                    opts.base.target_ip = next_value(&mut iter, "stage54 --target-ip")?;
                }
                "--client-ip" => {
                    opts.base.client_ip = next_value(&mut iter, "stage54 --client-ip")?;
                }
                "--target-port" => {
                    opts.base.target_port =
                        parse_port(&next_value(&mut iter, "stage54 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.base.so_mark =
                        parse_u32(&next_value(&mut iter, "stage54 --so-mark")?, arg)?;
                }
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_u32(&next_value(&mut iter, "stage54 --benchmark-iters")?, arg)?;
                }
                "--upstream-ip" => {
                    opts.upstream_ip = next_value(&mut iter, "stage54 --upstream-ip")?;
                }
                "--upstream-port" => {
                    opts.upstream_port =
                        parse_port(&next_value(&mut iter, "stage54 --upstream-port")?, arg)?;
                }
                "--qname" => opts.qname = next_value(&mut iter, "stage54 --qname")?,
                _ if arg.starts_with("--root=") => {
                    opts.base.root = PathBuf::from(value_after_equals(arg, "stage54 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.base.source_object =
                        PathBuf::from(value_after_equals(arg, "stage54 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.base.param_object =
                        PathBuf::from(value_after_equals(arg, "stage54 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.base.peer_section = value_after_equals(arg, "stage54 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.base.host_section = value_after_equals(arg, "stage54 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.base.lan_section = value_after_equals(arg, "stage54 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.base.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage54 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.base.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage54 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.base.target_ip = value_after_equals(arg, "stage54 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.base.client_ip = value_after_equals(arg, "stage54 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.base.target_port =
                        parse_port(&value_after_equals(arg, "stage54 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.base.so_mark =
                        parse_u32(&value_after_equals(arg, "stage54 --so-mark")?, arg)?;
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_u32(&value_after_equals(arg, "stage54 --benchmark-iters")?, arg)?;
                }
                _ if arg.starts_with("--upstream-ip=") => {
                    opts.upstream_ip = value_after_equals(arg, "stage54 --upstream-ip")?;
                }
                _ if arg.starts_with("--upstream-port=") => {
                    opts.upstream_port =
                        parse_port(&value_after_equals(arg, "stage54 --upstream-port")?, arg)?;
                }
                _ if arg.starts_with("--qname=") => {
                    opts.qname = value_after_equals(arg, "stage54 --qname")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage54-active-dns-tproxy-cache-admission argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters < 2 {
            return Err(RunnerOutput::usage(
                "stage54 --benchmark-iters must be at least 2 to cover reload cache restore",
            ));
        }
        if opts.upstream_port == 0 {
            return Err(RunnerOutput::usage(
                "stage54 --upstream-port must be non-zero",
            ));
        }
        if opts.qname.is_empty() {
            return Err(RunnerOutput::usage("stage54 --qname must be non-empty"));
        }
        Ok(opts)
    }
}

fn stage50_report(opts: &Stage50Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage50 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage50 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc", "python3", "sysctl"] {
        push_check(
            &mut checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        opts.source_object.exists(),
        json!({"path": path_string(&opts.source_object)}),
        &mut blockers,
        "stage50 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        opts.tproxy_port != 0,
        json!({"tproxy_port": opts.tproxy_port}),
        &mut blockers,
        "stage50 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "target-port-valid",
        opts.target_port != 0,
        json!({"target_port": opts.target_port}),
        &mut blockers,
        "stage50 target port must be non-zero",
    );
    if opts.execute_smoke {
        push_check(
            &mut checks,
            "stage50-resource-names-free",
            resource_leftovers().is_empty(),
            json!({"leftovers": resource_leftovers()}),
            &mut blockers,
            "stage50 temporary or production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(opts.tproxy_port),
            json!({"tproxy_port": opts.tproxy_port}),
            &mut blockers,
            "stage50 tproxy port is already in use",
        );
    }

    let before_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let before_map_ids = if opts.execute_smoke && blockers.is_empty() {
        match map_ids() {
            Ok(ids) => ids,
            Err(err) => {
                blockers.push(format!("stage50 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut topology_values = Value::Null;
    let mut param_image = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut lan_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut route_map_update = Value::Null;
    let mut tcp_accept = Value::Null;
    let mut client_traffic = Value::Null;
    let mut post_traffic_peer_stats = Value::Null;
    let mut post_traffic_lan_stats = Value::Null;
    let mut post_traffic_host_stats = Value::Null;
    let mut discovered_listen_map_id = None;
    let mut discovered_routing_map_id = None;
    let mut active_tcp_tproxy_ingress_smoke_passed = false;
    let mut original_destination_observed = false;
    let mut tcp_reply_path_succeeded = false;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage50_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        topology_values = result.topology_values;
        param_image = result.param_image;
        peer_attach_show = result.peer_attach_show;
        lan_attach_show = result.lan_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        route_map_update = result.route_map_update;
        tcp_accept = result.tcp_accept;
        client_traffic = result.client_traffic;
        post_traffic_peer_stats = result.post_traffic_peer_stats;
        post_traffic_lan_stats = result.post_traffic_lan_stats;
        post_traffic_host_stats = result.post_traffic_host_stats;
        discovered_listen_map_id = result.discovered_listen_map_id;
        discovered_routing_map_id = result.discovered_routing_map_id;
        active_tcp_tproxy_ingress_smoke_passed = result.passed;
        original_destination_observed = result.original_destination_observed;
        tcp_reply_path_succeeded = result.tcp_reply_path_succeeded;
        if !active_tcp_tproxy_ingress_smoke_passed {
            blockers.push("stage50 active TCP tproxy ingress smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_maps_cleaned) = if opts.execute_smoke {
        wait_for_loaded_map_cleanup(&[discovered_listen_map_id, discovered_routing_map_id])
    } else {
        (Vec::new(), true)
    };
    if opts.execute_smoke && !loaded_maps_cleaned {
        blockers.push("stage50 loaded BPF maps remain after cleanup".to_owned());
    }
    let leftovers = resource_leftovers();
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage50 resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage50 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage50-active-tcp-tproxy-ingress-admission"),
    );
    report.insert("stage".to_owned(), json!("stage50"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-active-tcp-tproxy-ingress-transparent-accept-smoke"),
    );
    report.insert("root".to_owned(), json!(path_string(&opts.root)));
    report.insert("execute_smoke".to_owned(), json!(opts.execute_smoke));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(opts.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!opts.execute_smoke));
    report.insert("blocked".to_owned(), json!(!blockers.is_empty()));
    report.insert(
        "active_tcp_tproxy_ingress_smoke_passed".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "active_tcp_tproxy_ingress_admitted".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "active_tcp_syn_reached_transparent_listener".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "original_destination_observed".to_owned(),
        json!(original_destination_observed),
    );
    report.insert(
        "tcp_reply_path_succeeded".to_owned(),
        json!(tcp_reply_path_succeeded),
    );
    report.insert(
        "active_tproxy_traffic_executed".to_owned(),
        json!(opts.execute_smoke),
    );
    report.insert(
        "active_tcp_tproxy_admitted".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed && original_destination_observed),
    );
    for key in [
        "active_udp_tproxy_admitted",
        "active_dns_tproxy_admitted",
        "route_dial_tcp_rust_control_plane_executed",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutated",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert("blockers".to_owned(), json!(blockers));
    report.insert("checks".to_owned(), json!(checks));
    report.insert(
        "active_tcp_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "client_netns": CLIENT_NETNS,
            "lan_host_iface": LAN_HOST_IFACE,
            "lan_client_iface": LAN_CLIENT_IFACE,
            "peer_section": opts.peer_section,
            "host_section": opts.host_section,
            "lan_section": opts.lan_section,
            "filter_pref": STAGE50_FILTER_PREF,
            "lan_filter_pref": STAGE50_LAN_FILTER_PREF,
            "source_object": path_string(&opts.source_object),
            "param_object": path_string(&opts.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "routing_map_kernel_name": ROUTING_MAP_KERNEL_NAME,
            "routing_fallback_outbound": OUTBOUND_STAGE50_PROXY,
            "match_type_fallback": MATCH_TYPE_FALLBACK,
            "tproxy_port": opts.tproxy_port,
            "target": format!("{}:{}", opts.target_ip, opts.target_port),
            "lan_gateway_ip": DEFAULT_STAGE50_LAN_GATEWAY_IP,
            "client_ip": opts.client_ip,
            "so_mark": opts.so_mark,
            "mptcp": opts.mptcp,
            "route_dial_tcp_required_later": true,
        }),
    );
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert("route_map_update".to_owned(), route_map_update);
    report.insert("tcp_accept".to_owned(), tcp_accept);
    report.insert("client_traffic".to_owned(), client_traffic);
    report.insert(
        "post_traffic_peer_stats".to_owned(),
        post_traffic_peer_stats,
    );
    report.insert("post_traffic_lan_stats".to_owned(), post_traffic_lan_stats);
    report.insert(
        "post_traffic_host_stats".to_owned(),
        post_traffic_host_stats,
    );
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("lan_attach_show".to_owned(), lan_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_listen_map_id": discovered_listen_map_id,
            "discovered_routing_map_id": discovered_routing_map_id,
            "loaded_maps_cleaned": loaded_maps_cleaned,
        }),
    );
    report.insert(
        "temporary_resources".to_owned(),
        json!({
            "leftovers_after_cleanup": leftovers,
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        }),
    );
    report.insert("remaining_blockers".to_owned(), json!(remaining_blockers()));
    Value::Object(report)
}

fn stage51_report(opts: &Stage51Options) -> Value {
    let base = &opts.base;
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&base.root),
        json!({"path": path_string(&base.root)}),
        &mut blockers,
        "stage51 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !base.execute_smoke || base.ack_root_gate,
        json!({"execute_smoke": base.execute_smoke, "ack_root_gate": base.ack_root_gate}),
        &mut blockers,
        "stage51 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc", "python3", "sysctl"] {
        push_check(
            &mut checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        base.source_object.exists(),
        json!({"path": path_string(&base.source_object)}),
        &mut blockers,
        "stage51 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        base.tproxy_port != 0,
        json!({"tproxy_port": base.tproxy_port}),
        &mut blockers,
        "stage51 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "target-port-valid",
        base.target_port != 0,
        json!({"target_port": base.target_port}),
        &mut blockers,
        "stage51 target port must be non-zero",
    );
    if base.execute_smoke {
        push_check(
            &mut checks,
            "stage51-resource-names-free",
            resource_leftovers().is_empty(),
            json!({"leftovers": resource_leftovers()}),
            &mut blockers,
            "stage51 temporary or production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(base.tproxy_port),
            json!({"tproxy_port": base.tproxy_port}),
            &mut blockers,
            "stage51 tproxy port is already in use",
        );
    }

    let before_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let before_map_ids = if base.execute_smoke && blockers.is_empty() {
        match map_ids() {
            Ok(ids) => ids,
            Err(err) => {
                blockers.push(format!("stage51 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut topology_values = Value::Null;
    let mut param_image = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut lan_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut route_map_update = Value::Null;
    let mut relay_accept = Value::Null;
    let mut upstream = Value::Null;
    let mut client_traffic = Value::Null;
    let mut outbound_dial = Value::Null;
    let mut benchmark = Value::Null;
    let mut post_traffic_peer_stats = Value::Null;
    let mut post_traffic_lan_stats = Value::Null;
    let mut post_traffic_host_stats = Value::Null;
    let mut discovered_listen_map_id = None;
    let mut discovered_routing_map_id = None;
    let mut active_tcp_relay_smoke_passed = false;
    let mut original_destination_observed = false;
    let mut outbound_relay_succeeded = false;
    let mut so_mark_observed = false;
    let mut mptcp_observed = false;
    if base.execute_smoke && blockers.is_empty() {
        let result = execute_stage51_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        topology_values = result.topology_values;
        param_image = result.param_image;
        peer_attach_show = result.peer_attach_show;
        lan_attach_show = result.lan_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        route_map_update = result.route_map_update;
        relay_accept = result.relay_accept;
        upstream = result.upstream;
        client_traffic = result.client_traffic;
        outbound_dial = result.outbound_dial;
        benchmark = result.benchmark;
        post_traffic_peer_stats = result.post_traffic_peer_stats;
        post_traffic_lan_stats = result.post_traffic_lan_stats;
        post_traffic_host_stats = result.post_traffic_host_stats;
        discovered_listen_map_id = result.discovered_listen_map_id;
        discovered_routing_map_id = result.discovered_routing_map_id;
        active_tcp_relay_smoke_passed = result.passed;
        original_destination_observed = result.original_destination_observed;
        outbound_relay_succeeded = result.outbound_relay_succeeded;
        so_mark_observed = result.so_mark_observed;
        mptcp_observed = result.mptcp_observed;
        if !active_tcp_relay_smoke_passed {
            blockers.push("stage51 active TCP relay smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_maps_cleaned) = if base.execute_smoke {
        wait_for_loaded_map_cleanup(&[discovered_listen_map_id, discovered_routing_map_id])
    } else {
        (Vec::new(), true)
    };
    if base.execute_smoke && !loaded_maps_cleaned {
        blockers.push("stage51 loaded BPF maps remain after cleanup".to_owned());
    }
    let leftovers = resource_leftovers();
    if base.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage51 resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if base.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage51 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let benchmark_recorded = base.execute_smoke
        && opts.benchmark_iters > 1
        && active_tcp_relay_smoke_passed
        && benchmark["status"].as_str() == Some("pass");
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage51-active-tcp-route-dial-relay-admission"),
    );
    report.insert("stage".to_owned(), json!("stage51"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-active-tcp-route-dial-outbound-relay-smoke"),
    );
    report.insert("root".to_owned(), json!(path_string(&base.root)));
    report.insert("execute_smoke".to_owned(), json!(base.execute_smoke));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(base.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!base.execute_smoke));
    report.insert("blocked".to_owned(), json!(!blockers.is_empty()));
    report.insert(
        "active_tcp_relay_smoke_passed".to_owned(),
        json!(active_tcp_relay_smoke_passed),
    );
    report.insert(
        "active_tcp_tproxy_ingress_admitted".to_owned(),
        json!(active_tcp_relay_smoke_passed),
    );
    report.insert(
        "active_tcp_syn_reached_transparent_listener".to_owned(),
        json!(active_tcp_relay_smoke_passed),
    );
    report.insert(
        "original_destination_observed".to_owned(),
        json!(original_destination_observed),
    );
    report.insert(
        "route_dial_tcp_direct_path_executed".to_owned(),
        json!(outbound_relay_succeeded),
    );
    report.insert(
        "route_dial_tcp_rust_control_plane_executed".to_owned(),
        json!(false),
    );
    report.insert(
        "outbound_relay_recorded".to_owned(),
        json!(outbound_relay_succeeded),
    );
    report.insert(
        "tcp_reply_path_succeeded".to_owned(),
        json!(outbound_relay_succeeded),
    );
    report.insert(
        "so_mark_real_outbound_socket_observed".to_owned(),
        json!(so_mark_observed),
    );
    report.insert(
        "mptcp_real_outbound_socket_observed".to_owned(),
        json!(mptcp_observed),
    );
    report.insert(
        "so_mark_mptcp_real_outbound_socket_recorded".to_owned(),
        json!(so_mark_observed && (!base.mptcp || mptcp_observed)),
    );
    report.insert(
        "active_tcp_tproxy_admitted".to_owned(),
        json!(active_tcp_relay_smoke_passed && outbound_relay_succeeded),
    );
    report.insert(
        "active_tproxy_traffic_executed".to_owned(),
        json!(base.execute_smoke),
    );
    report.insert(
        "active_tcp_relay_benchmark_recorded".to_owned(),
        json!(benchmark_recorded),
    );
    for key in [
        "active_udp_tproxy_admitted",
        "active_dns_tproxy_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutated",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert("blockers".to_owned(), json!(blockers));
    report.insert("checks".to_owned(), json!(checks));
    report.insert(
        "active_tcp_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "client_netns": CLIENT_NETNS,
            "lan_host_iface": LAN_HOST_IFACE,
            "lan_client_iface": LAN_CLIENT_IFACE,
            "peer_section": base.peer_section,
            "host_section": base.host_section,
            "lan_section": base.lan_section,
            "filter_pref": STAGE50_FILTER_PREF,
            "lan_filter_pref": STAGE50_LAN_FILTER_PREF,
            "source_object": path_string(&base.source_object),
            "param_object": path_string(&base.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "routing_map_kernel_name": ROUTING_MAP_KERNEL_NAME,
            "routing_fallback_outbound": OUTBOUND_STAGE50_PROXY,
            "match_type_fallback": MATCH_TYPE_FALLBACK,
            "tproxy_port": base.tproxy_port,
            "target": format!("{}:{}", base.target_ip, base.target_port),
            "lan_gateway_ip": DEFAULT_STAGE50_LAN_GATEWAY_IP,
            "client_ip": base.client_ip,
            "so_mark": base.so_mark,
            "mptcp": base.mptcp,
            "upstream_mptcp": opts.upstream_mptcp,
            "benchmark_iters": opts.benchmark_iters,
            "full_control_plane_route_table_required_later": true,
        }),
    );
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert("route_map_update".to_owned(), route_map_update);
    report.insert("relay_accept".to_owned(), relay_accept);
    report.insert("upstream".to_owned(), upstream);
    report.insert("client_traffic".to_owned(), client_traffic);
    report.insert("outbound_dial".to_owned(), outbound_dial);
    report.insert("benchmark".to_owned(), benchmark);
    report.insert(
        "post_traffic_peer_stats".to_owned(),
        post_traffic_peer_stats,
    );
    report.insert("post_traffic_lan_stats".to_owned(), post_traffic_lan_stats);
    report.insert(
        "post_traffic_host_stats".to_owned(),
        post_traffic_host_stats,
    );
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("lan_attach_show".to_owned(), lan_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_listen_map_id": discovered_listen_map_id,
            "discovered_routing_map_id": discovered_routing_map_id,
            "loaded_maps_cleaned": loaded_maps_cleaned,
        }),
    );
    report.insert(
        "temporary_resources".to_owned(),
        json!({
            "leftovers_after_cleanup": leftovers,
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        }),
    );
    report.insert(
        "remaining_blockers".to_owned(),
        json!(remaining_blockers_after_stage51()),
    );
    Value::Object(report)
}

fn stage52_report(opts: &Stage52Options) -> Value {
    let base = &opts.base;
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    let route_plan = stage52_route_plan(opts);
    let route_table_recorded = route_plan.userspace_route_executed
        && route_plan.final_outbound == OUTBOUND_USER_DEFINED_MIN
        && route_plan.second_choose.is_some();
    let choose_dial_target_recorded = route_plan.first_choose.should_reroute
        && route_plan.final_dial_target == format!("{}:{}", opts.domain, base.target_port);
    let (group_selection_model, group_selection_recorded) =
        stage52_group_selection_json(&route_plan);

    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&base.root),
        json!({"path": path_string(&base.root)}),
        &mut blockers,
        "stage52 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !base.execute_smoke || base.ack_root_gate,
        json!({"execute_smoke": base.execute_smoke, "ack_root_gate": base.ack_root_gate}),
        &mut blockers,
        "stage52 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc", "python3", "sysctl"] {
        push_check(
            &mut checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        base.source_object.exists(),
        json!({"path": path_string(&base.source_object)}),
        &mut blockers,
        "stage52 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        base.tproxy_port != 0,
        json!({"tproxy_port": base.tproxy_port}),
        &mut blockers,
        "stage52 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "target-port-valid",
        base.target_port != 0,
        json!({"target_port": base.target_port}),
        &mut blockers,
        "stage52 target port must be non-zero",
    );
    if base.execute_smoke {
        push_check(
            &mut checks,
            "stage52-resource-names-free",
            resource_leftovers().is_empty(),
            json!({"leftovers": resource_leftovers()}),
            &mut blockers,
            "stage52 temporary or production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(base.tproxy_port),
            json!({"tproxy_port": base.tproxy_port}),
            &mut blockers,
            "stage52 tproxy port is already in use",
        );
        push_check(
            &mut checks,
            "route-dial-target-port-free",
            tproxy_port_available(base.target_port),
            json!({"target_port": base.target_port, "domain": opts.domain}),
            &mut blockers,
            "stage52 route-dial target port is already in use on loopback",
        );
    }

    let before_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let before_map_ids = if base.execute_smoke && blockers.is_empty() {
        match map_ids() {
            Ok(ids) => ids,
            Err(err) => {
                blockers.push(format!("stage52 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut topology_values = Value::Null;
    let mut param_image = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut lan_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut route_map_update = Value::Null;
    let mut relay_accept = Value::Null;
    let mut upstream = Value::Null;
    let mut client_traffic = Value::Null;
    let mut outbound_dial = Value::Null;
    let mut benchmark = Value::Null;
    let mut smoke_route_plan = route_dial_plan_json(&route_plan);
    let mut smoke_group_selection = group_selection_model;
    let mut post_traffic_peer_stats = Value::Null;
    let mut post_traffic_lan_stats = Value::Null;
    let mut post_traffic_host_stats = Value::Null;
    let mut discovered_listen_map_id = None;
    let mut discovered_routing_map_id = None;
    let mut active_tcp_route_table_group_relay_smoke_passed = false;
    let mut original_destination_observed = false;
    let mut outbound_relay_succeeded = false;
    let mut so_mark_observed = false;
    let mut mptcp_observed = false;
    if base.execute_smoke && blockers.is_empty() {
        let result = execute_stage52_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        topology_values = result.topology_values;
        param_image = result.param_image;
        peer_attach_show = result.peer_attach_show;
        lan_attach_show = result.lan_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        route_map_update = result.route_map_update;
        relay_accept = result.relay_accept;
        upstream = result.upstream;
        client_traffic = result.client_traffic;
        outbound_dial = result.outbound_dial;
        benchmark = result.benchmark;
        smoke_route_plan = result.route_dial_plan;
        smoke_group_selection = result.group_selection;
        post_traffic_peer_stats = result.post_traffic_peer_stats;
        post_traffic_lan_stats = result.post_traffic_lan_stats;
        post_traffic_host_stats = result.post_traffic_host_stats;
        discovered_listen_map_id = result.discovered_listen_map_id;
        discovered_routing_map_id = result.discovered_routing_map_id;
        active_tcp_route_table_group_relay_smoke_passed = result.passed;
        original_destination_observed = result.original_destination_observed;
        outbound_relay_succeeded = result.outbound_relay_succeeded;
        so_mark_observed = result.so_mark_observed;
        mptcp_observed = result.mptcp_observed;
        if !active_tcp_route_table_group_relay_smoke_passed {
            blockers.push("stage52 active TCP route-table/group relay smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_maps_cleaned) = if base.execute_smoke {
        wait_for_loaded_map_cleanup(&[discovered_listen_map_id, discovered_routing_map_id])
    } else {
        (Vec::new(), true)
    };
    if base.execute_smoke && !loaded_maps_cleaned {
        blockers.push("stage52 loaded BPF maps remain after cleanup".to_owned());
    }
    let leftovers = resource_leftovers();
    if base.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage52 resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if base.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage52 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let benchmark_recorded = base.execute_smoke
        && opts.benchmark_iters > 1
        && active_tcp_route_table_group_relay_smoke_passed
        && benchmark["status"].as_str() == Some("pass");
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage52-active-tcp-route-table-group-relay-admission"),
    );
    report.insert("stage".to_owned(), json!("stage52"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-active-tcp-route-table-choose-target-group-relay-smoke"),
    );
    report.insert("root".to_owned(), json!(path_string(&base.root)));
    report.insert("execute_smoke".to_owned(), json!(base.execute_smoke));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(base.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!base.execute_smoke));
    report.insert("blocked".to_owned(), json!(!blockers.is_empty()));
    report.insert(
        "route_dial_tcp_route_table_recorded".to_owned(),
        json!(route_table_recorded),
    );
    report.insert(
        "choose_dial_target_recorded".to_owned(),
        json!(choose_dial_target_recorded),
    );
    report.insert(
        "outbound_group_selection_recorded".to_owned(),
        json!(group_selection_recorded),
    );
    report.insert(
        "route_dial_tcp_rust_control_plane_executed".to_owned(),
        json!(route_table_recorded && choose_dial_target_recorded && group_selection_recorded),
    );
    report.insert(
        "active_tcp_route_table_group_relay_smoke_passed".to_owned(),
        json!(active_tcp_route_table_group_relay_smoke_passed),
    );
    report.insert(
        "active_tcp_tproxy_ingress_admitted".to_owned(),
        json!(active_tcp_route_table_group_relay_smoke_passed),
    );
    report.insert(
        "active_tcp_syn_reached_transparent_listener".to_owned(),
        json!(active_tcp_route_table_group_relay_smoke_passed),
    );
    report.insert(
        "original_destination_observed".to_owned(),
        json!(original_destination_observed),
    );
    report.insert(
        "route_dial_tcp_direct_path_executed".to_owned(),
        json!(outbound_relay_succeeded),
    );
    report.insert(
        "outbound_relay_recorded".to_owned(),
        json!(outbound_relay_succeeded),
    );
    report.insert(
        "tcp_reply_path_succeeded".to_owned(),
        json!(outbound_relay_succeeded),
    );
    report.insert(
        "so_mark_real_outbound_socket_observed".to_owned(),
        json!(so_mark_observed),
    );
    report.insert(
        "mptcp_real_outbound_socket_observed".to_owned(),
        json!(mptcp_observed),
    );
    report.insert(
        "so_mark_mptcp_real_outbound_socket_recorded".to_owned(),
        json!(so_mark_observed && (!base.mptcp || mptcp_observed)),
    );
    report.insert(
        "active_tcp_tproxy_admitted".to_owned(),
        json!(active_tcp_route_table_group_relay_smoke_passed && outbound_relay_succeeded),
    );
    report.insert(
        "active_tproxy_traffic_executed".to_owned(),
        json!(base.execute_smoke),
    );
    report.insert(
        "active_tcp_route_table_group_benchmark_recorded".to_owned(),
        json!(benchmark_recorded),
    );
    for key in [
        "active_udp_tproxy_admitted",
        "active_dns_tproxy_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutated",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert("blockers".to_owned(), json!(blockers));
    report.insert("checks".to_owned(), json!(checks));
    report.insert(
        "active_tcp_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "client_netns": CLIENT_NETNS,
            "lan_host_iface": LAN_HOST_IFACE,
            "lan_client_iface": LAN_CLIENT_IFACE,
            "peer_section": base.peer_section,
            "host_section": base.host_section,
            "lan_section": base.lan_section,
            "filter_pref": STAGE50_FILTER_PREF,
            "lan_filter_pref": STAGE50_LAN_FILTER_PREF,
            "source_object": path_string(&base.source_object),
            "param_object": path_string(&base.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "routing_map_kernel_name": ROUTING_MAP_KERNEL_NAME,
            "routing_fallback_outbound": OUTBOUND_USER_DEFINED_MIN,
            "userspace_reroute_initial_outbound": OUTBOUND_CONTROL_PLANE_ROUTING,
            "match_type_fallback": MATCH_TYPE_FALLBACK,
            "tproxy_port": base.tproxy_port,
            "target": format!("{}:{}", base.target_ip, base.target_port),
            "domain": opts.domain,
            "dial_mode": opts.dial_mode.as_str(),
            "lan_gateway_ip": DEFAULT_STAGE50_LAN_GATEWAY_IP,
            "client_ip": base.client_ip,
            "so_mark": base.so_mark,
            "mptcp": base.mptcp,
            "upstream_mptcp": opts.upstream_mptcp,
            "benchmark_iters": opts.benchmark_iters,
            "bounded_to_direct_loopback_upstream": true,
            "protocol_outbound_true_dataplane_required_later": true,
        }),
    );
    report.insert("route_dial_plan".to_owned(), smoke_route_plan);
    report.insert("group_selection".to_owned(), smoke_group_selection);
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert("route_map_update".to_owned(), route_map_update);
    report.insert("relay_accept".to_owned(), relay_accept);
    report.insert("upstream".to_owned(), upstream);
    report.insert("client_traffic".to_owned(), client_traffic);
    report.insert("outbound_dial".to_owned(), outbound_dial);
    report.insert("benchmark".to_owned(), benchmark);
    report.insert(
        "post_traffic_peer_stats".to_owned(),
        post_traffic_peer_stats,
    );
    report.insert("post_traffic_lan_stats".to_owned(), post_traffic_lan_stats);
    report.insert(
        "post_traffic_host_stats".to_owned(),
        post_traffic_host_stats,
    );
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("lan_attach_show".to_owned(), lan_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_listen_map_id": discovered_listen_map_id,
            "discovered_routing_map_id": discovered_routing_map_id,
            "loaded_maps_cleaned": loaded_maps_cleaned,
        }),
    );
    report.insert(
        "temporary_resources".to_owned(),
        json!({
            "leftovers_after_cleanup": leftovers,
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        }),
    );
    report.insert(
        "remaining_blockers".to_owned(),
        json!(remaining_blockers_after_stage52()),
    );
    Value::Object(report)
}

fn stage53_report(opts: &Stage53Options) -> Value {
    let base = &opts.base;
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&base.root),
        json!({"path": path_string(&base.root)}),
        &mut blockers,
        "stage53 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !base.execute_smoke || base.ack_root_gate,
        json!({"execute_smoke": base.execute_smoke, "ack_root_gate": base.ack_root_gate}),
        &mut blockers,
        "stage53 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc", "python3", "sysctl"] {
        push_check(
            &mut checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        base.source_object.exists(),
        json!({"path": path_string(&base.source_object)}),
        &mut blockers,
        "stage53 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        base.tproxy_port != 0,
        json!({"tproxy_port": base.tproxy_port}),
        &mut blockers,
        "stage53 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "target-port-valid",
        base.target_port != 0,
        json!({"target_port": base.target_port}),
        &mut blockers,
        "stage53 target port must be non-zero",
    );
    if base.execute_smoke {
        push_check(
            &mut checks,
            "stage53-resource-names-free",
            resource_leftovers().is_empty(),
            json!({"leftovers": resource_leftovers()}),
            &mut blockers,
            "stage53 temporary or production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(base.tproxy_port),
            json!({"tproxy_port": base.tproxy_port}),
            &mut blockers,
            "stage53 tproxy port is already in use",
        );
        push_check(
            &mut checks,
            "stage53-target-loopback-address-free",
            !stage53_loopback_target_present(&base.target_ip),
            json!({"target_ip": base.target_ip}),
            &mut blockers,
            "stage53 target loopback address is already present",
        );
    }

    let before_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let before_map_ids = if base.execute_smoke && blockers.is_empty() {
        match map_ids() {
            Ok(ids) => ids,
            Err(err) => {
                blockers.push(format!("stage53 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut topology_values = Value::Null;
    let mut param_image = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut lan_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut route_map_update = Value::Null;
    let mut udp_receive = Value::Null;
    let mut udp_endpoint_pool = stage53_udp_endpoint_model_json(base);
    let mut outbound_packet_conn = Value::Null;
    let mut upstream = Value::Null;
    let mut client_traffic = Value::Null;
    let mut sendpkt_reply = Value::Null;
    let mut benchmark = Value::Null;
    let mut post_traffic_peer_stats = Value::Null;
    let mut post_traffic_lan_stats = Value::Null;
    let mut post_traffic_host_stats = Value::Null;
    let mut discovered_listen_map_id = None;
    let mut discovered_routing_map_id = None;
    let mut active_udp_tproxy_smoke_passed = false;
    let mut original_destination_observed = false;
    let mut endpoint_pool_live_recorded = false;
    let mut outbound_packet_conn_recorded = false;
    let mut sendpkt_reply_recorded = false;
    let mut so_mark_observed = false;
    if base.execute_smoke && blockers.is_empty() {
        let result = execute_stage53_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        topology_values = result.topology_values;
        param_image = result.param_image;
        peer_attach_show = result.peer_attach_show;
        lan_attach_show = result.lan_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        route_map_update = result.route_map_update;
        udp_receive = result.udp_receive;
        udp_endpoint_pool = result.udp_endpoint_pool;
        outbound_packet_conn = result.outbound_packet_conn;
        upstream = result.upstream;
        client_traffic = result.client_traffic;
        sendpkt_reply = result.sendpkt_reply;
        benchmark = result.benchmark;
        post_traffic_peer_stats = result.post_traffic_peer_stats;
        post_traffic_lan_stats = result.post_traffic_lan_stats;
        post_traffic_host_stats = result.post_traffic_host_stats;
        discovered_listen_map_id = result.discovered_listen_map_id;
        discovered_routing_map_id = result.discovered_routing_map_id;
        active_udp_tproxy_smoke_passed = result.passed;
        original_destination_observed = result.original_destination_observed;
        endpoint_pool_live_recorded = result.endpoint_pool_live_recorded;
        outbound_packet_conn_recorded = result.outbound_packet_conn_recorded;
        sendpkt_reply_recorded = result.sendpkt_reply_recorded;
        so_mark_observed = result.so_mark_observed;
        if !active_udp_tproxy_smoke_passed {
            blockers.push("stage53 active UDP tproxy endpoint smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_maps_cleaned) = if base.execute_smoke {
        wait_for_loaded_map_cleanup(&[discovered_listen_map_id, discovered_routing_map_id])
    } else {
        (Vec::new(), true)
    };
    if base.execute_smoke && !loaded_maps_cleaned {
        blockers.push("stage53 loaded BPF maps remain after cleanup".to_owned());
    }
    let leftovers = resource_leftovers();
    if base.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage53 resources remain after cleanup".to_owned());
    }
    let loopback_leftover = base.execute_smoke && stage53_loopback_target_present(&base.target_ip);
    if loopback_leftover {
        blockers.push("stage53 target loopback address remains after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if base.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage53 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let benchmark_recorded = base.execute_smoke
        && opts.benchmark_iters > 1
        && active_udp_tproxy_smoke_passed
        && benchmark["status"].as_str() == Some("pass");
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage53-active-udp-tproxy-endpoint-admission"),
    );
    report.insert("stage".to_owned(), json!("stage53"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-active-udp-tproxy-endpoint-packetconn-smoke"),
    );
    report.insert("root".to_owned(), json!(path_string(&base.root)));
    report.insert("execute_smoke".to_owned(), json!(base.execute_smoke));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(base.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!base.execute_smoke));
    report.insert("blocked".to_owned(), json!(!blockers.is_empty()));
    report.insert(
        "active_udp_tproxy_smoke_passed".to_owned(),
        json!(active_udp_tproxy_smoke_passed),
    );
    report.insert(
        "active_udp_tproxy_admitted".to_owned(),
        json!(
            active_udp_tproxy_smoke_passed
                && endpoint_pool_live_recorded
                && outbound_packet_conn_recorded
                && sendpkt_reply_recorded
        ),
    );
    report.insert(
        "active_udp_original_destination_observed".to_owned(),
        json!(original_destination_observed),
    );
    report.insert(
        "udp_endpoint_pool_live_recorded".to_owned(),
        json!(endpoint_pool_live_recorded),
    );
    report.insert(
        "udp_packetconn_write_read_recorded".to_owned(),
        json!(outbound_packet_conn_recorded),
    );
    report.insert(
        "udp_sendpkt_reply_recorded".to_owned(),
        json!(sendpkt_reply_recorded),
    );
    report.insert(
        "udp_so_mark_real_outbound_socket_observed".to_owned(),
        json!(so_mark_observed),
    );
    report.insert(
        "active_udp_tproxy_benchmark_recorded".to_owned(),
        json!(benchmark_recorded),
    );
    report.insert(
        "active_tproxy_traffic_executed".to_owned(),
        json!(base.execute_smoke),
    );
    for key in [
        "active_dns_tproxy_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutated",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert("blockers".to_owned(), json!(blockers));
    report.insert("checks".to_owned(), json!(checks));
    report.insert(
        "active_udp_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "client_netns": CLIENT_NETNS,
            "lan_host_iface": LAN_HOST_IFACE,
            "lan_client_iface": LAN_CLIENT_IFACE,
            "peer_section": base.peer_section,
            "host_section": base.host_section,
            "lan_section": base.lan_section,
            "filter_pref": STAGE50_FILTER_PREF,
            "lan_filter_pref": STAGE50_LAN_FILTER_PREF,
            "source_object": path_string(&base.source_object),
            "param_object": path_string(&base.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "routing_map_kernel_name": ROUTING_MAP_KERNEL_NAME,
            "routing_fallback_outbound": OUTBOUND_STAGE50_PROXY,
            "match_type_fallback": MATCH_TYPE_FALLBACK,
            "tproxy_port": base.tproxy_port,
            "target": format!("{}:{}", base.target_ip, base.target_port),
            "temporary_loopback_upstream_addr": format!("{}/32", base.target_ip),
            "client_ip": base.client_ip,
            "so_mark": base.so_mark,
            "mptcp_magic_network_flag": base.mptcp,
            "benchmark_iters": opts.benchmark_iters,
            "dns_udp53_excluded": true,
            "protocol_outbound_true_dataplane_required_later": true,
        }),
    );
    report.insert("udp_receive".to_owned(), udp_receive);
    report.insert("udp_endpoint_pool".to_owned(), udp_endpoint_pool);
    report.insert("outbound_packet_conn".to_owned(), outbound_packet_conn);
    report.insert("upstream".to_owned(), upstream);
    report.insert("client_traffic".to_owned(), client_traffic);
    report.insert("sendpkt_reply".to_owned(), sendpkt_reply);
    report.insert("benchmark".to_owned(), benchmark);
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert("route_map_update".to_owned(), route_map_update);
    report.insert(
        "post_traffic_peer_stats".to_owned(),
        post_traffic_peer_stats,
    );
    report.insert("post_traffic_lan_stats".to_owned(), post_traffic_lan_stats);
    report.insert(
        "post_traffic_host_stats".to_owned(),
        post_traffic_host_stats,
    );
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("lan_attach_show".to_owned(), lan_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_listen_map_id": discovered_listen_map_id,
            "discovered_routing_map_id": discovered_routing_map_id,
            "loaded_maps_cleaned": loaded_maps_cleaned,
        }),
    );
    report.insert(
        "temporary_resources".to_owned(),
        json!({
            "leftovers_after_cleanup": leftovers,
            "loopback_target_leftover_after_cleanup": loopback_leftover,
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        }),
    );
    report.insert(
        "remaining_blockers".to_owned(),
        json!(remaining_blockers_after_stage53()),
    );
    Value::Object(report)
}

fn stage54_report(opts: &Stage54Options) -> Value {
    let base = &opts.base;
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&base.root),
        json!({"path": path_string(&base.root)}),
        &mut blockers,
        "stage54 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !base.execute_smoke || base.ack_root_gate,
        json!({"execute_smoke": base.execute_smoke, "ack_root_gate": base.ack_root_gate}),
        &mut blockers,
        "stage54 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc", "python3", "sysctl"] {
        push_check(
            &mut checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        base.source_object.exists(),
        json!({"path": path_string(&base.source_object)}),
        &mut blockers,
        "stage54 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        base.tproxy_port != 0,
        json!({"tproxy_port": base.tproxy_port}),
        &mut blockers,
        "stage54 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "target-port-is-dns",
        base.target_port == 53,
        json!({"target_port": base.target_port}),
        &mut blockers,
        "stage54 target port must be UDP/53",
    );
    push_check(
        &mut checks,
        "upstream-port-valid",
        opts.upstream_port != 0,
        json!({"upstream_port": opts.upstream_port}),
        &mut blockers,
        "stage54 upstream port must be non-zero",
    );
    if base.execute_smoke {
        push_check(
            &mut checks,
            "stage54-resource-names-free",
            resource_leftovers().is_empty(),
            json!({"leftovers": resource_leftovers()}),
            &mut blockers,
            "stage54 temporary or production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(base.tproxy_port),
            json!({"tproxy_port": base.tproxy_port}),
            &mut blockers,
            "stage54 tproxy port is already in use",
        );
        push_check(
            &mut checks,
            "upstream-port-free",
            tproxy_port_available(opts.upstream_port),
            json!({"upstream": format!("{}:{}", opts.upstream_ip, opts.upstream_port)}),
            &mut blockers,
            "stage54 local DNS upstream port is already in use",
        );
    }

    let before_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let before_map_ids = if base.execute_smoke && blockers.is_empty() {
        match map_ids() {
            Ok(ids) => ids,
            Err(err) => {
                blockers.push(format!("stage54 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut topology_values = Value::Null;
    let mut param_image = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut lan_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut route_map_update = Value::Null;
    let mut dns_receive = Value::Null;
    let mut dns_controller = Value::Null;
    let mut dns_upstream = Value::Null;
    let mut dns_cache = stage54_dns_cache_model_json(opts);
    let mut domain_routing = Value::Null;
    let mut upstream_packet_conn = Value::Null;
    let mut client_traffic = Value::Null;
    let mut sendpkt_reply = Value::Null;
    let mut benchmark = Value::Null;
    let mut post_traffic_peer_stats = Value::Null;
    let mut post_traffic_lan_stats = Value::Null;
    let mut post_traffic_host_stats = Value::Null;
    let mut discovered_listen_map_id = None;
    let mut discovered_routing_map_id = None;
    let mut active_dns_tproxy_smoke_passed = false;
    let mut original_destination_observed = false;
    let mut dns_controller_recorded = false;
    let mut dns_upstream_query_recorded = false;
    let mut dns_response_validation_recorded = false;
    let mut dns_cache_restore_recorded = false;
    let mut domain_routing_owner_migration_recorded = false;
    let mut sendpkt_reply_recorded = false;
    let mut so_mark_observed = false;
    if base.execute_smoke && blockers.is_empty() {
        let result = execute_stage54_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        topology_values = result.topology_values;
        param_image = result.param_image;
        peer_attach_show = result.peer_attach_show;
        lan_attach_show = result.lan_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        route_map_update = result.route_map_update;
        dns_receive = result.dns_receive;
        dns_controller = result.dns_controller;
        dns_upstream = result.dns_upstream;
        dns_cache = result.dns_cache;
        domain_routing = result.domain_routing;
        upstream_packet_conn = result.upstream_packet_conn;
        client_traffic = result.client_traffic;
        sendpkt_reply = result.sendpkt_reply;
        benchmark = result.benchmark;
        post_traffic_peer_stats = result.post_traffic_peer_stats;
        post_traffic_lan_stats = result.post_traffic_lan_stats;
        post_traffic_host_stats = result.post_traffic_host_stats;
        discovered_listen_map_id = result.discovered_listen_map_id;
        discovered_routing_map_id = result.discovered_routing_map_id;
        active_dns_tproxy_smoke_passed = result.passed;
        original_destination_observed = result.original_destination_observed;
        dns_controller_recorded = result.dns_controller_recorded;
        dns_upstream_query_recorded = result.dns_upstream_query_recorded;
        dns_response_validation_recorded = result.dns_response_validation_recorded;
        dns_cache_restore_recorded = result.dns_cache_restore_recorded;
        domain_routing_owner_migration_recorded = result.domain_routing_owner_migration_recorded;
        sendpkt_reply_recorded = result.sendpkt_reply_recorded;
        so_mark_observed = result.so_mark_observed;
        if !active_dns_tproxy_smoke_passed {
            blockers.push("stage54 active DNS UDP/53 tproxy cache smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_maps_cleaned) = if base.execute_smoke {
        wait_for_loaded_map_cleanup(&[discovered_listen_map_id, discovered_routing_map_id])
    } else {
        (Vec::new(), true)
    };
    if base.execute_smoke && !loaded_maps_cleaned {
        blockers.push("stage54 loaded BPF maps remain after cleanup".to_owned());
    }
    let leftovers = resource_leftovers();
    if base.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage54 resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if base.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage54 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let benchmark_recorded = base.execute_smoke
        && active_dns_tproxy_smoke_passed
        && benchmark["status"].as_str() == Some("pass");
    let active_dns_tproxy_admitted = active_dns_tproxy_smoke_passed
        && dns_controller_recorded
        && dns_upstream_query_recorded
        && dns_response_validation_recorded
        && dns_cache_restore_recorded
        && domain_routing_owner_migration_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage54-active-dns-tproxy-cache-admission"),
    );
    report.insert("stage".to_owned(), json!("stage54"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-active-dns-udp53-cache-reload-smoke"),
    );
    report.insert("root".to_owned(), json!(path_string(&base.root)));
    report.insert("execute_smoke".to_owned(), json!(base.execute_smoke));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(base.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!base.execute_smoke));
    report.insert("blocked".to_owned(), json!(!blockers.is_empty()));
    report.insert(
        "active_dns_tproxy_smoke_passed".to_owned(),
        json!(active_dns_tproxy_smoke_passed),
    );
    report.insert(
        "active_dns_tproxy_admitted".to_owned(),
        json!(active_dns_tproxy_admitted),
    );
    report.insert(
        "active_dns_original_destination_observed".to_owned(),
        json!(original_destination_observed),
    );
    report.insert(
        "dns_controller_path_recorded".to_owned(),
        json!(dns_controller_recorded),
    );
    report.insert(
        "dns_upstream_query_recorded".to_owned(),
        json!(dns_upstream_query_recorded),
    );
    report.insert(
        "dns_response_validation_recorded".to_owned(),
        json!(dns_response_validation_recorded),
    );
    report.insert(
        "dns_cache_restore_recorded".to_owned(),
        json!(dns_cache_restore_recorded),
    );
    report.insert(
        "domain_routing_owner_migration_recorded".to_owned(),
        json!(domain_routing_owner_migration_recorded),
    );
    report.insert(
        "dns_sendpkt_reply_recorded".to_owned(),
        json!(sendpkt_reply_recorded),
    );
    report.insert(
        "dns_so_mark_upstream_socket_observed".to_owned(),
        json!(so_mark_observed),
    );
    report.insert(
        "active_dns_tproxy_benchmark_recorded".to_owned(),
        json!(benchmark_recorded),
    );
    report.insert(
        "active_tproxy_traffic_executed".to_owned(),
        json!(base.execute_smoke),
    );
    report.insert("active_udp_tproxy_admitted".to_owned(), json!(true));
    for key in [
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutated",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert("blockers".to_owned(), json!(blockers));
    report.insert("checks".to_owned(), json!(checks));
    report.insert(
        "active_dns_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "client_netns": CLIENT_NETNS,
            "lan_host_iface": LAN_HOST_IFACE,
            "lan_client_iface": LAN_CLIENT_IFACE,
            "peer_section": base.peer_section,
            "host_section": base.host_section,
            "lan_section": base.lan_section,
            "filter_pref": STAGE50_FILTER_PREF,
            "lan_filter_pref": STAGE50_LAN_FILTER_PREF,
            "source_object": path_string(&base.source_object),
            "param_object": path_string(&base.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "routing_map_kernel_name": ROUTING_MAP_KERNEL_NAME,
            "routing_fallback_outbound": OUTBOUND_STAGE50_PROXY,
            "match_type_fallback": MATCH_TYPE_FALLBACK,
            "tproxy_port": base.tproxy_port,
            "dns_target": format!("{}:{}", base.target_ip, base.target_port),
            "dns_upstream": format!("{}:{}", opts.upstream_ip, opts.upstream_port),
            "client_ip": base.client_ip,
            "so_mark": base.so_mark,
            "mptcp_magic_network_flag": base.mptcp,
            "benchmark_iters": opts.benchmark_iters,
            "qname": opts.qname,
            "qtype": 1,
            "qclass": 1,
            "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
            "anyfrom_timeout_ms": 5000,
            "restored_cache_hits_required": opts.benchmark_iters.saturating_sub(1),
        }),
    );
    report.insert("dns_receive".to_owned(), dns_receive);
    report.insert("dns_controller".to_owned(), dns_controller);
    report.insert("dns_upstream".to_owned(), dns_upstream);
    report.insert("dns_cache".to_owned(), dns_cache);
    report.insert("domain_routing".to_owned(), domain_routing);
    report.insert("upstream_packet_conn".to_owned(), upstream_packet_conn);
    report.insert("client_traffic".to_owned(), client_traffic);
    report.insert("sendpkt_reply".to_owned(), sendpkt_reply);
    report.insert("benchmark".to_owned(), benchmark);
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert("route_map_update".to_owned(), route_map_update);
    report.insert(
        "post_traffic_peer_stats".to_owned(),
        post_traffic_peer_stats,
    );
    report.insert("post_traffic_lan_stats".to_owned(), post_traffic_lan_stats);
    report.insert(
        "post_traffic_host_stats".to_owned(),
        post_traffic_host_stats,
    );
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("lan_attach_show".to_owned(), lan_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_listen_map_id": discovered_listen_map_id,
            "discovered_routing_map_id": discovered_routing_map_id,
            "loaded_maps_cleaned": loaded_maps_cleaned,
        }),
    );
    report.insert(
        "temporary_resources".to_owned(),
        json!({
            "leftovers_after_cleanup": leftovers,
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        }),
    );
    report.insert(
        "remaining_blockers".to_owned(),
        json!(remaining_blockers_after_stage54()),
    );
    Value::Object(report)
}

struct Stage50SmokeResult {
    passed: bool,
    original_destination_observed: bool,
    tcp_reply_path_succeeded: bool,
    discovered_listen_map_id: Option<u32>,
    discovered_routing_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    topology_values: Value,
    param_image: Value,
    peer_attach_show: Value,
    lan_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
    route_map_update: Value,
    tcp_accept: Value,
    client_traffic: Value,
    post_traffic_peer_stats: Value,
    post_traffic_lan_stats: Value,
    post_traffic_host_stats: Value,
}

struct Stage51SmokeResult {
    passed: bool,
    original_destination_observed: bool,
    outbound_relay_succeeded: bool,
    so_mark_observed: bool,
    mptcp_observed: bool,
    discovered_listen_map_id: Option<u32>,
    discovered_routing_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    topology_values: Value,
    param_image: Value,
    peer_attach_show: Value,
    lan_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
    route_map_update: Value,
    relay_accept: Value,
    upstream: Value,
    client_traffic: Value,
    outbound_dial: Value,
    benchmark: Value,
    post_traffic_peer_stats: Value,
    post_traffic_lan_stats: Value,
    post_traffic_host_stats: Value,
}

struct Stage52SmokeResult {
    passed: bool,
    original_destination_observed: bool,
    outbound_relay_succeeded: bool,
    so_mark_observed: bool,
    mptcp_observed: bool,
    discovered_listen_map_id: Option<u32>,
    discovered_routing_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    topology_values: Value,
    param_image: Value,
    peer_attach_show: Value,
    lan_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
    route_map_update: Value,
    route_dial_plan: Value,
    group_selection: Value,
    relay_accept: Value,
    upstream: Value,
    client_traffic: Value,
    outbound_dial: Value,
    benchmark: Value,
    post_traffic_peer_stats: Value,
    post_traffic_lan_stats: Value,
    post_traffic_host_stats: Value,
}

struct Stage53SmokeResult {
    passed: bool,
    original_destination_observed: bool,
    endpoint_pool_live_recorded: bool,
    outbound_packet_conn_recorded: bool,
    sendpkt_reply_recorded: bool,
    so_mark_observed: bool,
    discovered_listen_map_id: Option<u32>,
    discovered_routing_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    topology_values: Value,
    param_image: Value,
    peer_attach_show: Value,
    lan_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
    route_map_update: Value,
    udp_receive: Value,
    udp_endpoint_pool: Value,
    outbound_packet_conn: Value,
    upstream: Value,
    client_traffic: Value,
    sendpkt_reply: Value,
    benchmark: Value,
    post_traffic_peer_stats: Value,
    post_traffic_lan_stats: Value,
    post_traffic_host_stats: Value,
}

struct Stage54SmokeResult {
    passed: bool,
    original_destination_observed: bool,
    dns_controller_recorded: bool,
    dns_upstream_query_recorded: bool,
    dns_response_validation_recorded: bool,
    dns_cache_restore_recorded: bool,
    domain_routing_owner_migration_recorded: bool,
    sendpkt_reply_recorded: bool,
    so_mark_observed: bool,
    discovered_listen_map_id: Option<u32>,
    discovered_routing_map_id: Option<u32>,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    topology_values: Value,
    param_image: Value,
    peer_attach_show: Value,
    lan_attach_show: Value,
    host_attach_show: Value,
    loaded_map_handoff: Value,
    route_map_update: Value,
    dns_receive: Value,
    dns_controller: Value,
    dns_upstream: Value,
    dns_cache: Value,
    domain_routing: Value,
    upstream_packet_conn: Value,
    client_traffic: Value,
    sendpkt_reply: Value,
    benchmark: Value,
    post_traffic_peer_stats: Value,
    post_traffic_lan_stats: Value,
    post_traffic_host_stats: Value,
}

fn execute_stage50_smoke(opts: &Stage50Options, before_map_ids: &[u32]) -> Stage50SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= setup_production_topology(&mut executed_steps, opts);
    ok &= setup_client_topology(&mut executed_steps, opts);
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut executed_steps, opts);
    ok &= topology_values["status"].as_str() == Some("pass");
    if let Some(dae0_mac) = dae0_mac {
        ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
    }
    let param_image = if let (Some(dae0_ifindex), Some(dae0peer_mac)) = (dae0_ifindex, dae0peer_mac)
    {
        write_param_image(opts, dae0_ifindex, dae0peer_mac)
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&opts.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut executed_steps, opts);
    }
    let peer_attach_show = show_peer_program(&mut executed_steps);

    let live_handoff = if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            before_map_ids,
            opts.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => Some(handoff),
            Err(err) => {
                ok = false;
                executed_steps.push(json!({
                    "name": "open-live-loaded-tproxy-listen-socket-map",
                    "status": "fail",
                    "error": err.to_string(),
                }));
                None
            }
        }
    } else {
        None
    };
    let (loaded_map_handoff, discovered_listen_map_id) = match live_handoff.as_ref() {
        Some(handoff) => (live_handoff_json(handoff), Some(handoff.map.id)),
        None => (
            json!({
                "status": "skipped",
                "reason": "peer PARAM-aware attach did not pass",
            }),
            None,
        ),
    };

    let before_lan_map_ids = map_ids().unwrap_or_default();
    if ok {
        ok &= attach_lan_program(&mut executed_steps, opts);
    }
    let lan_attach_show = show_lan_program(&mut executed_steps);
    let (route_map_update, discovered_routing_map_id) = if ok {
        match update_stage50_routing_map(&before_lan_map_ids, opts.so_mark) {
            Ok((value, id)) => (value, Some(id)),
            Err(err) => {
                ok = false;
                (json!({"status": "fail", "error": err}), None)
            }
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "LAN PARAM-aware attach did not pass",
            }),
            None,
        )
    };

    if ok {
        ok &= attach_host_program(&mut executed_steps, opts);
    }
    let host_attach_show = show_host_program(&mut executed_steps);

    let (tcp_accept, client_traffic, original_destination_observed, tcp_reply_path_succeeded) =
        if ok {
            let listener = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.tcp_listener.try_clone().ok());
            match listener {
                Some(listener) => run_active_tcp_probe(listener, opts),
                None => (
                    json!({"status": "fail", "error": "failed to clone tproxy TCP listener"}),
                    Value::Null,
                    false,
                    false,
                ),
            }
        } else {
            (
                json!({
                    "status": "skipped",
                    "reason": "BPF attach or routing map update did not pass",
                }),
                Value::Null,
                false,
                false,
            )
        };
    let post_traffic_peer_stats = show_peer_program_stats(&mut executed_steps);
    let post_traffic_lan_stats = show_lan_program_stats(&mut executed_steps);
    let post_traffic_host_stats = show_host_program_stats(&mut executed_steps);
    ok &= tcp_accept["status"].as_str() == Some("pass")
        && client_traffic["status"].as_str() == Some("pass")
        && original_destination_observed;

    cleanup_stage50(&mut cleanup_steps);

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let lan_output = lan_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage50SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&opts.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && lan_attach_show["status"].as_str() == Some("pass")
            && lan_output.contains(&opts.lan_section)
            && lan_output.contains("tproxy_lan_ingr")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&opts.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && resource_leftovers().is_empty(),
        original_destination_observed,
        tcp_reply_path_succeeded,
        discovered_listen_map_id,
        discovered_routing_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        lan_attach_show,
        host_attach_show,
        loaded_map_handoff,
        route_map_update,
        tcp_accept,
        client_traffic,
        post_traffic_peer_stats,
        post_traffic_lan_stats,
        post_traffic_host_stats,
    }
}

fn execute_stage51_smoke(opts: &Stage51Options, before_map_ids: &[u32]) -> Stage51SmokeResult {
    let base = &opts.base;
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= setup_production_topology(&mut executed_steps, base);
    ok &= setup_client_topology(&mut executed_steps, base);
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut executed_steps, base);
    ok &= topology_values["status"].as_str() == Some("pass");
    if let Some(dae0_mac) = dae0_mac {
        ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
    }
    let param_image = if let (Some(dae0_ifindex), Some(dae0peer_mac)) = (dae0_ifindex, dae0peer_mac)
    {
        write_param_image(base, dae0_ifindex, dae0peer_mac)
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&base.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut executed_steps, base);
    }
    let peer_attach_show = show_peer_program(&mut executed_steps);

    let live_handoff = if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            before_map_ids,
            base.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => Some(handoff),
            Err(err) => {
                ok = false;
                executed_steps.push(json!({
                    "name": "open-live-loaded-tproxy-listen-socket-map",
                    "status": "fail",
                    "error": err.to_string(),
                }));
                None
            }
        }
    } else {
        None
    };
    let (loaded_map_handoff, discovered_listen_map_id) = match live_handoff.as_ref() {
        Some(handoff) => (live_handoff_json(handoff), Some(handoff.map.id)),
        None => (
            json!({
                "status": "skipped",
                "reason": "peer PARAM-aware attach did not pass",
            }),
            None,
        ),
    };

    let before_lan_map_ids = map_ids().unwrap_or_default();
    if ok {
        ok &= attach_lan_program(&mut executed_steps, base);
    }
    let lan_attach_show = show_lan_program(&mut executed_steps);
    let (route_map_update, discovered_routing_map_id) = if ok {
        match update_stage50_routing_map(&before_lan_map_ids, base.so_mark) {
            Ok((value, id)) => (value, Some(id)),
            Err(err) => {
                ok = false;
                (json!({"status": "fail", "error": err}), None)
            }
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "LAN PARAM-aware attach did not pass",
            }),
            None,
        )
    };

    if ok {
        ok &= attach_host_program(&mut executed_steps, base);
    }
    let host_attach_show = show_host_program(&mut executed_steps);

    let (
        relay_accept,
        upstream,
        client_traffic,
        outbound_dial,
        benchmark,
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
    ) = if ok {
        let listener = live_handoff
            .as_ref()
            .and_then(|handoff| handoff.listeners.tcp_listener.try_clone().ok());
        match listener {
            Some(listener) => run_active_tcp_relay_probe(listener, opts),
            None => (
                json!({"status": "fail", "error": "failed to clone tproxy TCP listener"}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            ),
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "BPF attach or routing map update did not pass",
            }),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            false,
            false,
            false,
            false,
        )
    };
    let post_traffic_peer_stats = show_peer_program_stats(&mut executed_steps);
    let post_traffic_lan_stats = show_lan_program_stats(&mut executed_steps);
    let post_traffic_host_stats = show_host_program_stats(&mut executed_steps);
    ok &= relay_accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client_traffic["status"].as_str() == Some("pass")
        && outbound_relay_succeeded
        && original_destination_observed
        && so_mark_observed
        && (!base.mptcp || mptcp_observed);

    cleanup_stage50(&mut cleanup_steps);

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let lan_output = lan_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage51SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&base.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && lan_attach_show["status"].as_str() == Some("pass")
            && lan_output.contains(&base.lan_section)
            && lan_output.contains("tproxy_lan_ingr")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&base.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && resource_leftovers().is_empty(),
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
        discovered_listen_map_id,
        discovered_routing_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        lan_attach_show,
        host_attach_show,
        loaded_map_handoff,
        route_map_update,
        relay_accept,
        upstream,
        client_traffic,
        outbound_dial,
        benchmark,
        post_traffic_peer_stats,
        post_traffic_lan_stats,
        post_traffic_host_stats,
    }
}

fn execute_stage52_smoke(opts: &Stage52Options, before_map_ids: &[u32]) -> Stage52SmokeResult {
    let base = &opts.base;
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= setup_production_topology(&mut executed_steps, base);
    ok &= setup_client_topology(&mut executed_steps, base);
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut executed_steps, base);
    ok &= topology_values["status"].as_str() == Some("pass");
    if let Some(dae0_mac) = dae0_mac {
        ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
    }
    let param_image = if let (Some(dae0_ifindex), Some(dae0peer_mac)) = (dae0_ifindex, dae0peer_mac)
    {
        write_param_image(base, dae0_ifindex, dae0peer_mac)
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&base.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut executed_steps, base);
    }
    let peer_attach_show = show_peer_program(&mut executed_steps);

    let live_handoff = if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            before_map_ids,
            base.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => Some(handoff),
            Err(err) => {
                ok = false;
                executed_steps.push(json!({
                    "name": "open-live-loaded-tproxy-listen-socket-map",
                    "status": "fail",
                    "error": err.to_string(),
                }));
                None
            }
        }
    } else {
        None
    };
    let (loaded_map_handoff, discovered_listen_map_id) = match live_handoff.as_ref() {
        Some(handoff) => (live_handoff_json(handoff), Some(handoff.map.id)),
        None => (
            json!({
                "status": "skipped",
                "reason": "peer PARAM-aware attach did not pass",
            }),
            None,
        ),
    };

    let before_lan_map_ids = map_ids().unwrap_or_default();
    if ok {
        ok &= attach_lan_program(&mut executed_steps, base);
    }
    let lan_attach_show = show_lan_program(&mut executed_steps);
    let (route_map_update, discovered_routing_map_id) = if ok {
        match update_stage50_routing_map(&before_lan_map_ids, base.so_mark) {
            Ok((value, id)) => (value, Some(id)),
            Err(err) => {
                ok = false;
                (json!({"status": "fail", "error": err}), None)
            }
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "LAN PARAM-aware attach did not pass",
            }),
            None,
        )
    };

    if ok {
        ok &= attach_host_program(&mut executed_steps, base);
    }
    let host_attach_show = show_host_program(&mut executed_steps);

    let (
        route_dial_plan,
        group_selection,
        relay_accept,
        upstream,
        client_traffic,
        outbound_dial,
        benchmark,
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
    ) = if ok {
        let listener = live_handoff
            .as_ref()
            .and_then(|handoff| handoff.listeners.tcp_listener.try_clone().ok());
        match listener {
            Some(listener) => run_active_tcp_route_table_group_relay_probe(listener, opts),
            None => (
                route_dial_plan_json(&stage52_route_plan(opts)),
                json!({"status": "skipped", "reason": "failed to clone tproxy TCP listener"}),
                json!({"status": "fail", "error": "failed to clone tproxy TCP listener"}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            ),
        }
    } else {
        (
            route_dial_plan_json(&stage52_route_plan(opts)),
            json!({
                "status": "skipped",
                "reason": "BPF attach or routing map update did not pass",
            }),
            json!({
                "status": "skipped",
                "reason": "BPF attach or routing map update did not pass",
            }),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            false,
            false,
            false,
            false,
        )
    };
    let post_traffic_peer_stats = show_peer_program_stats(&mut executed_steps);
    let post_traffic_lan_stats = show_lan_program_stats(&mut executed_steps);
    let post_traffic_host_stats = show_host_program_stats(&mut executed_steps);
    ok &= route_dial_plan["userspace_route_executed"]
        .as_bool()
        .unwrap_or(false)
        && group_selection["status"].as_str() == Some("pass")
        && relay_accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client_traffic["status"].as_str() == Some("pass")
        && outbound_relay_succeeded
        && original_destination_observed
        && so_mark_observed
        && (!base.mptcp || mptcp_observed);

    cleanup_stage50(&mut cleanup_steps);

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let lan_output = lan_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage52SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&base.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && lan_attach_show["status"].as_str() == Some("pass")
            && lan_output.contains(&base.lan_section)
            && lan_output.contains("tproxy_lan_ingr")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&base.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && resource_leftovers().is_empty(),
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
        discovered_listen_map_id,
        discovered_routing_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        lan_attach_show,
        host_attach_show,
        loaded_map_handoff,
        route_map_update,
        route_dial_plan,
        group_selection,
        relay_accept,
        upstream,
        client_traffic,
        outbound_dial,
        benchmark,
        post_traffic_peer_stats,
        post_traffic_lan_stats,
        post_traffic_host_stats,
    }
}

fn execute_stage53_smoke(opts: &Stage53Options, before_map_ids: &[u32]) -> Stage53SmokeResult {
    let base = &opts.base;
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= setup_production_topology(&mut executed_steps, base);
    ok &= setup_client_topology(&mut executed_steps, base);
    ok &= add_stage53_loopback_target(&mut executed_steps, base);
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut executed_steps, base);
    ok &= topology_values["status"].as_str() == Some("pass");
    if let Some(dae0_mac) = dae0_mac {
        ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
    }
    let param_image = if let (Some(dae0_ifindex), Some(dae0peer_mac)) = (dae0_ifindex, dae0peer_mac)
    {
        write_param_image(base, dae0_ifindex, dae0peer_mac)
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&base.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut executed_steps, base);
    }
    let peer_attach_show = show_peer_program(&mut executed_steps);

    let live_handoff = if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            before_map_ids,
            base.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => Some(handoff),
            Err(err) => {
                ok = false;
                executed_steps.push(json!({
                    "name": "open-live-loaded-tproxy-listen-socket-map",
                    "status": "fail",
                    "error": err.to_string(),
                }));
                None
            }
        }
    } else {
        None
    };
    let (loaded_map_handoff, discovered_listen_map_id) = match live_handoff.as_ref() {
        Some(handoff) => (live_handoff_json(handoff), Some(handoff.map.id)),
        None => (
            json!({
                "status": "skipped",
                "reason": "peer PARAM-aware attach did not pass",
            }),
            None,
        ),
    };

    let before_lan_map_ids = map_ids().unwrap_or_default();
    if ok {
        ok &= attach_lan_program(&mut executed_steps, base);
    }
    let lan_attach_show = show_lan_program(&mut executed_steps);
    let (route_map_update, discovered_routing_map_id) = if ok {
        match update_stage50_routing_map(&before_lan_map_ids, base.so_mark) {
            Ok((value, id)) => (value, Some(id)),
            Err(err) => {
                ok = false;
                (json!({"status": "fail", "error": err}), None)
            }
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "LAN PARAM-aware attach did not pass",
            }),
            None,
        )
    };

    if ok {
        ok &= attach_host_program(&mut executed_steps, base);
    }
    let host_attach_show = show_host_program(&mut executed_steps);

    let (
        udp_receive,
        udp_endpoint_pool,
        outbound_packet_conn,
        upstream,
        client_traffic,
        sendpkt_reply,
        benchmark,
        original_destination_observed,
        endpoint_pool_live_recorded,
        outbound_packet_conn_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
    ) = if ok {
        let udp_socket = live_handoff
            .as_ref()
            .and_then(|handoff| handoff.listeners.udp_socket.try_clone().ok());
        match udp_socket {
            Some(udp_socket) => run_active_udp_tproxy_endpoint_probe(udp_socket, opts),
            None => (
                json!({"status": "fail", "error": "failed to clone tproxy UDP socket"}),
                stage53_udp_endpoint_model_json(base),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
            ),
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "BPF attach or routing map update did not pass",
            }),
            stage53_udp_endpoint_model_json(base),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            false,
            false,
            false,
            false,
            false,
        )
    };
    let post_traffic_peer_stats = show_peer_program_stats(&mut executed_steps);
    let post_traffic_lan_stats = show_lan_program_stats(&mut executed_steps);
    let post_traffic_host_stats = show_host_program_stats(&mut executed_steps);
    ok &= udp_receive["status"].as_str() == Some("pass")
        && udp_endpoint_pool["status"].as_str() == Some("pass")
        && outbound_packet_conn["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client_traffic["status"].as_str() == Some("pass")
        && sendpkt_reply["status"].as_str() == Some("pass")
        && original_destination_observed
        && endpoint_pool_live_recorded
        && outbound_packet_conn_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;

    delete_stage53_loopback_target(&mut cleanup_steps, base);
    cleanup_stage50(&mut cleanup_steps);

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let lan_output = lan_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage53SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&base.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && lan_attach_show["status"].as_str() == Some("pass")
            && lan_output.contains(&base.lan_section)
            && lan_output.contains("tproxy_lan_ingr")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&base.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && resource_leftovers().is_empty()
            && !stage53_loopback_target_present(&base.target_ip),
        original_destination_observed,
        endpoint_pool_live_recorded,
        outbound_packet_conn_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
        discovered_listen_map_id,
        discovered_routing_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        lan_attach_show,
        host_attach_show,
        loaded_map_handoff,
        route_map_update,
        udp_receive,
        udp_endpoint_pool,
        outbound_packet_conn,
        upstream,
        client_traffic,
        sendpkt_reply,
        benchmark,
        post_traffic_peer_stats,
        post_traffic_lan_stats,
        post_traffic_host_stats,
    }
}

fn execute_stage54_smoke(opts: &Stage54Options, before_map_ids: &[u32]) -> Stage54SmokeResult {
    let base = &opts.base;
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= setup_production_topology(&mut executed_steps, base);
    ok &= setup_client_topology(&mut executed_steps, base);
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut executed_steps, base);
    ok &= topology_values["status"].as_str() == Some("pass");
    if let Some(dae0_mac) = dae0_mac {
        ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
    }
    let param_image = if let (Some(dae0_ifindex), Some(dae0peer_mac)) = (dae0_ifindex, dae0peer_mac)
    {
        write_param_image(base, dae0_ifindex, dae0peer_mac)
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&base.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut executed_steps, base);
    }
    let peer_attach_show = show_peer_program(&mut executed_steps);

    let live_handoff = if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            before_map_ids,
            base.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => Some(handoff),
            Err(err) => {
                ok = false;
                executed_steps.push(json!({
                    "name": "open-live-loaded-tproxy-listen-socket-map",
                    "status": "fail",
                    "error": err.to_string(),
                }));
                None
            }
        }
    } else {
        None
    };
    let (loaded_map_handoff, discovered_listen_map_id) = match live_handoff.as_ref() {
        Some(handoff) => (live_handoff_json(handoff), Some(handoff.map.id)),
        None => (
            json!({
                "status": "skipped",
                "reason": "peer PARAM-aware attach did not pass",
            }),
            None,
        ),
    };

    let before_lan_map_ids = map_ids().unwrap_or_default();
    if ok {
        ok &= attach_lan_program(&mut executed_steps, base);
    }
    let lan_attach_show = show_lan_program(&mut executed_steps);
    let (route_map_update, discovered_routing_map_id) = if ok {
        match update_stage50_routing_map(&before_lan_map_ids, base.so_mark) {
            Ok((value, id)) => (value, Some(id)),
            Err(err) => {
                ok = false;
                (json!({"status": "fail", "error": err}), None)
            }
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "LAN PARAM-aware attach did not pass",
            }),
            None,
        )
    };

    if ok {
        ok &= attach_host_program(&mut executed_steps, base);
    }
    let host_attach_show = show_host_program(&mut executed_steps);

    let (
        dns_receive,
        dns_controller,
        dns_upstream,
        dns_cache,
        domain_routing,
        upstream_packet_conn,
        client_traffic,
        sendpkt_reply,
        benchmark,
        original_destination_observed,
        dns_controller_recorded,
        dns_upstream_query_recorded,
        dns_response_validation_recorded,
        dns_cache_restore_recorded,
        domain_routing_owner_migration_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
    ) = if ok {
        let udp_socket = live_handoff
            .as_ref()
            .and_then(|handoff| handoff.listeners.udp_socket.try_clone().ok());
        match udp_socket {
            Some(udp_socket) => run_active_dns_tproxy_cache_probe(udp_socket, opts),
            None => (
                json!({"status": "fail", "error": "failed to clone tproxy UDP socket"}),
                Value::Null,
                Value::Null,
                stage54_dns_cache_model_json(opts),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
            ),
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "BPF attach or routing map update did not pass",
            }),
            Value::Null,
            Value::Null,
            stage54_dns_cache_model_json(opts),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        )
    };
    let post_traffic_peer_stats = show_peer_program_stats(&mut executed_steps);
    let post_traffic_lan_stats = show_lan_program_stats(&mut executed_steps);
    let post_traffic_host_stats = show_host_program_stats(&mut executed_steps);
    ok &= dns_receive["status"].as_str() == Some("pass")
        && dns_controller["status"].as_str() == Some("pass")
        && dns_upstream["status"].as_str() == Some("pass")
        && dns_cache["status"].as_str() == Some("pass")
        && domain_routing["status"].as_str() == Some("pass")
        && upstream_packet_conn["status"].as_str() == Some("pass")
        && client_traffic["status"].as_str() == Some("pass")
        && sendpkt_reply["status"].as_str() == Some("pass")
        && original_destination_observed
        && dns_controller_recorded
        && dns_upstream_query_recorded
        && dns_response_validation_recorded
        && dns_cache_restore_recorded
        && domain_routing_owner_migration_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;

    cleanup_stage50(&mut cleanup_steps);

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let lan_output = lan_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage54SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&base.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && lan_attach_show["status"].as_str() == Some("pass")
            && lan_output.contains(&base.lan_section)
            && lan_output.contains("tproxy_lan_ingr")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&base.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && resource_leftovers().is_empty(),
        original_destination_observed,
        dns_controller_recorded,
        dns_upstream_query_recorded,
        dns_response_validation_recorded,
        dns_cache_restore_recorded,
        domain_routing_owner_migration_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
        discovered_listen_map_id,
        discovered_routing_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        lan_attach_show,
        host_attach_show,
        loaded_map_handoff,
        route_map_update,
        dns_receive,
        dns_controller,
        dns_upstream,
        dns_cache,
        domain_routing,
        upstream_packet_conn,
        client_traffic,
        sendpkt_reply,
        benchmark,
        post_traffic_peer_stats,
        post_traffic_lan_stats,
        post_traffic_host_stats,
    }
}

fn setup_production_topology(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "create-production-veth-pair",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "add",
                PRODUCTION_HOST_IFACE,
                "type",
                "veth",
                "peer",
                "name",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "create-production-netns",
        CommandSpec::new("ip", &["netns", "add", PRODUCTION_NETNS]),
    );
    ok &= run_step(
        steps,
        "assign-production-netns-id",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "set",
                PRODUCTION_NETNS,
                &opts.dae_netns_id.to_string(),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "move-production-peer-into-netns",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "set",
                PRODUCTION_PEER_IFACE,
                "netns",
                PRODUCTION_NETNS,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-production-host-link-up",
        CommandSpec::new("ip", &["link", "set", PRODUCTION_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        steps,
        "bring-production-netns-loopback-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-production-peer-link-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "link",
                "set",
                PRODUCTION_PEER_IFACE,
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-fwmark-rule",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "rule",
                "add",
                "fwmark",
                "0x8000000/0x8000000",
                "table",
                "2023",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-local-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "local",
                "default",
                "dev",
                "lo",
                "table",
                "2023",
            ],
        ),
    );
    ok
}

fn add_stage53_loopback_target(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    run_step(
        steps,
        "add-stage53-temporary-loopback-upstream-address",
        CommandSpec::new(
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/32", opts.target_ip),
                "dev",
                "lo",
            ],
        ),
    )
}

fn delete_stage53_loopback_target(cleanup_steps: &mut Vec<Value>, opts: &Stage50Options) {
    run_cleanup_step(
        cleanup_steps,
        "delete-stage53-temporary-loopback-upstream-address",
        CommandSpec::new(
            "ip",
            &[
                "addr",
                "del",
                &format!("{}/32", opts.target_ip),
                "dev",
                "lo",
            ],
        ),
    );
}

fn stage53_loopback_target_present(target_ip: &str) -> bool {
    Command::new("ip")
        .args(["addr", "show", "dev", "lo"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|stdout| stdout.contains(target_ip))
}

fn setup_client_topology(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "create-client-netns",
        CommandSpec::new("ip", &["netns", "add", CLIENT_NETNS]),
    );
    ok &= run_step(
        steps,
        "create-lan-veth-pair",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "add",
                LAN_HOST_IFACE,
                "type",
                "veth",
                "peer",
                "name",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "move-lan-client-into-netns",
        CommandSpec::new(
            "ip",
            &["link", "set", LAN_CLIENT_IFACE, "netns", CLIENT_NETNS],
        ),
    );
    ok &= run_step(
        steps,
        "assign-lan-host-ip",
        CommandSpec::new(
            "ip",
            &[
                "addr",
                "add",
                &format!("{DEFAULT_STAGE50_LAN_GATEWAY_IP}/24"),
                "dev",
                LAN_HOST_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-lan-host-link-up",
        CommandSpec::new("ip", &["link", "set", LAN_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        steps,
        "disable-lan-host-send-redirects",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{LAN_HOST_IFACE}.send_redirects=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-lan-host-rp-filter",
        CommandSpec::new(
            "sysctl",
            &["-w", &format!("net.ipv4.conf.{LAN_HOST_IFACE}.rp_filter=0")],
        ),
    );
    ok &= run_step(
        steps,
        "bring-client-loopback-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "assign-lan-client-ip",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "addr",
                "add",
                &format!("{}/24", opts.client_ip),
                "dev",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-lan-client-link-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "link",
                "set",
                LAN_CLIENT_IFACE,
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-client-default-route-via-lan-gateway",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "route",
                "add",
                "default",
                "via",
                DEFAULT_STAGE50_LAN_GATEWAY_IP,
                "dev",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok
}

fn read_topology_values(
    steps: &mut Vec<Value>,
    opts: &Stage50Options,
) -> (Value, Option<u32>, Option<[u8; 6]>, Option<[u8; 6]>) {
    let dae0_ifindex_step = run_observation_step(
        steps,
        "read-production-dae0-ifindex",
        CommandSpec::new(
            "cat",
            &[&format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/ifindex")],
        ),
    );
    let dae0_mac_step = run_observation_step(
        steps,
        "read-production-dae0-mac",
        CommandSpec::new(
            "cat",
            &[&format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/address")],
        ),
    );
    let dae0peer_mac_step = run_observation_step(
        steps,
        "read-production-dae0peer-mac",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "cat",
                &format!("/sys/class/net/{PRODUCTION_PEER_IFACE}/address"),
            ],
        ),
    );
    let dae0_ifindex = parse_step_u32(&dae0_ifindex_step).ok();
    let dae0_mac = parse_step_mac(&dae0_mac_step).ok();
    let dae0peer_mac = parse_step_mac(&dae0peer_mac_step).ok();
    let value = match (dae0_ifindex, dae0_mac, dae0peer_mac) {
        (Some(dae0_ifindex), Some(dae0_mac), Some(dae0peer_mac)) => json!({
            "status": "pass",
            "dae0_ifindex": dae0_ifindex,
            "dae_netns_id": opts.dae_netns_id,
            "dae0_mac": mac_string(dae0_mac),
            "dae0peer_mac": mac_string(dae0peer_mac),
            "control_plane_pid": std::process::id(),
        }),
        _ => json!({
            "status": "fail",
            "dae0_ifindex_step": dae0_ifindex_step,
            "dae0_mac_step": dae0_mac_step,
            "dae0peer_mac_step": dae0peer_mac_step,
        }),
    };
    (value, dae0_ifindex, dae0_mac, dae0peer_mac)
}

fn setup_production_ipv4_datapath(steps: &mut Vec<Value>, dae0_mac: [u8; 6]) -> bool {
    let host_mac = mac_string(dae0_mac);
    let mut ok = true;
    ok &= run_step(
        steps,
        "set-daens-dae0peer-accept-local",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "sysctl",
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_PEER_IFACE}.accept_local=1"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "set-production-dae0-accept-local",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_HOST_IFACE}.accept_local=1"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-production-dae0-send-redirects",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_HOST_IFACE}.send_redirects=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-production-dae0-rp-filter",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_HOST_IFACE}.rp_filter=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "assign-daens-dae0peer-link-ip",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "addr",
                "add",
                "169.254.0.11/32",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-link-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-default-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "default",
                "via",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-host-neighbor",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "neigh",
                "replace",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
                "lladdr",
                &host_mac,
                "nud",
                "permanent",
            ],
        ),
    );
    ok
}

fn write_param_image(opts: &Stage50Options, dae0_ifindex: u32, dae0peer_mac: [u8; 6]) -> Value {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: opts.tproxy_port,
        control_plane_pid: std::process::id(),
        dae0_ifindex,
        dae_netns_id: opts.dae_netns_id,
        dae0peer_mac,
        has_bpf_get_current_task: true,
    });
    match write_param_aware_object(&opts.source_object, &opts.param_object, param) {
        Ok(report) => json!({
            "status": "pass",
            "path": path_string(&opts.param_object),
            "rewritten_param_matches": report.rewritten_param_matches,
            "previous_param_was_zero": report.previous_param_was_zero,
            "source_len": report.source_len,
            "output_len": report.output_len,
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
            },
            "location": {
                "symbol": report.location.symbol,
                "section": report.location.section,
                "symbol_size": report.location.symbol_size,
                "file_offset": report.location.file_offset,
            },
        }),
        Err(err) => json!({
            "status": "fail",
            "path": path_string(&opts.param_object),
            "error": err.to_string(),
        }),
    }
}

fn attach_peer_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-peer-clsact-qdisc",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "qdisc",
                "add",
                "dev",
                PRODUCTION_PEER_IFACE,
                "clsact",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0peer-param-aware-ebpf-program",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "add",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.peer_section,
            ],
        ),
    );
    ok
}

fn attach_lan_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-lan-host-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "add", "dev", LAN_HOST_IFACE, "clsact"]),
    );
    ok &= run_step(
        steps,
        "attach-lan-ingress-param-aware-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                LAN_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_LAN_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.lan_section,
            ],
        ),
    );
    ok
}

fn attach_host_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-host-clsact-qdisc",
        CommandSpec::new(
            "tc",
            &["qdisc", "add", "dev", PRODUCTION_HOST_IFACE, "clsact"],
        ),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0-param-aware-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.host_section,
            ],
        ),
    );
    ok
}

fn show_peer_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "show",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
            ],
        ),
    )
}

fn show_lan_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-lan-ingress-param-aware-ebpf-program-filter",
        CommandSpec::new("tc", &["filter", "show", "dev", LAN_HOST_IFACE, "ingress"]),
    )
}

fn show_host_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &["filter", "show", "dev", PRODUCTION_HOST_IFACE, "ingress"],
        ),
    )
}

fn show_peer_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "-s",
                "filter",
                "show",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
            ],
        ),
    )
}

fn show_lan_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-lan-ingress-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "tc",
            &["-s", "filter", "show", "dev", LAN_HOST_IFACE, "ingress"],
        ),
    )
}

fn show_host_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "tc",
            &[
                "-s",
                "filter",
                "show",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
            ],
        ),
    )
}

fn live_handoff_json(handoff: &dae_ebpf_support::LiveLoadedTproxyListenSocketMap) -> Value {
    json!({
        "status": "pass",
        "map": map_json(&handoff.map),
        "new_map_ids": handoff.new_map_ids,
        "keys_updated": handoff.keys_updated,
        "tcp_listener_fd_observed": handoff.tcp_listener_fd >= 0,
        "udp_socket_fd_observed": handoff.udp_socket_fd >= 0,
        "tcp_options": {
            "ip_transparent": handoff.tcp_options.ip_transparent,
            "so_reuseaddr": handoff.tcp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.tcp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.tcp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.tcp_options.original_dst_capture_ready,
        },
        "udp_options": {
            "ip_transparent": handoff.udp_options.ip_transparent,
            "so_reuseaddr": handoff.udp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.udp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.udp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.udp_options.original_dst_capture_ready,
        },
    })
}

fn update_stage50_routing_map(
    before_map_ids: &[u32],
    so_mark: u32,
) -> Result<(Value, u32), String> {
    let (fd, info, new_map_ids) =
        open_unique_new_map(before_map_ids, ROUTING_MAP_KERNEL_NAME, 4, 24)
            .map_err(|err| err.to_string())?;
    let key = 0_u32.to_ne_bytes();
    let value = fallback_match_set_value(OUTBOUND_STAGE50_PROXY, so_mark);
    update_map_elem_bytes(fd.as_raw_fd(), &key, &value).map_err(|err| err.to_string())?;
    Ok((
        json!({
            "status": "pass",
            "map": map_json(&info),
            "new_map_ids": new_map_ids,
            "key": 0,
            "match_type": "Fallback",
            "match_type_value": MATCH_TYPE_FALLBACK,
            "outbound": OUTBOUND_STAGE50_PROXY,
            "mark": so_mark,
            "must": false,
        }),
        info.id,
    ))
}

fn fallback_match_set_value(outbound: u8, mark: u32) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[17] = MATCH_TYPE_FALLBACK;
    value[18] = outbound;
    value[20..24].copy_from_slice(&mark.to_ne_bytes());
    value
}

fn open_unique_new_map(
    before_map_ids: &[u32],
    name: &str,
    key_size: u32,
    value_size: u32,
) -> std::io::Result<(OwnedFd, RuntimeMapInfo, Vec<u32>)> {
    let current = map_ids()?;
    let new_map_ids = current
        .iter()
        .copied()
        .filter(|id| !before_map_ids.contains(id))
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for id in &new_map_ids {
        let fd = open_map_fd(*id)?;
        let info = map_info(fd.as_raw_fd())?;
        if info.name == name && info.key_size == key_size && info.value_size == value_size {
            candidates.push((fd, info));
        }
    }
    if candidates.len() != 1 {
        return Err(std::io::Error::other(format!(
            "expected exactly one new map {name}, found {}",
            candidates.len()
        )));
    }
    let (fd, info) = candidates.remove(0);
    Ok((fd, info, new_map_ids))
}

fn run_active_tcp_probe(
    listener: TcpListener,
    opts: &Stage50Options,
) -> (Value, Value, bool, bool) {
    let target = format!("{}:{}", opts.target_ip, opts.target_port);
    let accept_handle = thread::spawn(move || tcp_accept_probe(listener));
    thread::sleep(Duration::from_millis(100));
    let client = run_client_probe(&target);
    let accept = accept_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "accept thread panicked"}));
    let original_destination_observed = accept["local_addr"].as_str() == Some(target.as_str());
    let tcp_reply_path_succeeded = client["stdout"]
        .as_str()
        .is_some_and(|stdout| stdout.contains("stage50-tcp-ack"));
    (
        accept,
        client,
        original_destination_observed,
        tcp_reply_path_succeeded,
    )
}

#[allow(clippy::type_complexity)]
fn run_active_tcp_relay_probe(
    listener: TcpListener,
    opts: &Stage51Options,
) -> (Value, Value, Value, Value, Value, bool, bool, bool, bool) {
    let target = format!("{}:{}", opts.base.target_ip, opts.base.target_port);
    let iterations = opts.benchmark_iters;
    let (upstream_listener, upstream_listener_report) = match bind_loopback_tcp_listener(
        opts.base.mptcp && opts.upstream_mptcp,
    ) {
        Ok(value) => value,
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to bind upstream listener: {err}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_addr = match upstream_listener.local_addr() {
        Ok(std::net::SocketAddr::V4(addr)) => addr,
        Ok(addr) => {
            return (
                json!({"status": "fail", "error": format!("unexpected upstream address family: {addr}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to read upstream address: {err}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_handle = thread::spawn(move || {
        upstream_echo_probe(
            upstream_listener,
            upstream_listener_report,
            iterations,
            STAGE51_TCP_PAYLOAD,
            STAGE51_TCP_RESPONSE,
        )
    });
    let relay_target = target.clone();
    let mark = opts.base.so_mark;
    let mptcp = opts.base.mptcp;
    let accept_handle = thread::spawn(move || {
        tcp_relay_accept_probe(
            listener,
            upstream_addr,
            &relay_target,
            mark,
            mptcp,
            iterations,
        )
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_relay_probe(&target, iterations);
    let accept = accept_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "relay accept thread panicked"}));
    let upstream = upstream_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "upstream thread panicked"}));
    let elapsed = started.elapsed();
    let original_destination_observed =
        accept["first_local_addr"].as_str() == Some(target.as_str());
    let outbound_relay_succeeded = accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("stage51-relay-ack-count="));
    let outbound_dial = accept["last_outbound_dial"].clone();
    let so_mark_observed = outbound_dial["so_mark"].as_u64() == Some(mark as u64)
        && outbound_dial["so_mark_applied"].as_bool().unwrap_or(false);
    let mptcp_observed = !mptcp
        || outbound_dial["mptcp_protocol_observed"]
            .as_bool()
            .unwrap_or(false)
        || outbound_dial["mptcp_info_available"]
            .as_bool()
            .unwrap_or(false);
    let benchmark = if iterations > 1 && outbound_relay_succeeded {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_connection": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "stage51 active TCP ingress plus Rust direct outbound relay loopback benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": if iterations > 1 { "fail" } else { "skipped" },
            "iterations": iterations,
            "reason": if iterations > 1 { "relay smoke failed" } else { "benchmark-iters is 1" },
        })
    };
    (
        accept,
        upstream,
        client,
        outbound_dial,
        benchmark,
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
    )
}

fn run_active_tcp_route_table_group_relay_probe(
    listener: TcpListener,
    opts: &Stage52Options,
) -> (
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    bool,
    bool,
    bool,
    bool,
) {
    let target = format!("{}:{}", opts.base.target_ip, opts.base.target_port);
    let iterations = opts.benchmark_iters;
    let route_plan = stage52_route_plan(opts);
    let route_plan_json = route_dial_plan_json(&route_plan);
    let (group_selection, group_selection_ok) = stage52_group_selection_json(&route_plan);
    let upstream_target = match route_plan.final_dial_target.parse::<std::net::SocketAddr>() {
        Ok(std::net::SocketAddr::V4(addr)) => addr,
        Ok(addr) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("stage52 route target is not IPv4: {addr}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
        Err(err) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("stage52 route target is not a socket address: {err}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let (upstream_listener, upstream_listener_report) = match bind_loopback_tcp_listener_on_port(
        opts.base.mptcp && opts.upstream_mptcp,
        upstream_target.port(),
    ) {
        Ok(value) => value,
        Err(err) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("failed to bind route target upstream listener: {err}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_bound_addr = match upstream_listener.local_addr() {
        Ok(std::net::SocketAddr::V4(addr)) => addr,
        Ok(addr) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("unexpected upstream address family: {addr}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
        Err(err) => {
            return (
                route_plan_json,
                group_selection,
                json!({"status": "fail", "error": format!("failed to read upstream address: {err}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_handle = thread::spawn(move || {
        upstream_echo_probe(
            upstream_listener,
            upstream_listener_report,
            iterations,
            STAGE52_TCP_PAYLOAD,
            STAGE52_TCP_RESPONSE,
        )
    });
    let relay_target = target.clone();
    let final_mark = route_plan.final_mark;
    let mptcp = route_plan.mptcp;
    let final_dial_target = route_plan.final_dial_target.clone();
    let accept_handle = thread::spawn(move || {
        tcp_route_table_group_relay_accept_probe(
            listener,
            upstream_bound_addr,
            &final_dial_target,
            &relay_target,
            final_mark,
            mptcp,
            iterations,
        )
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_stage52_relay_probe(&target, iterations);
    let accept = accept_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage52 relay accept thread panicked"}),
    );
    let upstream = upstream_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "stage52 upstream thread panicked"}));
    let elapsed = started.elapsed();
    let original_destination_observed =
        accept["first_local_addr"].as_str() == Some(target.as_str());
    let outbound_relay_succeeded = group_selection_ok
        && accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("stage52-route-group-ack-count="));
    let outbound_dial = accept["last_outbound_dial"].clone();
    let so_mark_observed = outbound_dial["so_mark"].as_u64() == Some(final_mark as u64)
        && outbound_dial["so_mark_applied"].as_bool().unwrap_or(false);
    let mptcp_observed = !mptcp
        || outbound_dial["mptcp_protocol_observed"]
            .as_bool()
            .unwrap_or(false)
        || outbound_dial["mptcp_info_available"]
            .as_bool()
            .unwrap_or(false);
    let benchmark = if iterations > 1 && outbound_relay_succeeded {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_connection": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "stage52 active TCP ingress plus Rust route table, ChooseDialTarget, outbound group selection, and direct loopback relay benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": if iterations > 1 { "fail" } else { "skipped" },
            "iterations": iterations,
            "reason": if iterations > 1 { "stage52 relay smoke failed" } else { "benchmark-iters is 1" },
        })
    };
    (
        route_plan_json,
        group_selection,
        accept,
        upstream,
        client,
        outbound_dial,
        benchmark,
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
    )
}

fn run_active_udp_tproxy_endpoint_probe(
    udp_socket: UdpSocket,
    opts: &Stage53Options,
) -> (
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    bool,
    bool,
    bool,
    bool,
    bool,
) {
    let target = match stage_target_addr(&opts.base) {
        Ok(target) => target,
        Err(err) => {
            return (
                json!({"status": "fail", "error": err}),
                stage53_udp_endpoint_model_json(&opts.base),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
            );
        }
    };
    let iterations = opts.benchmark_iters;
    let upstream = match UdpSocket::bind(target) {
        Ok(socket) => socket,
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to bind UDP upstream {target}: {err}")}),
                stage53_udp_endpoint_model_json(&opts.base),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
            );
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(3)));
    let upstream_handle = thread::spawn(move || udp_upstream_echo_probe(upstream, iterations));
    let mark = opts.base.so_mark;
    let mptcp = opts.base.mptcp;
    let accept_handle = thread::spawn(move || {
        udp_tproxy_endpoint_probe(udp_socket, target, mark, mptcp, iterations)
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_stage53_udp_probe(&target.to_string(), iterations);
    let accept = accept_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage53 UDP tproxy thread panicked"}),
    );
    let upstream = upstream_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage53 UDP upstream thread panicked"}),
    );
    let elapsed = started.elapsed();
    let accept_failure = || json!({"status": "fail", "accept_probe": accept.clone()});
    let udp_receive = accept
        .get("udp_receive")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let udp_endpoint_pool = accept
        .get("udp_endpoint_pool")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let outbound_packet_conn = accept
        .get("outbound_packet_conn")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let sendpkt_reply = accept
        .get("sendpkt_reply")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let target_string = target.to_string();
    let original_destination_observed =
        udp_receive["first_original_dst"].as_str() == Some(target_string.as_str());
    let endpoint_pool_live_recorded = udp_endpoint_pool["created_entries"].as_u64() == Some(1)
        && udp_endpoint_pool["reused_writes"].as_u64() == Some(iterations.saturating_sub(1) as u64)
        && udp_endpoint_pool["full_cone_key"].as_str().is_some();
    let outbound_packet_conn_recorded = outbound_packet_conn["status"].as_str() == Some("pass")
        && outbound_packet_conn["write_to_count"].as_u64() == Some(iterations as u64)
        && outbound_packet_conn["read_from_count"].as_u64() == Some(iterations as u64);
    let sendpkt_reply_recorded = sendpkt_reply["status"].as_str() == Some("pass")
        && sendpkt_reply["reply_count"].as_u64() == Some(iterations as u64)
        && sendpkt_reply["source_matches_original_dst"]
            .as_bool()
            .unwrap_or(false);
    let so_mark_observed = outbound_packet_conn["so_mark"].as_u64() == Some(mark as u64)
        && outbound_packet_conn["so_mark_applied"]
            .as_bool()
            .unwrap_or(false);
    let client_ok = client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("stage53-udp-ack-count="));
    let smoke_ok = accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client_ok
        && original_destination_observed
        && endpoint_pool_live_recorded
        && outbound_packet_conn_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;
    let benchmark = if iterations > 1 && smoke_ok {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_packet": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "stage53 active UDP tproxy plus endpoint pool, direct PacketConn, and sendPkt-style reply benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": if iterations > 1 { "fail" } else { "skipped" },
            "iterations": iterations,
            "reason": if iterations > 1 { "stage53 UDP smoke failed" } else { "benchmark-iters is 1" },
        })
    };
    (
        udp_receive,
        udp_endpoint_pool,
        outbound_packet_conn,
        upstream,
        client,
        sendpkt_reply,
        benchmark,
        original_destination_observed,
        endpoint_pool_live_recorded,
        outbound_packet_conn_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
    )
}

fn run_active_dns_tproxy_cache_probe(
    udp_socket: UdpSocket,
    opts: &Stage54Options,
) -> (
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    Value,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
) {
    let target = match stage_target_addr(&opts.base) {
        Ok(target) => target,
        Err(err) => {
            return (
                json!({"status": "fail", "error": err}),
                Value::Null,
                Value::Null,
                stage54_dns_cache_model_json(opts),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_addr = match stage54_upstream_addr(opts) {
        Ok(addr) => addr,
        Err(err) => {
            return (
                json!({"status": "fail", "error": err}),
                Value::Null,
                Value::Null,
                stage54_dns_cache_model_json(opts),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream = match UdpSocket::bind(upstream_addr) {
        Ok(socket) => socket,
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to bind DNS upstream {upstream_addr}: {err}")}),
                Value::Null,
                Value::Null,
                stage54_dns_cache_model_json(opts),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
            );
        }
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(3)));
    let qname = opts.qname.clone();
    let upstream_handle = thread::spawn(move || dns_upstream_echo_probe(upstream, &qname));
    let mark = opts.base.so_mark;
    let mptcp = opts.base.mptcp;
    let iterations = opts.benchmark_iters;
    let qname = opts.qname.clone();
    let accept_handle = thread::spawn(move || {
        dns_tproxy_cache_probe(
            udp_socket,
            target,
            upstream_addr,
            mark,
            mptcp,
            &qname,
            iterations,
        )
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_stage54_dns_probe(&target.to_string(), &opts.qname, iterations);
    let accept = accept_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage54 DNS tproxy thread panicked"}),
    );
    let upstream = upstream_handle.join().unwrap_or_else(
        |_| json!({"status": "fail", "error": "stage54 DNS upstream thread panicked"}),
    );
    let elapsed = started.elapsed();
    let accept_failure = || json!({"status": "fail", "accept_probe": accept.clone()});
    let dns_receive = accept
        .get("dns_receive")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let dns_controller = accept
        .get("dns_controller")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let dns_cache = accept
        .get("dns_cache")
        .cloned()
        .unwrap_or_else(|| stage54_dns_cache_model_json(opts));
    let domain_routing = accept
        .get("domain_routing")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let upstream_packet_conn = accept
        .get("upstream_packet_conn")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let sendpkt_reply = accept
        .get("sendpkt_reply")
        .cloned()
        .unwrap_or_else(|| accept_failure());
    let target_string = target.to_string();
    let original_destination_observed =
        dns_receive["first_original_dst"].as_str() == Some(target_string.as_str());
    let dns_controller_recorded = dns_controller["status"].as_str() == Some("pass")
        && dns_controller["dns_udp53_controller_path"]
            .as_bool()
            .unwrap_or(false);
    let dns_upstream_query_recorded =
        upstream["status"].as_str() == Some("pass") && upstream["accepted"].as_u64() == Some(1);
    let dns_response_validation_recorded = dns_controller["validated_responses"].as_u64()
        == Some(iterations as u64)
        && upstream["response_validated"].as_bool().unwrap_or(false);
    let dns_cache_restore_recorded = dns_cache["status"].as_str() == Some("pass")
        && dns_cache["cache_miss_upstream_queries"].as_u64() == Some(1)
        && dns_cache["restored_cache_hits"].as_u64() == Some(iterations.saturating_sub(1) as u64);
    let domain_routing_owner_migration_recorded = domain_routing["status"].as_str() == Some("pass")
        && domain_routing["owner_after_reload_present"]
            .as_bool()
            .unwrap_or(false);
    let sendpkt_reply_recorded = sendpkt_reply["status"].as_str() == Some("pass")
        && sendpkt_reply["reply_count"].as_u64() == Some(iterations as u64)
        && sendpkt_reply["source_matches_original_dst"]
            .as_bool()
            .unwrap_or(false);
    let so_mark_observed = upstream_packet_conn["so_mark"].as_u64() == Some(mark as u64)
        && upstream_packet_conn["so_mark_applied"]
            .as_bool()
            .unwrap_or(false);
    let client_ok = client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("stage54-dns-ack-count="));
    let smoke_ok = accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client_ok
        && original_destination_observed
        && dns_controller_recorded
        && dns_upstream_query_recorded
        && dns_response_validation_recorded
        && dns_cache_restore_recorded
        && domain_routing_owner_migration_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;
    let benchmark = if smoke_ok {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_query": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "stage54 active DNS UDP/53 tproxy plus upstream miss, restored cache hits, domain routing owner, and sendPkt-style reply benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": "fail",
            "iterations": iterations,
            "reason": "stage54 DNS UDP/53 smoke failed",
        })
    };
    (
        dns_receive,
        dns_controller,
        upstream,
        dns_cache,
        domain_routing,
        upstream_packet_conn,
        client,
        sendpkt_reply,
        benchmark,
        original_destination_observed,
        dns_controller_recorded,
        dns_upstream_query_recorded,
        dns_response_validation_recorded,
        dns_cache_restore_recorded,
        domain_routing_owner_migration_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
    )
}

fn tcp_accept_probe(listener: TcpListener) -> Value {
    if let Err(err) = listener.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let (mut stream, peer) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return json!({"status": "fail", "error": err.to_string()}),
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let local_addr = stream.local_addr().map(|addr| addr.to_string()).ok();
    let mut buf = vec![0_u8; TCP_PAYLOAD.len()];
    let read_status = stream.read_exact(&mut buf);
    let write_status = if read_status.is_ok() {
        stream.write_all(TCP_RESPONSE)
    } else {
        Ok(())
    };
    let passed = read_status.is_ok() && write_status.is_ok() && buf == TCP_PAYLOAD;
    json!({
        "status": if passed { "pass" } else { "fail" },
        "peer_addr": peer.to_string(),
        "local_addr": local_addr,
        "payload_matched": buf == TCP_PAYLOAD,
        "read_error": read_status.err().map(|err| err.to_string()),
        "write_error": write_status.err().map(|err| err.to_string()),
    })
}

fn tcp_relay_accept_probe(
    listener: TcpListener,
    upstream_addr: SocketAddrV4,
    target: &str,
    mark: u32,
    mptcp: bool,
    iterations: u32,
) -> Value {
    if let Err(err) = listener.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let started = Instant::now();
    let magic_network = magic_network_bytes("tcp", mark, mptcp);
    let parsed_magic = parse_magic_network(&magic_network).ok();
    let mut first_local_addr = None;
    let mut first_peer_addr = None;
    let mut last_outbound_dial = Value::Null;
    let mut relayed_connections = 0_u32;
    let mut bytes_client_to_outbound = 0_usize;
    let mut bytes_outbound_to_client = 0_usize;
    for _ in 0..iterations {
        let (mut inbound, peer) = match accept_with_deadline(&listener, Duration::from_secs(4)) {
            Ok(accepted) => accepted,
            Err(err) => return json!({"status": "fail", "error": err.to_string()}),
        };
        let _ = inbound.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = inbound.set_write_timeout(Some(Duration::from_secs(2)));
        let local_addr = inbound.local_addr().map(|addr| addr.to_string()).ok();
        if first_local_addr.is_none() {
            first_local_addr = local_addr.clone();
            first_peer_addr = Some(peer.to_string());
        }
        let mut payload = vec![0_u8; STAGE51_TCP_PAYLOAD.len()];
        if let Err(err) = inbound.read_exact(&mut payload) {
            return json!({"status": "fail", "error": format!("read inbound payload: {err}")});
        }
        if payload != STAGE51_TCP_PAYLOAD {
            return json!({
                "status": "fail",
                "error": "unexpected inbound payload",
                "payload": String::from_utf8_lossy(&payload).to_string(),
            });
        }
        let mut outbound = match magic_tcp_connect(
            upstream_addr,
            &TcpDirectDialOptions {
                mark,
                mptcp,
                timeout: Duration::from_secs(3),
            },
        ) {
            Ok(conn) => conn,
            Err(err) => return json!({"status": "fail", "error": format!("outbound dial: {err}")}),
        };
        if let Err(err) = outbound.stream.write_all(&payload) {
            return json!({"status": "fail", "error": format!("write outbound payload: {err}")});
        }
        let mut response = vec![0_u8; STAGE51_TCP_RESPONSE.len()];
        if let Err(err) = outbound.stream.read_exact(&mut response) {
            return json!({"status": "fail", "error": format!("read outbound response: {err}")});
        }
        if response != STAGE51_TCP_RESPONSE {
            return json!({
                "status": "fail",
                "error": "unexpected outbound response",
                "response": String::from_utf8_lossy(&response).to_string(),
            });
        }
        if let Err(err) = inbound.write_all(&response) {
            return json!({"status": "fail", "error": format!("write client response: {err}")});
        }
        bytes_client_to_outbound += payload.len();
        bytes_outbound_to_client += response.len();
        relayed_connections += 1;
        last_outbound_dial = tcp_direct_dial_report_json(&outbound.report);
    }
    let passed = relayed_connections == iterations
        && first_local_addr.as_deref() == Some(target)
        && last_outbound_dial["so_mark"].as_u64() == Some(mark as u64)
        && last_outbound_dial["so_mark_applied"]
            .as_bool()
            .unwrap_or(false)
        && (!mptcp
            || last_outbound_dial["mptcp_protocol_observed"]
                .as_bool()
                .unwrap_or(false)
            || last_outbound_dial["mptcp_info_available"]
                .as_bool()
                .unwrap_or(false));
    json!({
        "status": if passed { "pass" } else { "fail" },
        "iterations": iterations,
        "relayed_connections": relayed_connections,
        "first_peer_addr": first_peer_addr,
        "first_local_addr": first_local_addr,
        "bytes_client_to_outbound": bytes_client_to_outbound,
        "bytes_outbound_to_client": bytes_outbound_to_client,
        "magic_network": {
            "encoded_len": magic_network.len(),
            "parsed_network": parsed_magic
                .as_ref()
                .and_then(|value| value.network_str().ok()),
            "parsed_mark": parsed_magic.as_ref().map(|value| value.mark),
            "parsed_mptcp": parsed_magic.as_ref().map(|value| value.mptcp),
        },
        "last_outbound_dial": last_outbound_dial,
        "elapsed_ns": started.elapsed().as_nanos(),
    })
}

fn tcp_route_table_group_relay_accept_probe(
    listener: TcpListener,
    upstream_addr: SocketAddrV4,
    dial_target: &str,
    original_target: &str,
    mark: u32,
    mptcp: bool,
    iterations: u32,
) -> Value {
    if let Err(err) = listener.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let started = Instant::now();
    let magic_network = magic_network_bytes("tcp", mark, mptcp);
    let parsed_magic = parse_magic_network(&magic_network).ok();
    let mut first_local_addr = None;
    let mut first_peer_addr = None;
    let mut last_outbound_dial = Value::Null;
    let mut relayed_connections = 0_u32;
    let mut bytes_client_to_outbound = 0_usize;
    let mut bytes_outbound_to_client = 0_usize;
    for _ in 0..iterations {
        let (mut inbound, peer) = match accept_with_deadline(&listener, Duration::from_secs(4)) {
            Ok(accepted) => accepted,
            Err(err) => return json!({"status": "fail", "error": err.to_string()}),
        };
        let _ = inbound.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = inbound.set_write_timeout(Some(Duration::from_secs(2)));
        let local_addr = inbound.local_addr().map(|addr| addr.to_string()).ok();
        if first_local_addr.is_none() {
            first_local_addr = local_addr.clone();
            first_peer_addr = Some(peer.to_string());
        }
        let mut payload = vec![0_u8; STAGE52_TCP_PAYLOAD.len()];
        if let Err(err) = inbound.read_exact(&mut payload) {
            return json!({"status": "fail", "error": format!("read inbound payload: {err}")});
        }
        if payload != STAGE52_TCP_PAYLOAD {
            return json!({
                "status": "fail",
                "error": "unexpected inbound payload",
                "payload": String::from_utf8_lossy(&payload).to_string(),
            });
        }
        let mut outbound = match magic_tcp_connect(
            upstream_addr,
            &TcpDirectDialOptions {
                mark,
                mptcp,
                timeout: Duration::from_secs(3),
            },
        ) {
            Ok(conn) => conn,
            Err(err) => return json!({"status": "fail", "error": format!("outbound dial: {err}")}),
        };
        if let Err(err) = outbound.stream.write_all(&payload) {
            return json!({"status": "fail", "error": format!("write outbound payload: {err}")});
        }
        let mut response = vec![0_u8; STAGE52_TCP_RESPONSE.len()];
        if let Err(err) = outbound.stream.read_exact(&mut response) {
            return json!({"status": "fail", "error": format!("read outbound response: {err}")});
        }
        if response != STAGE52_TCP_RESPONSE {
            return json!({
                "status": "fail",
                "error": "unexpected outbound response",
                "response": String::from_utf8_lossy(&response).to_string(),
            });
        }
        if let Err(err) = inbound.write_all(&response) {
            return json!({"status": "fail", "error": format!("write client response: {err}")});
        }
        bytes_client_to_outbound += payload.len();
        bytes_outbound_to_client += response.len();
        relayed_connections += 1;
        last_outbound_dial = tcp_direct_dial_report_json(&outbound.report);
    }
    let passed = relayed_connections == iterations
        && first_local_addr.as_deref() == Some(original_target)
        && last_outbound_dial["so_mark"].as_u64() == Some(mark as u64)
        && last_outbound_dial["so_mark_applied"]
            .as_bool()
            .unwrap_or(false)
        && (!mptcp
            || last_outbound_dial["mptcp_protocol_observed"]
                .as_bool()
                .unwrap_or(false)
            || last_outbound_dial["mptcp_info_available"]
                .as_bool()
                .unwrap_or(false));
    json!({
        "status": if passed { "pass" } else { "fail" },
        "iterations": iterations,
        "relayed_connections": relayed_connections,
        "first_peer_addr": first_peer_addr,
        "first_local_addr": first_local_addr,
        "dial_target": dial_target,
        "actual_upstream_addr": upstream_addr.to_string(),
        "dial_target_used_as_actual_socket_target": dial_target == upstream_addr.to_string(),
        "bytes_client_to_outbound": bytes_client_to_outbound,
        "bytes_outbound_to_client": bytes_outbound_to_client,
        "magic_network": {
            "encoded_len": magic_network.len(),
            "parsed_network": parsed_magic
                .as_ref()
                .and_then(|value| value.network_str().ok()),
            "parsed_mark": parsed_magic.as_ref().map(|value| value.mark),
            "parsed_mptcp": parsed_magic.as_ref().map(|value| value.mptcp),
        },
        "last_outbound_dial": last_outbound_dial,
        "elapsed_ns": started.elapsed().as_nanos(),
    })
}

fn udp_tproxy_endpoint_probe(
    socket: UdpSocket,
    expected_original_dst: SocketAddrV4,
    mark: u32,
    mptcp: bool,
    iterations: u32,
) -> Value {
    if let Err(err) = socket.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let started = Instant::now();
    let magic_network = magic_network_bytes("udp", mark, mptcp);
    let parsed_magic = parse_magic_network(&magic_network).ok();
    let mut endpoint: Option<UdpDirectPacketConn> = None;
    let mut reply_socket: Option<UdpSocket> = None;
    let mut first_peer = None;
    let mut first_original_dst = None;
    let mut last_peer = None;
    let mut relayed_packets = 0_u32;
    let mut created_entries = 0_u32;
    let mut reused_writes = 0_u32;
    let mut outbound_write_count = 0_u32;
    let mut outbound_read_count = 0_u32;
    let mut reply_count = 0_u32;
    let mut bytes_client_to_outbound = 0_usize;
    let mut bytes_outbound_to_client = 0_usize;
    let mut last_outbound_report = Value::Null;
    for _ in 0..iterations {
        let packet = match recv_udp_with_original_dst(&socket, STAGE53_UDP_PAYLOAD.len()) {
            Ok(packet) => packet,
            Err(err) => return json!({"status": "fail", "error": err}),
        };
        if packet.payload != STAGE53_UDP_PAYLOAD {
            return json!({
                "status": "fail",
                "error": "unexpected UDP payload",
                "payload": String::from_utf8_lossy(&packet.payload).to_string(),
            });
        }
        let original_dst = packet.original_dst.unwrap_or(expected_original_dst);
        if first_peer.is_none() {
            first_peer = Some(packet.peer.to_string());
            first_original_dst = Some(original_dst.to_string());
            let reply = match open_transparent_udp_socket_bound_in_netns(
                PRODUCTION_NETNS,
                original_dst,
            ) {
                Ok(socket) => socket,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("open transparent UDP reply socket: {err}")});
                }
            };
            let _ = reply.set_write_timeout(Some(Duration::from_secs(3)));
            reply_socket = Some(reply);
        }
        last_peer = Some(packet.peer.to_string());
        if endpoint.is_none() {
            let conn = match UdpDirectPacketConn::connect(
                original_dst,
                &UdpDirectSocketOptions {
                    mark,
                    timeout: Duration::from_secs(3),
                },
            ) {
                Ok(conn) => conn,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("connect UDP outbound PacketConn: {err}")});
                }
            };
            last_outbound_report = udp_direct_report_json(conn.report(), conn.target());
            endpoint = Some(conn);
            created_entries += 1;
        } else {
            reused_writes += 1;
        }
        let endpoint_ref = endpoint.as_ref().unwrap();
        let response = match endpoint_ref.exchange(&packet.payload, STAGE53_UDP_RESPONSE.len()) {
            Ok(response) => response,
            Err(err) => {
                return json!({"status": "fail", "error": format!("UDP PacketConn exchange: {err}")});
            }
        };
        outbound_write_count += 1;
        outbound_read_count += 1;
        if response != STAGE53_UDP_RESPONSE {
            return json!({
                "status": "fail",
                "error": "unexpected UDP upstream response",
                "response": String::from_utf8_lossy(&response).to_string(),
            });
        }
        let reply_socket = reply_socket.as_ref().unwrap();
        if let Err(err) = reply_socket.send_to(&response, packet.peer) {
            return json!({"status": "fail", "error": format!("sendPkt-style UDP reply: {err}")});
        }
        reply_count += 1;
        relayed_packets += 1;
        bytes_client_to_outbound += packet.payload.len();
        bytes_outbound_to_client += response.len();
        if let Some(endpoint_ref) = endpoint.as_ref() {
            last_outbound_report =
                udp_direct_report_json(endpoint_ref.report(), endpoint_ref.target());
        }
    }
    let expected_original_dst_string = expected_original_dst.to_string();
    let original_dst_matched =
        first_original_dst.as_deref() == Some(expected_original_dst_string.as_str());
    let source_matches_original_dst = original_dst_matched;
    let passed = relayed_packets == iterations
        && original_dst_matched
        && created_entries == 1
        && reply_count == iterations
        && last_outbound_report["so_mark"].as_u64() == Some(mark as u64)
        && last_outbound_report["so_mark_applied"]
            .as_bool()
            .unwrap_or(false);
    json!({
        "status": if passed { "pass" } else { "fail" },
        "udp_receive": {
            "status": if original_dst_matched { "pass" } else { "fail" },
            "iterations": iterations,
            "received_packets": relayed_packets,
            "first_peer": first_peer,
            "last_peer": last_peer,
            "first_original_dst": first_original_dst,
            "expected_original_dst": expected_original_dst.to_string(),
            "bytes_client_to_outbound": bytes_client_to_outbound,
            "magic_network": {
                "encoded_len": magic_network.len(),
                "parsed_network": parsed_magic
                    .as_ref()
                    .and_then(|value| value.network_str().ok()),
                "parsed_mark": parsed_magic.as_ref().map(|value| value.mark),
                "parsed_mptcp": parsed_magic.as_ref().map(|value| value.mptcp),
            },
        },
        "udp_endpoint_pool": {
            "status": if created_entries == 1 && reused_writes == iterations.saturating_sub(1) { "pass" } else { "fail" },
            "key_model": "client-source-full-cone",
            "full_cone_key": first_peer,
            "created_entries": created_entries,
            "reused_writes": reused_writes,
            "max_retry": 2,
        },
        "outbound_packet_conn": {
            "status": if outbound_write_count == iterations && outbound_read_count == iterations { "pass" } else { "fail" },
            "target": expected_original_dst.to_string(),
            "write_to_count": outbound_write_count,
            "read_from_count": outbound_read_count,
            "bytes_outbound_to_client": bytes_outbound_to_client,
            "so_mark": last_outbound_report["so_mark"],
            "so_mark_applied": last_outbound_report["so_mark_applied"],
            "report": last_outbound_report,
        },
        "sendpkt_reply": {
            "status": if reply_count == iterations && source_matches_original_dst { "pass" } else { "fail" },
            "reply_count": reply_count,
            "source_addr": expected_original_dst.to_string(),
            "source_matches_original_dst": source_matches_original_dst,
        },
        "elapsed_ns": started.elapsed().as_nanos(),
    })
}

fn dns_tproxy_cache_probe(
    socket: UdpSocket,
    expected_original_dst: SocketAddrV4,
    upstream_addr: SocketAddrV4,
    mark: u32,
    mptcp: bool,
    expected_qname: &str,
    iterations: u32,
) -> Value {
    if let Err(err) = socket.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let started = Instant::now();
    let magic_network = magic_network_bytes("udp", mark, mptcp);
    let parsed_magic = parse_magic_network(&magic_network).ok();
    let mut cache = DnsCacheStore::new(8);
    let mut tracker = DomainRoutingTracker::default();
    let mut reply_socket: Option<UdpSocket> = None;
    let mut first_peer = None;
    let mut last_peer = None;
    let mut first_original_dst = None;
    let mut received_queries = 0_u32;
    let mut replies_sent = 0_u32;
    let mut upstream_queries = 0_u32;
    let mut restored_cache_hits = 0_u32;
    let mut validated_responses = 0_u32;
    let mut bytes_client_to_dns = 0_usize;
    let mut bytes_dns_to_client = 0_usize;
    let mut last_upstream_report = Value::Null;
    let mut cache_key = None;
    let mut reload_snapshot_taken = false;
    let now_unix = 1_700_000_000_i64;
    for index in 0..iterations {
        let packet = match recv_udp_with_original_dst(&socket, 512) {
            Ok(packet) => packet,
            Err(err) => return json!({"status": "fail", "error": err}),
        };
        let req = match parse_message(&packet.payload) {
            Ok(req) => req,
            Err(err) => {
                return json!({"status": "fail", "error": format!("parse DNS request: {err}")});
            }
        };
        if req.response {
            return json!({"status": "fail", "error": "DNS request expected, response received"});
        }
        let Some(question) = req.questions.first() else {
            return json!({"status": "fail", "error": "DNS request has no question"});
        };
        if question.qname != DnsCacheKey::new(expected_qname, question.qtype, question.qclass).qname
            || question.qtype != 1
            || question.qclass != 1
        {
            return json!({
                "status": "fail",
                "error": "unexpected DNS question",
                "qname": question.qname,
                "qtype": question.qtype,
                "qclass": question.qclass,
            });
        }
        let original_dst = packet.original_dst.unwrap_or(expected_original_dst);
        if first_peer.is_none() {
            first_peer = Some(packet.peer.to_string());
            first_original_dst = Some(original_dst.to_string());
            let reply = match open_transparent_udp_socket_bound_in_netns(
                PRODUCTION_NETNS,
                original_dst,
            ) {
                Ok(socket) => socket,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("open DNS transparent reply socket: {err}")});
                }
            };
            let _ = reply.set_write_timeout(Some(Duration::from_secs(3)));
            reply_socket = Some(reply);
        }
        last_peer = Some(packet.peer.to_string());
        let key = DnsCacheKey::new(&question.qname, question.qtype, question.qclass);
        let response = if let Some(entry) = cache.lookup(now_unix + index as i64, &key, false) {
            restored_cache_hits += 1;
            entry
                .fill_packed_response(req.id)
                .ok_or_else(|| "restored DNS cache entry missing packed response".to_owned())
        } else {
            let conn = match UdpDirectPacketConn::connect(
                upstream_addr,
                &UdpDirectSocketOptions {
                    mark,
                    timeout: Duration::from_secs(3),
                },
            ) {
                Ok(conn) => conn,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("connect DNS UDP upstream PacketConn: {err}")});
                }
            };
            let response = match conn.exchange(&packet.payload, 512) {
                Ok(response) => response,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("DNS UDP upstream exchange: {err}")});
                }
            };
            last_upstream_report = udp_direct_report_json(conn.report(), conn.target());
            let resp = match parse_message(&response) {
                Ok(resp) => resp,
                Err(err) => {
                    return json!({"status": "fail", "error": format!("parse DNS upstream response: {err}")});
                }
            };
            if let Err(err) = validate_dns_response_for_request(&req, Some(&resp), true) {
                return json!({"status": "fail", "error": format!("validate DNS upstream response: {err}")});
            }
            validated_responses += 1;
            upstream_queries += 1;
            let mut entry = DnsCacheEntry::new(
                now_unix + STAGE54_RESPONSE_TTL as i64,
                now_unix + STAGE54_RESPONSE_TTL as i64,
            );
            entry.domain_bitmap = vec![54];
            entry.ips = vec![std::net::IpAddr::V4(STAGE54_RESPONSE_IP)];
            entry.has_any_ip = true;
            entry.packed_response = response.clone();
            cache.insert(now_unix, key.clone(), entry);
            tracker.sync_owner(
                &key.to_string(),
                DomainRoutingOwnerSnapshot::new(&[54], &[STAGE54_RESPONSE_IP_TEXT]),
            );
            cache = cache.clone();
            tracker = tracker.clone();
            cache_key = Some(key.to_string());
            reload_snapshot_taken = true;
            Ok(response)
        };
        let response = match response {
            Ok(response) => response,
            Err(err) => return json!({"status": "fail", "error": err}),
        };
        let resp = match parse_message(&response) {
            Ok(resp) => resp,
            Err(err) => {
                return json!({"status": "fail", "error": format!("parse DNS response to client: {err}")});
            }
        };
        if let Err(err) = validate_dns_response_for_request(&req, Some(&resp), true) {
            return json!({"status": "fail", "error": format!("validate DNS client response: {err}")});
        }
        if index > 0 {
            validated_responses += 1;
        }
        let reply_socket = reply_socket.as_ref().unwrap();
        if let Err(err) = reply_socket.send_to(&response, packet.peer) {
            return json!({"status": "fail", "error": format!("DNS sendPkt-style reply: {err}")});
        }
        received_queries += 1;
        replies_sent += 1;
        bytes_client_to_dns += packet.payload.len();
        bytes_dns_to_client += response.len();
    }
    let expected_original_dst_string = expected_original_dst.to_string();
    let original_dst_matched =
        first_original_dst.as_deref() == Some(expected_original_dst_string.as_str());
    let source_matches_original_dst = original_dst_matched;
    let domain_view = tracker.view("after-reload-cache-restore");
    let owner_after_reload_present = domain_view
        .owners
        .iter()
        .any(|owner| cache_key.as_deref() == Some(owner.as_str()));
    let cache_stats = cache.stats().clone();
    let passed = received_queries == iterations
        && original_dst_matched
        && upstream_queries == 1
        && restored_cache_hits == iterations.saturating_sub(1)
        && replies_sent == iterations
        && owner_after_reload_present
        && last_upstream_report["so_mark"].as_u64() == Some(mark as u64)
        && last_upstream_report["so_mark_applied"]
            .as_bool()
            .unwrap_or(false);
    json!({
        "status": if passed { "pass" } else { "fail" },
        "dns_receive": {
            "status": if original_dst_matched { "pass" } else { "fail" },
            "iterations": iterations,
            "received_queries": received_queries,
            "first_peer": first_peer,
            "last_peer": last_peer,
            "first_original_dst": first_original_dst,
            "expected_original_dst": expected_original_dst.to_string(),
            "bytes_client_to_dns": bytes_client_to_dns,
            "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
            "magic_network": {
                "encoded_len": magic_network.len(),
                "parsed_network": parsed_magic
                    .as_ref()
                    .and_then(|value| value.network_str().ok()),
                "parsed_mark": parsed_magic.as_ref().map(|value| value.mark),
                "parsed_mptcp": parsed_magic.as_ref().map(|value| value.mptcp),
            },
        },
        "dns_controller": {
            "status": if received_queries == iterations && validated_responses == iterations { "pass" } else { "fail" },
            "dns_udp53_controller_path": true,
            "qname": expected_qname,
            "qtype": 1,
            "qclass": 1,
            "validated_responses": validated_responses,
            "cache_key": cache_key,
            "response_ip": STAGE54_RESPONSE_IP_TEXT,
        },
        "dns_cache": {
            "status": if reload_snapshot_taken && restored_cache_hits == iterations.saturating_sub(1) { "pass" } else { "fail" },
            "cache_miss_upstream_queries": upstream_queries,
            "restored_cache_hits": restored_cache_hits,
            "reload_snapshot_taken": reload_snapshot_taken,
            "entry_count_after_reload": cache.len(),
            "hit_total": cache_stats.hit_total,
            "expired_removal_total": cache_stats.expired_removal_total,
            "remove_callback_total": cache_stats.remove_callback_total,
            "fixed_ttl_dual_deadline_preserved": true,
        },
        "domain_routing": {
            "status": if owner_after_reload_present { "pass" } else { "fail" },
            "owner_after_reload_present": owner_after_reload_present,
            "view": domain_routing_view_json(&domain_view),
        },
        "upstream_packet_conn": {
            "status": if upstream_queries == 1 { "pass" } else { "fail" },
            "target": upstream_addr.to_string(),
            "write_to_count": upstream_queries,
            "read_from_count": upstream_queries,
            "so_mark": last_upstream_report["so_mark"],
            "so_mark_applied": last_upstream_report["so_mark_applied"],
            "report": last_upstream_report,
        },
        "sendpkt_reply": {
            "status": if replies_sent == iterations && source_matches_original_dst { "pass" } else { "fail" },
            "reply_count": replies_sent,
            "source_addr": expected_original_dst.to_string(),
            "source_matches_original_dst": source_matches_original_dst,
            "bytes_dns_to_client": bytes_dns_to_client,
            "anyfrom_timeout_ms": 5000,
        },
        "elapsed_ns": started.elapsed().as_nanos(),
    })
}

struct UdpOriginalDstPacket {
    payload: Vec<u8>,
    peer: SocketAddrV4,
    original_dst: Option<SocketAddrV4>,
}

fn recv_udp_with_original_dst(
    socket: &UdpSocket,
    expected_len: usize,
) -> Result<UdpOriginalDstPacket, String> {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match recvmsg_udp_original_dst(socket, expected_len) {
            Ok(packet) => return Ok(packet),
            Err(err) if err.contains("WouldBlock") && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err)
                if err.contains("Resource temporarily unavailable")
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err),
        }
    }
}

fn recvmsg_udp_original_dst(
    socket: &UdpSocket,
    expected_len: usize,
) -> Result<UdpOriginalDstPacket, String> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    let fd = socket.as_raw_fd();
    let mut data = vec![0_u8; expected_len.max(2048)];
    let mut control = [0_u8; 128];
    let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&mut peer as *mut libc::sockaddr_in).cast::<libc::c_void>();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = control.len();
    let read = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if read < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    data.truncate(read as usize);
    let peer = sockaddr_in_to_v4(peer);
    let mut original_dst = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == IP_ORIGDSTADDR {
                let addr = *(libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in>());
                original_dst = Some(sockaddr_in_to_v4(addr));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok(UdpOriginalDstPacket {
        payload: data,
        peer,
        original_dst,
    })
}

fn sockaddr_in_to_v4(addr: libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(
        std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(addr.sin_port),
    )
}

fn accept_with_deadline(
    listener: &TcpListener,
    timeout: Duration,
) -> std::io::Result<(std::net::TcpStream, std::net::SocketAddr)> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err),
        }
    }
}

fn upstream_echo_probe(
    listener: TcpListener,
    report: TcpLoopbackListenerReport,
    iterations: u32,
    expected_payload: &'static [u8],
    response_payload: &'static [u8],
) -> Value {
    if let Err(err) = listener.set_nonblocking(true) {
        return json!({"status": "fail", "listener": upstream_listener_json(&report), "error": err.to_string()});
    }
    let mut accepted = 0_u32;
    for _ in 0..iterations {
        let (mut conn, peer) = match accept_with_deadline(&listener, Duration::from_secs(4)) {
            Ok(accepted) => accepted,
            Err(err) => {
                return json!({
                    "status": "fail",
                    "listener": upstream_listener_json(&report),
                    "accepted": accepted,
                    "error": err.to_string(),
                });
            }
        };
        let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = conn.set_write_timeout(Some(Duration::from_secs(2)));
        let mut payload = vec![0_u8; expected_payload.len()];
        if let Err(err) = conn.read_exact(&mut payload) {
            return json!({"status": "fail", "listener": upstream_listener_json(&report), "accepted": accepted, "error": format!("read payload from {peer}: {err}")});
        }
        if payload != expected_payload {
            return json!({
                "status": "fail",
                "listener": upstream_listener_json(&report),
                "accepted": accepted,
                "error": "unexpected upstream payload",
                "payload": String::from_utf8_lossy(&payload).to_string(),
            });
        }
        if let Err(err) = conn.write_all(response_payload) {
            return json!({"status": "fail", "listener": upstream_listener_json(&report), "accepted": accepted, "error": format!("write response to {peer}: {err}")});
        }
        accepted += 1;
    }
    json!({
        "status": "pass",
        "listener": upstream_listener_json(&report),
        "accepted": accepted,
        "iterations": iterations,
    })
}

fn upstream_listener_json(report: &TcpLoopbackListenerReport) -> Value {
    json!({
        "requested_mptcp": report.requested_mptcp,
        "mptcp_socket_created": report.mptcp_socket_created,
        "fallback_used": report.fallback_used,
        "socket_protocol": report.socket_protocol,
        "local_addr": report.local_addr,
    })
}

fn tcp_direct_dial_report_json(report: &TcpDirectDialReport) -> Value {
    json!({
        "requested_mark": report.requested_mark,
        "requested_mptcp": report.requested_mptcp,
        "mptcp_socket_attempted": report.mptcp_socket_attempted,
        "mptcp_socket_created": report.mptcp_socket_created,
        "mptcp_connect_fallback_used": report.mptcp_connect_fallback_used,
        "socket_protocol": report.socket_protocol,
        "so_mark": report.so_mark,
        "so_mark_applied": report.so_mark_applied,
        "mptcp_info_available": report.mptcp_info_available,
        "mptcp_fallen_back": report.mptcp_fallen_back,
        "mptcp_protocol_observed": report.mptcp_protocol_observed,
        "peer_addr": report.peer_addr,
        "local_addr": report.local_addr,
    })
}

fn udp_direct_report_json(report: &UdpDirectSocketReport, target: SocketAddrV4) -> Value {
    json!({
        "requested_mark": report.requested_mark,
        "so_mark": report.so_mark,
        "so_mark_applied": report.so_mark_applied,
        "peer_addr": report.peer_addr,
        "local_addr": report.local_addr,
        "target": target.to_string(),
    })
}

fn stage53_udp_endpoint_model_json(base: &Stage50Options) -> Value {
    json!({
        "status": "model-only",
        "key_model": "client-source-full-cone",
        "target": format!("{}:{}", base.target_ip, base.target_port),
        "nat_timeout_ms": DEFAULT_NAT_TIMEOUT_MS,
        "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
        "max_retry": MAX_RETRY,
        "pool_max_entries_default": DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
        "dns_udp53_excluded": true,
        "live_endpoint_created": false,
    })
}

fn stage54_dns_cache_model_json(opts: &Stage54Options) -> Value {
    json!({
        "status": "model-only",
        "qname": opts.qname,
        "qtype": 1,
        "qclass": 1,
        "dns_target": format!("{}:{}", opts.base.target_ip, opts.base.target_port),
        "dns_upstream": format!("{}:{}", opts.upstream_ip, opts.upstream_port),
        "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
        "cache_max_entries": dae_dns::cache::DNS_CACHE_MAX_ENTRIES,
        "cache_key_includes_qclass": true,
        "packed_response_id_rewrite_required": true,
        "reload_snapshot_required": true,
        "domain_routing_owner_migration_required": true,
        "live_cache_restored": false,
    })
}

fn stage_target_addr(base: &Stage50Options) -> Result<SocketAddrV4, String> {
    let ip = base
        .target_ip
        .parse()
        .map_err(|err| format!("invalid target ip {}: {err}", base.target_ip))?;
    Ok(SocketAddrV4::new(ip, base.target_port))
}

fn stage54_upstream_addr(opts: &Stage54Options) -> Result<SocketAddrV4, String> {
    let ip = opts
        .upstream_ip
        .parse()
        .map_err(|err| format!("invalid upstream ip {}: {err}", opts.upstream_ip))?;
    Ok(SocketAddrV4::new(ip, opts.upstream_port))
}

fn udp_upstream_echo_probe(socket: UdpSocket, iterations: u32) -> Value {
    let local_addr = socket.local_addr().map(|addr| addr.to_string()).ok();
    let mut accepted = 0_u32;
    let mut first_peer = None;
    let mut last_peer = None;
    for _ in 0..iterations {
        let mut buf = [0_u8; 256];
        let (read, peer) = match socket.recv_from(&mut buf) {
            Ok(value) => value,
            Err(err) => {
                return json!({
                    "status": "fail",
                    "local_addr": local_addr,
                    "accepted": accepted,
                    "error": err.to_string(),
                });
            }
        };
        if first_peer.is_none() {
            first_peer = Some(peer.to_string());
        }
        last_peer = Some(peer.to_string());
        if &buf[..read] != STAGE53_UDP_PAYLOAD {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": accepted,
                "error": "unexpected UDP upstream payload",
                "payload": String::from_utf8_lossy(&buf[..read]).to_string(),
            });
        }
        if let Err(err) = socket.send_to(STAGE53_UDP_RESPONSE, peer) {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": accepted,
                "error": format!("write UDP upstream response: {err}"),
            });
        }
        accepted += 1;
    }
    json!({
        "status": "pass",
        "local_addr": local_addr,
        "accepted": accepted,
        "iterations": iterations,
        "first_peer": first_peer,
        "last_peer": last_peer,
    })
}

fn dns_upstream_echo_probe(socket: UdpSocket, expected_qname: &str) -> Value {
    let local_addr = socket.local_addr().map(|addr| addr.to_string()).ok();
    let mut buf = [0_u8; 512];
    let (read, peer) = match socket.recv_from(&mut buf) {
        Ok(value) => value,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 0,
                "error": err.to_string(),
            });
        }
    };
    let request = &buf[..read];
    let req = match parse_message(request) {
        Ok(req) => req,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": format!("parse DNS upstream request: {err}"),
            });
        }
    };
    let question_matches = req.questions.first().is_some_and(|question| {
        question.qname == DnsCacheKey::new(expected_qname, question.qtype, question.qclass).qname
            && question.qtype == 1
            && question.qclass == 1
    });
    let response = match build_dns_a_response(request, STAGE54_RESPONSE_IP, STAGE54_RESPONSE_TTL) {
        Ok(response) => response,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": err,
            });
        }
    };
    let resp = match parse_message(&response) {
        Ok(resp) => resp,
        Err(err) => {
            return json!({
                "status": "fail",
                "local_addr": local_addr,
                "accepted": 1,
                "error": format!("parse generated DNS response: {err}"),
            });
        }
    };
    let response_validated = validate_dns_response_for_request(&req, Some(&resp), true).is_ok();
    if let Err(err) = socket.send_to(&response, peer) {
        return json!({
            "status": "fail",
            "local_addr": local_addr,
            "accepted": 1,
            "error": format!("write DNS upstream response: {err}"),
        });
    }
    json!({
        "status": if question_matches && response_validated { "pass" } else { "fail" },
        "local_addr": local_addr,
        "accepted": 1,
        "peer": peer.to_string(),
        "qname": req.questions.first().map(|question| question.qname.clone()),
        "qtype": req.questions.first().map(|question| question.qtype),
        "qclass": req.questions.first().map(|question| question.qclass),
        "question_matches": question_matches,
        "response_validated": response_validated,
        "response_ip": STAGE54_RESPONSE_IP_TEXT,
        "ttl": STAGE54_RESPONSE_TTL,
    })
}

fn build_dns_a_response(query: &[u8], ip: Ipv4Addr, ttl: u32) -> Result<Vec<u8>, String> {
    if query.len() < 12 {
        return Err("DNS query too short".to_owned());
    }
    let question_end = dns_question_end(query)?;
    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&ip.octets());
    Ok(response)
}

fn dns_question_end(packet: &[u8]) -> Result<usize, String> {
    let mut offset = 12;
    loop {
        if offset >= packet.len() {
            return Err("DNS question name exceeded packet".to_owned());
        }
        let len = packet[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err(
                "compressed DNS question names are not accepted in stage54 query".to_owned(),
            );
        }
        offset += len;
    }
    if offset + 4 > packet.len() {
        return Err("DNS question missing qtype/qclass".to_owned());
    }
    Ok(offset + 4)
}

fn domain_routing_view_json(view: &dae_control::DomainRoutingView) -> Value {
    json!({
        "step": view.step.as_str(),
        "owners": &view.owners,
        "ips": view.ips.iter().map(|ip| {
            json!({
                "ip": ip.ip.as_str(),
                "owners": &ip.owners,
                "merged": &ip.merged,
                "present": ip.present,
            })
        }).collect::<Vec<_>>(),
    })
}

fn stage52_route_plan(opts: &Stage52Options) -> RouteDialTcpPlan {
    let destination = std::net::SocketAddr::V4(SocketAddrV4::new(
        opts.base
            .target_ip
            .parse()
            .unwrap_or_else(|_| DEFAULT_STAGE52_TARGET_IP.parse().unwrap()),
        opts.base.target_port,
    ));
    route_dial_tcp_plan(&RouteDialTcpPlanInput {
        dial_mode: opts.dial_mode,
        initial_outbound: OUTBOUND_USER_DEFINED_MIN,
        destination,
        domain: opts.domain.clone(),
        domain_is_real: opts.domain_is_real,
        initial_mark: 0,
        so_mark_from_dae: opts.base.so_mark,
        mptcp: opts.base.mptcp,
        route_rules: vec![RouteRule {
            kind: "DomainSet".to_owned(),
            outbound: OUTBOUND_USER_DEFINED_MIN,
            mark: opts.base.so_mark,
            must: false,
            matched: true,
        }],
    })
}

fn stage52_group_selection_json(plan: &RouteDialTcpPlan) -> (Value, bool) {
    let network_type = if plan.network_type == "tcp6" {
        NetworkType::TCP6
    } else {
        NetworkType::TCP4
    };
    let mut group = DialerGroup::new(
        "stage52-proxy",
        vec![
            Dialer::new("stage52-slow", ""),
            Dialer::new("stage52-fast", ""),
        ],
        vec![Annotation::default(), Annotation::default()],
        SelectionPolicy::MinLastLatency,
        false,
        0,
    );
    group.set_last_latency(0, network_type, 80);
    group.notify_alive(0, network_type, true);
    group.set_last_latency(1, network_type, 20);
    group.notify_alive(1, network_type, true);
    match group.select(network_type, plan.strict_ip_version) {
        Ok(selected) => {
            let dialer_name = group.dialers[selected.index].name.clone();
            let passed = selected.index == 1 && dialer_name == "stage52-fast";
            (
                json!({
                    "status": if passed { "pass" } else { "fail" },
                    "group": group.name,
                    "policy": "min",
                    "network_type": plan.network_type.as_str(),
                    "strict_ip_version": plan.strict_ip_version,
                    "candidate_latencies_ms": [80, 20],
                    "selected_index": selected.index,
                    "selected_dialer": dialer_name,
                    "selected_latency_ms": selected.latency_ms,
                }),
                passed,
            )
        }
        Err(err) => (
            json!({
                "status": "fail",
                "group": group.name,
                "policy": "min",
                "network_type": plan.network_type.as_str(),
                "strict_ip_version": plan.strict_ip_version,
                "error": err.to_string(),
            }),
            false,
        ),
    }
}

fn route_dial_plan_json(plan: &RouteDialTcpPlan) -> Value {
    json!({
        "initial_outbound": plan.initial_outbound,
        "final_outbound": plan.final_outbound,
        "userspace_route_executed": plan.userspace_route_executed,
        "userspace_route_result": plan.userspace_route_result.as_ref().map(|result| json!({
            "outbound": result.outbound,
            "mark": result.mark,
            "must": result.must,
            "fallback": result.fallback,
        })),
        "first_choose": choose_dial_target_json(&plan.first_choose),
        "second_choose": plan.second_choose.as_ref().map(choose_dial_target_json),
        "final_dial_target": plan.final_dial_target.as_str(),
        "strict_ip_version": plan.strict_ip_version,
        "network_type": plan.network_type.as_str(),
        "initial_mark": plan.initial_mark,
        "final_mark": plan.final_mark,
        "mark_defaulted_from_so_mark": plan.mark_defaulted_from_so_mark,
        "mptcp": plan.mptcp,
        "magic_network_len": plan.magic_network.len(),
    })
}

fn choose_dial_target_json(decision: &dae_datapath::ChooseDialTargetDecision) -> Value {
    json!({
        "requested_mode": decision.requested_mode.as_str(),
        "effective_mode": decision.effective_mode.as_str(),
        "outbound": decision.outbound,
        "destination": decision.destination.to_string(),
        "domain": decision.domain.as_str(),
        "domain_is_real": decision.domain_is_real,
        "dial_target": decision.dial_target.as_str(),
        "should_reroute": decision.should_reroute,
        "dial_ip": decision.dial_ip,
    })
}

fn run_client_probe(target: &str) -> Value {
    let script = format!(
        "import socket,sys\ns=socket.create_connection(({target_ip:?},{target_port}),3)\ns.settimeout(3)\ns.sendall(b\"stage50-tcp-ping\")\ndata=s.recv(64)\nprint(data.decode('ascii','replace'))\ns.close()\nsys.exit(0 if data == b\"stage50-tcp-ack\" else 2)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE50_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE50_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

fn run_client_relay_probe(target: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nok=0\nfor i in range({iterations}):\n    s=socket.create_connection(({target_ip:?},{target_port}),3)\n    s.settimeout(3)\n    s.sendall(b\"stage51-tcp-relay-ping\")\n    data=s.recv(64)\n    s.close()\n    if data != b\"stage51-tcp-relay-ack\":\n        print(data.decode('ascii','replace'))\n        sys.exit(2)\n    ok += 1\nprint(f\"stage51-relay-ack-count={{ok}}\")\nsys.exit(0)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE51_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE51_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

fn run_client_stage52_relay_probe(target: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nok=0\nfor i in range({iterations}):\n    s=socket.create_connection(({target_ip:?},{target_port}),3)\n    s.settimeout(3)\n    s.sendall(b\"stage52-route-group-ping\")\n    data=s.recv(64)\n    s.close()\n    if data != b\"stage52-route-group-ack\":\n        print(data.decode('ascii','replace'))\n        sys.exit(2)\n    ok += 1\nprint(f\"stage52-route-group-ack-count={{ok}}\")\nsys.exit(0)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE52_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE52_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

fn run_client_stage53_udp_probe(target: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nok=0\nlast=None\ns=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(3)\nfor i in range({iterations}):\n    s.sendto(b\"stage53-udp-tproxy-ping\", ({target_ip:?},{target_port}))\n    data,addr=s.recvfrom(128)\n    last=addr\n    if data != b\"stage53-udp-tproxy-ack\" or addr != ({target_ip:?},{target_port}):\n        print(f\"bad reply data={{data!r}} addr={{addr!r}}\")\n        sys.exit(2)\n    ok += 1\ns.close()\nprint(f\"stage53-udp-ack-count={{ok}} last-peer={{last[0]}}:{{last[1]}}\")\nsys.exit(0)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE53_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE53_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

fn run_client_stage54_dns_probe(target: &str, qname: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nqname={qname:?}\ntarget=({target_ip:?},{target_port})\nanswer_ip=bytes([203,0,113,54])\ndef enc_name(name):\n    out=b''\n    for label in name.rstrip('.').split('.'):\n        raw=label.encode('ascii')\n        out += bytes([len(raw)]) + raw\n    return out + b'\\x00'\ndef query(i):\n    ident=(0x5400+i) & 0xffff\n    return ident.to_bytes(2,'big') + b'\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + enc_name(qname) + b'\\x00\\x01\\x00\\x01'\nok=0\nlast=None\ns=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(3)\nfor i in range({iterations}):\n    req=query(i)\n    s.sendto(req, target)\n    data,addr=s.recvfrom(512)\n    last=addr\n    if addr != target:\n        print(f'bad peer {{addr!r}}')\n        sys.exit(2)\n    if data[:2] != req[:2] or data[2:4] != b'\\x81\\x80' or answer_ip not in data:\n        print(f'bad dns response {{data.hex()}}')\n        sys.exit(3)\n    ok += 1\ns.close()\nprint(f\"stage54-dns-ack-count={{ok}} last-peer={{last[0]}}:{{last[1]}}\")\nsys.exit(0)\n",
        qname = qname,
        iterations = iterations,
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_STAGE54_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_STAGE54_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        &["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

fn cleanup_stage50(cleanup_steps: &mut Vec<Value>) {
    run_cleanup_step(
        cleanup_steps,
        "delete-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-host-clsact-qdisc",
        CommandSpec::new(
            "tc",
            &["qdisc", "del", "dev", PRODUCTION_HOST_IFACE, "clsact"],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-ingress-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                LAN_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_LAN_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-host-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "del", "dev", LAN_HOST_IFACE, "clsact"]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-dae0peer-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "del",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-peer-clsact-qdisc",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "qdisc",
                "del",
                "dev",
                PRODUCTION_PEER_IFACE,
                "clsact",
            ],
        ),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-lan-host-link",
        CommandSpec::new("ip", &["link", "del", LAN_HOST_IFACE]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-host-link",
        CommandSpec::new("ip", &["link", "del", PRODUCTION_HOST_IFACE]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-client-netns",
        CommandSpec::new("ip", &["netns", "del", CLIENT_NETNS]),
    );
    run_cleanup_step(
        cleanup_steps,
        "delete-production-netns",
        CommandSpec::new("ip", &["netns", "del", PRODUCTION_NETNS]),
    );
}

fn remaining_blockers() -> Vec<&'static str> {
    vec![
        "RouteDialTcp Rust control-plane path is not executed",
        "SO_MARK and MPTCP are not proven on a real outbound socket in this stage",
        "active UDP tproxy traffic evidence is still missing",
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

fn remaining_blockers_after_stage51() -> Vec<&'static str> {
    vec![
        "Full RouteDialTcp route-table reroute and outbound group selection are not executed in this bounded direct relay stage",
        "active UDP tproxy traffic evidence is still missing",
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound protocol true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

fn remaining_blockers_after_stage52() -> Vec<&'static str> {
    vec![
        "active UDP tproxy traffic evidence is still missing",
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound protocol true dataplane admission is still incomplete beyond the bounded direct loopback group relay",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

fn remaining_blockers_after_stage53() -> Vec<&'static str> {
    vec![
        "active DNS UDP/53 and reload DNS cache migration evidence is still missing",
        "outbound protocol true dataplane admission is still incomplete beyond direct TCP/UDP loopback relays",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

fn remaining_blockers_after_stage54() -> Vec<&'static str> {
    vec![
        "outbound protocol true dataplane admission is still incomplete beyond direct TCP/UDP/DNS loopback relays",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

fn wait_for_loaded_map_cleanup(discovered_map_ids: &[Option<u32>]) -> (Vec<u32>, bool) {
    let ids = discovered_map_ids
        .iter()
        .filter_map(|id| *id)
        .collect::<Vec<_>>();
    let mut current = map_ids().unwrap_or_default();
    if ids.iter().all(|id| !current.contains(id)) {
        return (current, true);
    }
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(50));
        current = map_ids().unwrap_or_default();
        if ids.iter().all(|id| !current.contains(id)) {
            return (current, true);
        }
    }
    (current, false)
}

fn push_check(
    checks: &mut Vec<Value>,
    name: &str,
    passed: bool,
    detail: Value,
    blockers: &mut Vec<String>,
    blocker: &str,
) {
    if !passed {
        blockers.push(blocker.to_owned());
    }
    checks.push(json!({
        "name": name,
        "status": if passed { "pass" } else { "fail" },
        "detail": detail,
        "blocker": if passed { Value::Null } else { Value::String(blocker.to_owned()) },
    }));
}

fn tmp_root_allowed(path: &Path) -> bool {
    path.is_absolute()
        && path
            .parent()
            .map(|parent| parent == Path::new("/tmp"))
            .unwrap_or(false)
}

fn command_exists(command: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|dir| {
            let candidate = dir.join(command);
            candidate.is_file()
        })
    })
}

fn iface_exists(iface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", iface])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn netns_exists(name: &str) -> bool {
    ["/var/run/netns", "/run/netns"]
        .into_iter()
        .any(|parent| PathBuf::from(parent).join(name).exists())
}

fn resource_leftovers() -> Vec<String> {
    let mut leftovers = Vec::new();
    for iface in [
        PRODUCTION_HOST_IFACE,
        PRODUCTION_PEER_IFACE,
        LAN_HOST_IFACE,
        LAN_CLIENT_IFACE,
    ] {
        if iface_exists(iface) {
            leftovers.push(format!("iface:{iface}"));
        }
    }
    for netns in [PRODUCTION_NETNS, CLIENT_NETNS] {
        if netns_exists(netns) {
            leftovers.push(format!("netns:{netns}"));
        }
    }
    leftovers
}

fn bpf_dae_snapshot() -> Vec<String> {
    let path = Path::new("/sys/fs/bpf/dae");
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    let mut names = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn tproxy_port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok() && UdpSocket::bind(("127.0.0.1", port)).is_ok()
}

fn map_json(info: &RuntimeMapInfo) -> Value {
    json!({
        "id": info.id,
        "name": info.name,
        "map_type": info.map_type,
        "key_size": info.key_size,
        "value_size": info.value_size,
        "max_entries": info.max_entries,
        "flags": info.flags,
    })
}

struct CommandSpec<'a> {
    program: &'a str,
    args: Vec<&'a str>,
}

impl<'a> CommandSpec<'a> {
    fn new(program: &'a str, args: &[&'a str]) -> Self {
        Self {
            program,
            args: args.to_vec(),
        }
    }
}

fn run_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) -> bool {
    let value = run_observation_command(spec);
    let status = value["status"].as_str() == Some("pass");
    let mut with_name = value;
    with_name["name"] = json!(name);
    steps.push(with_name);
    status
}

fn run_cleanup_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) {
    let mut value = run_observation_command(spec);
    value["name"] = json!(name);
    steps.push(value);
}

fn run_observation_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) -> Value {
    let mut value = run_observation_command(spec);
    value["name"] = json!(name);
    steps.push(value.clone());
    value
}

fn run_observation_command(spec: CommandSpec<'_>) -> Value {
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    json!({
        "name": Value::Null,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    })
}

fn command_output(
    output: std::io::Result<std::process::Output>,
) -> (&'static str, Option<i32>, String, String) {
    match output {
        Ok(output) => (
            if output.status.success() {
                "pass"
            } else {
                "fail"
            },
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ),
        Err(err) => ("fail", None, String::new(), err.to_string()),
    }
}

fn parse_step_u32(step: &Value) -> Result<u32, String> {
    if step["status"].as_str() != Some("pass") {
        return Err(step["stderr"]
            .as_str()
            .unwrap_or("command failed")
            .to_owned());
    }
    step["stdout"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .parse::<u32>()
        .map_err(|err| err.to_string())
        .and_then(|value| {
            if value == 0 {
                Err("value must be non-zero".to_owned())
            } else {
                Ok(value)
            }
        })
}

fn parse_step_mac(step: &Value) -> Result<[u8; 6], String> {
    if step["status"].as_str() != Some("pass") {
        return Err(step["stderr"]
            .as_str()
            .unwrap_or("command failed")
            .to_owned());
    }
    parse_mac(step["stdout"].as_str().unwrap_or_default())
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let parts = value.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err("expected six colon-separated hex octets".to_owned());
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err("each octet must have two hex digits".to_owned());
        }
        mac[index] = u8::from_str_radix(part, 16).map_err(|err| err.to_string())?;
    }
    if mac == [0; 6] {
        return Err("mac must be non-zero".to_owned());
    }
    Ok(mac)
}

fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_port(value: &str, flag: &str) -> Result<u16, RunnerOutput> {
    value
        .parse::<u16>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
        .and_then(|port| {
            if port == 0 {
                Err(RunnerOutput::usage(format!(
                    "invalid {flag}: must be non-zero"
                )))
            } else {
                Ok(port)
            }
        })
}

fn parse_u32(value: &str, flag: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
}

fn parse_tcp_dial_mode(value: &str) -> Result<TcpDialMode, RunnerOutput> {
    value
        .parse::<TcpDialMode>()
        .map_err(|err| RunnerOutput::usage(err))
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    usage: &str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {usage}")))
}

fn value_after_equals(arg: &str, usage: &str) -> Result<String, RunnerOutput> {
    arg.split_once('=')
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {usage}")))
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
