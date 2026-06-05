use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::mem::size_of;
use std::net::{
    IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::slice;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use dae_core_types::OutboundIndex;
use dae_datapath::{
    OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT, TcpDialMode,
    TcpDirectDialReport, choose_dial_target,
};
use dae_ebpf_support::{
    BpfIpBytes, BpfRoutingResult, BpfTuplesKey, lookup_map_elem_bytes, open_map_fd,
};
use dae_outbound::{
    anytls::{AnyTlsFrame, contract as anytls_contract, link as anytls_link},
    http_proxy::{HttpConnectOptions, request as http_request},
    hysteria2::{
        authenticate_hysteria2_connection, build_hysteria2_pinned_client_config,
        read_hysteria2_tcp_response, write_hysteria2_tcp_request,
    },
    juicity::{
        authenticate_juicity_connection, build_juicity_runtime_client_config,
        write_juicity_tcp_request,
    },
    shadowsocks::{AeadStreamCodec, ShadowsocksMetadata, read_encrypted_chunk_from_stream},
    socks5::{Socks5Address, handshake},
    trojan::packet as trojan_packet,
    tuic::{
        authenticate_tuic_connection, build_tuic_runtime_client_config, write_tuic_connect_request,
    },
    vless::packet,
    vmess::{
        VMessAeadTcpClientSessionStart, aead_tcp_client_session_start,
        aead_tcp_response_reader_from_stream,
    },
};
use dae_routing::{Query, RoutingMatcher};
use dae_sniffing::{SniffingError, sniff_tcp};
use serde_json::{Value, json};

use super::ResidentDataplaneMetrics;
use super::client::{
    AsyncResidentTlsClient, AsyncVlessTlsClient, TlsDriveOutcome, VlessTlsClient,
    async_resident_tls_underlay_name, async_tls_underlay_name, drive_tls_io_record_aware,
    open_async_resident_tls_client, open_async_vless_tls_client, open_vless_tls_client,
    tls_underlay_name,
};
use super::direct::{
    DirectTcpConnection, DirectTcpRelayStats, open_direct_tcp_connection,
    open_direct_tcp_connection_async, relay_tcp_direct, relay_tcp_direct_async,
};
use super::events::append_event;
use super::io::write_all_nonblocking;
use super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::vision::{
    VisionInnerTlsState, VisionUnpadder, VisionUplinkMode, drain_vision_uplink,
    drain_vision_uplink_async,
};
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_IDLE_SLEEP, RESIDENT_TCP_ACCEPT_SLEEP,
    RESIDENT_TCP_IDLE_TIMEOUT, TLS_RECORD_MAX_PAYLOAD_LEN, VLESS_RESPONSE_VERSION,
    XTLS_RPRX_VISION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::runtime;
use tokio::time;

const BPF_L4_TCP: u8 = 6;
const ROUTING_L4_TCP: u8 = 1;
const ROUTING_IP_VERSION_4: u8 = 1;
const TCP_SNIFF_BUFFER_LIMIT: usize = 64 * 1024;

pub(super) struct ResidentTcpRouter {
    proxies: BTreeMap<u8, ResidentProxyPlan>,
    routing_tuple_map_id: u32,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    sniffing_timeout: Duration,
    so_mark_from_dae: u32,
    mptcp: bool,
}

impl ResidentTcpRouter {
    pub(super) fn new(
        proxies: BTreeMap<u8, ResidentProxyPlan>,
        routing_tuple_map_id: Option<u32>,
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
        sniffing_timeout: Duration,
        so_mark_from_dae: u32,
        mptcp: bool,
    ) -> Result<Self, String> {
        if proxies.is_empty() {
            return Err("resident TCP router needs at least one proxy outbound".to_owned());
        }
        let routing_tuple_map_id = routing_tuple_map_id.ok_or_else(|| {
            "resident TCP router needs routing_tuples_map id for Go-compatible per-flow outbound selection"
                .to_owned()
        })?;
        Ok(Self {
            proxies,
            routing_tuple_map_id,
            routing_matcher,
            dial_mode,
            sniffing_timeout,
            so_mark_from_dae,
            mptcp,
        })
    }

    pub(super) fn proxy_count(&self) -> usize {
        self.proxies.len()
    }

    pub(super) fn dial_mode_name(&self) -> &'static str {
        self.dial_mode.as_str()
    }

    pub(super) fn sniffing_timeout(&self) -> Duration {
        self.sniffing_timeout
    }

    fn select(
        &self,
        peer: SocketAddrV4,
        original_dst: SocketAddrV4,
        sniffed_domain: &str,
    ) -> Result<TcpSelection, String> {
        let initial = self.lookup_routing_result(peer, original_dst)?;
        self.select_from_routing_result(peer, original_dst, sniffed_domain, initial)
    }

    fn select_from_routing_result(
        &self,
        peer: SocketAddrV4,
        original_dst: SocketAddrV4,
        sniffed_domain: &str,
        initial: BpfRoutingResult,
    ) -> Result<TcpSelection, String> {
        let destination = SocketAddr::V4(original_dst);
        let first_choose = choose_dial_target(
            self.dial_mode,
            initial.outbound,
            destination,
            sniffed_domain,
            false,
        );
        let mut final_outbound = initial.outbound;
        let mut final_mark = initial.mark;
        let mut userspace_route_executed = false;
        let mut userspace_route_must = false;

        if first_choose.should_reroute || final_outbound == OUTBOUND_CONTROL_PLANE_ROUTING {
            let outcome = self
                .routing_matcher
                .match_query_detail(&Query {
                    source: Some(IpAddr::V4(*peer.ip())),
                    dest: IpAddr::V4(*original_dst.ip()),
                    source_port: Some(peer.port()),
                    dest_port: original_dst.port(),
                    ip_version: Some(ROUTING_IP_VERSION_4),
                    l4proto: Some(ROUTING_L4_TCP),
                    domain: sniffed_domain.to_owned(),
                    process_name: process_name(&initial.pname),
                    dscp: Some(initial.dscp),
                    mac: Some(initial.mac),
                })
                .map_err(|err| format!("resident TCP userspace reroute: {err}"))?;
            final_outbound = outcome.outbound.value();
            final_mark = outcome.mark;
            userspace_route_executed = true;
            userspace_route_must = outcome.must;
        }

        let second_choose = userspace_route_executed.then(|| {
            choose_dial_target(
                self.dial_mode,
                final_outbound,
                destination,
                sniffed_domain,
                false,
            )
        });
        let final_choose = second_choose.as_ref().unwrap_or(&first_choose);
        if final_mark == 0 {
            final_mark = self.so_mark_from_dae;
        }
        let route = TcpRouteSelection {
            initial_outbound: initial.outbound,
            final_outbound,
            final_mark,
            userspace_route_executed,
            userspace_route_must,
            dial_target: final_choose.dial_target.clone(),
            dial_ip: final_choose.dial_ip,
            log_metadata: TcpRoutingLogMetadata::from_bpf(&initial),
        };
        match final_outbound {
            OUTBOUND_DIRECT => Ok(TcpSelection::Direct(TcpDirectSelection {
                route,
                mptcp: self.mptcp,
            })),
            OUTBOUND_BLOCK => Ok(TcpSelection::Block(TcpBlockSelection { route })),
            _ => {
                let Some(proxy) = self.proxies.get(&final_outbound) else {
                    return Err(format!(
                        "resident TCP selected outbound {} but no Rust proxy plan is available; unsupported protocol must stay on Go control plane until implemented",
                        OutboundIndex(final_outbound)
                    ));
                };
                let mut proxy = proxy.clone();
                proxy.mark = route.final_mark;
                proxy.mptcp = self.mptcp;
                Ok(TcpSelection::Proxy(TcpProxySelection { route, proxy }))
            }
        }
    }

    fn lookup_routing_result(
        &self,
        peer: SocketAddrV4,
        original_dst: SocketAddrV4,
    ) -> Result<BpfRoutingResult, String> {
        let key = BpfTuplesKey {
            sip: ipv4_mapped_ip_bytes(*peer.ip()),
            dip: ipv4_mapped_ip_bytes(*original_dst.ip()),
            sport: peer.port().to_be(),
            dport: original_dst.port().to_be(),
            l4proto: BPF_L4_TCP,
            padding: [0; 3],
        };
        let fd = open_map_fd(self.routing_tuple_map_id).map_err(|err| {
            format!(
                "open routing_tuples_map id {} for resident TCP: {err}",
                self.routing_tuple_map_id
            )
        })?;
        let mut result = BpfRoutingResult::default();
        lookup_map_elem_bytes(fd.as_raw_fd(), bytes_of(&key), bytes_of_mut(&mut result)).map_err(
            |err| {
                format!(
                    "lookup routing_tuples_map for {} -> {} tcp: {err}",
                    peer, original_dst
                )
            },
        )?;
        Ok(result)
    }
}

#[derive(Debug)]
struct TcpRouteSelection {
    initial_outbound: u8,
    final_outbound: u8,
    final_mark: u32,
    userspace_route_executed: bool,
    userspace_route_must: bool,
    dial_target: String,
    dial_ip: bool,
    log_metadata: TcpRoutingLogMetadata,
}

#[derive(Debug)]
struct TcpRoutingLogMetadata {
    pid: u32,
    dscp: u8,
    pname: String,
    mac: String,
}

impl TcpRoutingLogMetadata {
    fn from_bpf(result: &BpfRoutingResult) -> Self {
        Self {
            pid: result.pid,
            dscp: result.dscp,
            pname: process_name(&result.pname).unwrap_or_default(),
            mac: mac_string(&result.mac),
        }
    }
}

#[derive(Debug)]
struct TcpProxySelection {
    route: TcpRouteSelection,
    proxy: ResidentProxyPlan,
}

#[derive(Debug)]
struct TcpDirectSelection {
    route: TcpRouteSelection,
    mptcp: bool,
}

#[derive(Debug)]
struct TcpBlockSelection {
    route: TcpRouteSelection,
}

#[derive(Debug)]
enum TcpSelection {
    Proxy(TcpProxySelection),
    Direct(TcpDirectSelection),
    Block(TcpBlockSelection),
}

struct TcpSniffReport {
    payload: Vec<u8>,
    domain: String,
    error: Option<String>,
}

pub(super) fn resident_tcp_accept_loop(
    listener: TcpListener,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    flow_stack_bytes: usize,
) {
    if let Err(err) = listener.set_nonblocking(true) {
        append_event(
            &event_file,
            &event_lock,
            json!({"event": "tcp_listener_nonblocking_failed", "error": err.to_string()}),
        );
        return;
    }
    let runtime = match runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "tcp_async_runtime_build_failed", "error": err.to_string()}),
            );
            return;
        }
    };
    runtime.block_on(resident_tcp_accept_loop_async(
        listener,
        router,
        stop,
        event_file,
        event_lock,
        metrics,
        flow_stack_bytes,
    ));
}

async fn resident_tcp_accept_loop_async(
    listener: TcpListener,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    flow_stack_bytes: usize,
) {
    let listener = match TokioTcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "tcp_async_listener_adopt_failed", "error": err.to_string()}),
            );
            return;
        }
    };
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "tcp_worker_started",
            "proxy_count": router.proxy_count(),
            "dial_mode": router.dial_mode_name(),
            "execution": "async-accept-direct-v1",
            "proxy_execution": "async-proxy-tls-v1",
            "legacy_flow_stack_bytes": flow_stack_bytes,
        }),
    );
    while !stop.load(Ordering::Relaxed) {
        match time::timeout(RESIDENT_TCP_ACCEPT_SLEEP, listener.accept()).await {
            Err(_) => {}
            Ok(Ok((stream, peer))) => {
                spawn_async_tcp_flow(
                    stream,
                    peer,
                    Arc::clone(&router),
                    Arc::clone(&stop),
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    Arc::clone(&metrics),
                );
            }
            Ok(Err(err)) => {
                append_event(
                    &event_file,
                    &event_lock,
                    json!({"event": "tcp_accept_failed", "error": err.to_string()}),
                );
                time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    append_event(
        &event_file,
        &event_lock,
        json!({"event": "tcp_worker_stopped"}),
    );
}

#[allow(clippy::too_many_arguments)]
fn spawn_async_tcp_flow(
    stream: TokioTcpStream,
    peer: SocketAddr,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    tokio::spawn(async move {
        match handle_tcp_connection_async_or_handoff(
            stream,
            peer,
            router,
            stop,
            Arc::clone(&metrics),
        )
        .await
        {
            Ok(Some(event)) => append_event(&event_file, &event_lock, event),
            Ok(None) => {}
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({"event": "tcp_connection_failed", "peer": peer.to_string(), "error": err}),
            ),
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection_async_or_handoff(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Option<Value>, String> {
    let peer_v4 = match peer {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "resident TCP dataplane currently supports IPv4 TCP peers only: {addr}"
            ));
        }
    };
    let original_dst = match inbound
        .local_addr()
        .map_err(|err| format!("read original TCP destination: {err}"))?
    {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "resident TCP dataplane currently supports IPv4 original destinations only: {addr}"
            ));
        }
    };
    inbound
        .set_nodelay(true)
        .map_err(|err| format!("set inbound TCP_NODELAY: {err}"))?;
    let sniff = sniff_initial_tcp_payload_async(&mut inbound, router.sniffing_timeout).await?;
    let selection = router.select(peer_v4, original_dst, &sniff.domain)?;
    match selection {
        TcpSelection::Direct(selection) => {
            metrics.tcp_opened();
            let result = handle_direct_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                Arc::clone(&stop),
                &sniff,
                &metrics,
            )
            .await;
            metrics.tcp_closed();
            result.map(Some)
        }
        TcpSelection::Block(selection) => {
            let _ = inbound.shutdown().await;
            let mut event = json!({
                "event": "tcp_connection_blocked",
                "outbound_kind": "block",
                "peer": peer.to_string(),
                "original_dst": original_dst.to_string(),
                "dial_target": &selection.route.dial_target,
                "dial_ip": selection.route.dial_ip,
                "initial_outbound": selection.route.initial_outbound,
                "final_outbound": selection.route.final_outbound,
                "final_mark": selection.route.final_mark,
                "userspace_route_executed": selection.route.userspace_route_executed,
                "userspace_route_must": selection.route.userspace_route_must,
                "sniffed_domain": &sniff.domain,
                "sniff_error": &sniff.error,
                "execution": "async-block",
            });
            append_tcp_route_log_fields(&mut event, &selection.route, "block", "fixed", "block");
            Ok(Some(event))
        }
        TcpSelection::Proxy(selection) => {
            metrics.tcp_opened();
            let result = if matches!(
                selection.proxy.handler,
                ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
            ) {
                handle_proxy_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    &sniff,
                    &metrics,
                )
                .await
            } else if matches!(
                selection.proxy.handler,
                ResidentProxyProtocolPlan::TrojanTcpTls { .. }
                    | ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
            ) {
                handle_frame_tls_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    &sniff,
                    &metrics,
                )
                .await
            } else if matches!(
                selection.proxy.handler,
                ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
                    | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
                    | ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
            ) {
                handle_quic_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    &sniff,
                    &metrics,
                )
                .await
            } else {
                handle_first_batch_proxy_tcp_connection_async(
                    inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    sniff,
                    Arc::clone(&metrics),
                )
                .await
            };
            metrics.tcp_closed();
            result.map(Some)
        }
    }
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
fn spawn_proxy_tcp_connection_thread(
    inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    flow_stack_bytes: usize,
) -> Result<(), String> {
    let mut inbound = inbound
        .into_std()
        .map_err(|err| format!("convert async inbound TCP to std for proxy handoff: {err}"))?;
    thread::Builder::new()
        .name("dae-tcp-proxy-flow".to_owned())
        .stack_size(flow_stack_bytes)
        .spawn(move || {
            metrics.tcp_opened();
            let result = handle_proxy_tcp_connection(
                &mut inbound,
                peer,
                original_dst,
                selection,
                &stop,
                &sniff,
                &metrics,
            );
            metrics.tcp_closed();
            match result {
                Ok(mut event) => {
                    event["execution"] = json!("per-connection-thread-transitional");
                    append_event(&event_file, &event_lock, event)
                }
                Err(err) => append_event(
                    &event_file,
                    &event_lock,
                    json!({"event": "tcp_connection_failed", "peer": peer.to_string(), "error": err}),
                ),
            }
        })
        .map_err(|err| format!("spawn resident proxy TCP flow thread: {err}"))?;
    Ok(())
}

#[allow(dead_code)]
fn resident_tcp_accept_loop_sync_legacy(
    listener: TcpListener,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    flow_stack_bytes: usize,
) {
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "tcp_worker_started",
            "proxy_count": router.proxy_count(),
            "dial_mode": router.dial_mode_name(),
            "execution": "per-connection-thread-legacy",
            "flow_stack_bytes": flow_stack_bytes,
        }),
    );
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let router = Arc::clone(&router);
                let stop = Arc::clone(&stop);
                let connection_event_file = event_file.clone();
                let connection_event_lock = Arc::clone(&event_lock);
                let metrics = Arc::clone(&metrics);
                if let Err(err) = thread::Builder::new()
                    .name("dae-tcp-flow".to_owned())
                    .stack_size(flow_stack_bytes)
                    .spawn(move || {
                        metrics.tcp_opened();
                        let result = handle_tcp_connection(stream, peer, router, stop, &metrics);
                        metrics.tcp_closed();
                        match result {
                            Ok(event) => append_event(
                                &connection_event_file,
                                &connection_event_lock,
                                event,
                            ),
                            Err(err) => append_event(
                                &connection_event_file,
                                &connection_event_lock,
                                json!({"event": "tcp_connection_failed", "peer": peer.to_string(), "error": err}),
                            ),
                        }
                    })
                {
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "tcp_connection_thread_spawn_failed",
                            "peer": peer.to_string(),
                            "flow_stack_bytes": flow_stack_bytes,
                            "error": err.to_string(),
                        }),
                    );
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(RESIDENT_TCP_ACCEPT_SLEEP);
            }
            Err(err) => {
                append_event(
                    &event_file,
                    &event_lock,
                    json!({"event": "tcp_accept_failed", "error": err.to_string()}),
                );
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    append_event(
        &event_file,
        &event_lock,
        json!({"event": "tcp_worker_stopped"}),
    );
}

fn handle_tcp_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let peer_v4 = match peer {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "resident TCP dataplane currently supports IPv4 TCP peers only: {addr}"
            ));
        }
    };
    let original_dst = match inbound
        .local_addr()
        .map_err(|err| format!("read original TCP destination: {err}"))?
    {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "resident TCP dataplane currently supports IPv4 original destinations only: {addr}"
            ));
        }
    };
    inbound
        .set_nonblocking(true)
        .map_err(|err| format!("set inbound nonblocking: {err}"))?;
    inbound
        .set_nodelay(true)
        .map_err(|err| format!("set inbound TCP_NODELAY: {err}"))?;
    let sniff = sniff_initial_tcp_payload(&mut inbound, router.sniffing_timeout)?;
    let selection = router.select(peer_v4, original_dst, &sniff.domain)?;
    match selection {
        TcpSelection::Proxy(selection) => handle_proxy_tcp_connection(
            &mut inbound,
            peer,
            original_dst,
            selection,
            &stop,
            &sniff,
            metrics,
        ),
        TcpSelection::Direct(selection) => handle_direct_tcp_connection(
            &mut inbound,
            peer,
            original_dst,
            selection,
            &stop,
            &sniff,
            metrics,
        ),
        TcpSelection::Block(selection) => {
            let _ = inbound.shutdown(Shutdown::Both);
            let mut event = json!({
                "event": "tcp_connection_blocked",
                "outbound_kind": "block",
                "peer": peer.to_string(),
                "original_dst": original_dst.to_string(),
                "dial_target": &selection.route.dial_target,
                "dial_ip": selection.route.dial_ip,
                "initial_outbound": selection.route.initial_outbound,
                "final_outbound": selection.route.final_outbound,
                "final_mark": selection.route.final_mark,
                "userspace_route_executed": selection.route.userspace_route_executed,
                "userspace_route_must": selection.route.userspace_route_must,
                "sniffed_domain": &sniff.domain,
                "sniff_error": &sniff.error,
            });
            append_tcp_route_log_fields(&mut event, &selection.route, "block", "fixed", "block");
            Ok(event)
        }
    }
}

fn handle_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client = open_vless_tls_client(&selection.proxy)?;
    let tls_underlay = tls_underlay_name(&client);
    client.set_nonblocking(true)?;
    let request = packet::first_write_bytes(
        &selection.proxy.vless_key()?,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS TCP request: {err}"))?;
    client
        .queue_plain(&request, "queue VLESS TCP request")
        .map_err(|err| err.to_string())?;
    relay_tcp_over_vless_tls(
        inbound,
        &mut client,
        stop,
        &selection.proxy.flow,
        selection.proxy.vless_key()?,
        &sniff.payload,
        metrics,
    )
    .map(|stats| {
        proxy_tcp_finished_event(peer, original_dst, &selection, sniff, tls_underlay, &stats)
    })
    .or_else(|err| {
        Ok::<Value, String>(proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
        ))
    })
}

async fn handle_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client = open_async_vless_tls_client(&selection.proxy).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write VLESS TCP request")
        .await?;
    relay_tcp_over_vless_tls_async(
        inbound,
        &mut client,
        stop,
        &selection.proxy.flow,
        key,
        &sniff.payload,
        metrics,
    )
    .await
    .map(|stats| {
        let mut event =
            proxy_tcp_finished_event(peer, original_dst, &selection, sniff, tls_underlay, &stats);
        event["execution"] = json!("async-proxy-tls-v1");
        event
    })
    .or_else(|err| {
        let mut event =
            proxy_tcp_failed_event(peer, original_dst, &selection, sniff, tls_underlay, &err);
        event["execution"] = json!("async-proxy-tls-v1");
        Ok::<Value, String>(event)
    })
}

async fn handle_first_batch_proxy_tcp_connection_async(
    inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Value, String> {
    let mut inbound = inbound
        .into_std()
        .map_err(|err| format!("convert async inbound TCP to std for first-batch proxy: {err}"))?;
    tokio::task::spawn_blocking(move || {
        inbound
            .set_nonblocking(false)
            .map_err(|err| format!("set first-batch inbound blocking: {err}"))?;
        handle_first_batch_proxy_tcp_connection(
            &mut inbound,
            peer,
            original_dst,
            selection,
            &stop,
            &sniff,
            &metrics,
        )
    })
    .await
    .map_err(|err| format!("join first-batch proxy task: {err}"))?
}

fn handle_first_batch_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            handle_socks5_proxy_tcp_connection(
                inbound,
                peer,
                original_dst,
                &selection,
                stop,
                sniff,
                metrics,
                username,
                password,
            )
        }
        ResidentProxyProtocolPlan::HttpProxyTcp { username, password } => {
            handle_http_proxy_tcp_connection(
                inbound,
                peer,
                original_dst,
                &selection,
                stop,
                sniff,
                metrics,
                username,
                password,
            )
        }
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher,
            password,
            salt_len,
        } => handle_shadowsocks_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            cipher,
            password,
            *salt_len,
        ),
        ResidentProxyProtocolPlan::VmessAeadTcp { id } => handle_vmess_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            id,
        ),
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => Err(
            "first-batch proxy dispatcher received VLESS handler; use VLESS TLS dispatcher"
                .to_owned(),
        ),
        ResidentProxyProtocolPlan::TrojanTcpTls { .. } => Err(
            "first-batch proxy dispatcher received generic TLS handler; use TLS dispatcher"
                .to_owned(),
        ),
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => Err(
            "first-batch proxy dispatcher received frame TLS handler; use TLS dispatcher"
                .to_owned(),
        ),
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => Err(
            "first-batch proxy dispatcher received QUIC handler; use QUIC dispatcher".to_owned(),
        ),
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => Err(
            "first-batch proxy dispatcher received QUIC handler; use QUIC dispatcher".to_owned(),
        ),
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => Err(
            "first-batch proxy dispatcher received QUIC handler; use QUIC dispatcher".to_owned(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_frame_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::TrojanTcpTls { password } => {
            let password = password.clone();
            handle_trojan_tls_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &password,
            )
            .await
        }
        ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } => {
            let auth = auth.clone();
            handle_anytls_tls_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &auth,
            )
            .await
        }
        _ => Err("frame TLS dispatcher received unsupported handler".to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_trojan_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    password: &str,
) -> Result<Value, String> {
    let mut client = open_async_resident_tls_client(&selection.proxy).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let request = trojan_packet::tcp_request_header(
        password,
        "tcp",
        &selection.route.dial_target,
        &sniff.payload,
    )
    .map_err(|err| format!("build Trojan TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write Trojan TCP request")
        .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }
    match relay_tcp_over_resident_tls_plain_async(inbound, &mut client, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &stats,
                "async-proxy-tls-v1",
            );
            event["tls_underlay"] = json!(tls_underlay);
            Ok(event)
        }
        Err(err) => {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &err,
                "async-proxy-tls-v1",
            );
            event["tls_underlay"] = json!(tls_underlay);
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_anytls_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    auth: &str,
) -> Result<Value, String> {
    let mut client = open_async_resident_tls_client(&selection.proxy).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let sid = 1_u32;
    client
        .write_plain_all(
            &anytls_link::handshake_auth_bytes(auth),
            "write AnyTLS auth handshake",
        )
        .await?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_SETTINGS,
        sid,
        &anytls_link::settings_bytes(),
        "write AnyTLS settings",
    )
    .await?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_SYN,
        sid,
        &[],
        "write AnyTLS SYN",
    )
    .await?;
    let target_addr = anytls_link::socks_addr(&selection.route.dial_target)
        .map_err(|err| format!("build AnyTLS target address: {err}"))?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_PSH,
        sid,
        &target_addr,
        "write AnyTLS target",
    )
    .await?;
    if !sniff.payload.is_empty() {
        write_anytls_frame(
            &mut client,
            anytls_contract::CMD_PSH,
            sid,
            &sniff.payload,
            "write AnyTLS initial payload",
        )
        .await?;
        metrics.add_upload(sniff.payload.len());
    }
    wait_anytls_synack(&mut client, sid).await?;

    match relay_tcp_over_anytls_async(inbound, &mut client, stop, sid, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += sniff.payload.len();
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "anytls",
                &stats,
                "async-proxy-frame-tls-v1",
            );
            event["tls_underlay"] = json!(tls_underlay);
            Ok(event)
        }
        Err(err) => {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "anytls",
                &err,
                "async-proxy-frame-tls-v1",
            );
            event["tls_underlay"] = json!(tls_underlay);
            Ok(event)
        }
    }
}

async fn write_anytls_frame(
    client: &mut AsyncResidentTlsClient,
    cmd: u8,
    sid: u32,
    data: &[u8],
    label: &str,
) -> Result<(), String> {
    let frame = anytls_link::frame(cmd, sid, data);
    client.write_plain_all(&frame, label).await
}

async fn wait_anytls_synack(client: &mut AsyncResidentTlsClient, sid: u32) -> Result<(), String> {
    loop {
        let frame = read_anytls_frame(client).await?;
        match frame.cmd {
            cmd if cmd == anytls_contract::CMD_SYNACK
                && frame.sid == sid
                && frame.data.is_empty() =>
            {
                return Ok(());
            }
            cmd if matches!(
                cmd,
                anytls_contract::CMD_WASTE
                    | anytls_contract::CMD_SERVER_SETTINGS
                    | anytls_contract::CMD_UPDATE_PADDING
                    | anytls_contract::CMD_HEART_RESPONSE
            ) => {}
            cmd if cmd == anytls_contract::CMD_ALERT => {
                return Err(format!(
                    "AnyTLS alert before SYNACK: {} bytes",
                    frame.data.len()
                ));
            }
            cmd => {
                return Err(format!(
                    "unexpected AnyTLS frame before SYNACK: cmd={cmd} sid={} len={}",
                    frame.sid,
                    frame.data.len()
                ));
            }
        }
    }
}

async fn relay_tcp_over_anytls_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    sid: u32,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = write_anytls_frame(
                            client,
                            anytls_contract::CMD_FIN,
                            sid,
                            &[],
                            "write AnyTLS FIN",
                        )
                        .await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        write_anytls_frame(
                            client,
                            anytls_contract::CMD_PSH,
                            sid,
                            &inbound_buf[..read],
                            "write client payload to AnyTLS",
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for AnyTLS relay: {err}")),
                }
            }
            frame = read_anytls_frame(client), if !proxy_closed => {
                let frame = frame?;
                match frame.cmd {
                    cmd if cmd == anytls_contract::CMD_PSH && frame.sid == sid => {
                        if !frame.data.is_empty() {
                            inbound
                                .write_all(&frame.data)
                                .await
                                .map_err(|err| format!("write AnyTLS payload to client: {err}"))?;
                            stats.direct_to_client += frame.data.len();
                            metrics.add_download(frame.data.len());
                        }
                        last_activity = Instant::now();
                    }
                    cmd if cmd == anytls_contract::CMD_FIN && frame.sid == sid => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    cmd if matches!(
                        cmd,
                        anytls_contract::CMD_WASTE
                            | anytls_contract::CMD_SERVER_SETTINGS
                            | anytls_contract::CMD_UPDATE_PADDING
                            | anytls_contract::CMD_HEART_RESPONSE
                    ) => {
                        last_activity = Instant::now();
                    }
                    cmd if cmd == anytls_contract::CMD_ALERT => {
                        return Err(format!("AnyTLS alert frame: sid={} len={}", frame.sid, frame.data.len()));
                    }
                    cmd => {
                        return Err(format!(
                            "unexpected AnyTLS relay frame: cmd={cmd} sid={} len={}",
                            frame.sid,
                            frame.data.len()
                        ));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed && proxy_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident AnyTLS relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}

async fn read_anytls_frame(client: &mut AsyncResidentTlsClient) -> Result<AnyTlsFrame, String> {
    let mut header = [0_u8; anytls_contract::HEADER_OVERHEAD_SIZE];
    read_resident_tls_plain_exact(client, &mut header, "read AnyTLS frame header").await?;
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0_u8; len];
    read_resident_tls_plain_exact(client, &mut data, "read AnyTLS frame data").await?;
    Ok(AnyTlsFrame {
        cmd: header[0],
        sid: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        data,
    })
}

async fn read_resident_tls_plain_exact(
    client: &mut AsyncResidentTlsClient,
    buf: &mut [u8],
    label: &str,
) -> Result<(), String> {
    let mut offset = 0_usize;
    while offset < buf.len() {
        let read = time::timeout(
            RESIDENT_TCP_IDLE_TIMEOUT,
            client.read_plain(&mut buf[offset..]),
        )
        .await
        .map_err(|_| format!("{label}: timeout"))?
        .map_err(|err| format!("{label}: {err}"))?;
        if read == 0 {
            return Err(format!("{label}: early eof"));
        }
        offset += read;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            pin_sha256,
            max_rx,
        } => {
            let auth = auth.clone();
            let pin_sha256 = pin_sha256.clone();
            let max_rx = *max_rx;
            handle_hysteria2_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &auth,
                &pin_sha256,
                max_rx,
            )
            .await
        }
        ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid,
            password,
            alpn,
        } => {
            let uuid = uuid.clone();
            let password = password.clone();
            let alpn = alpn.clone();
            handle_tuic_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &uuid,
                &password,
                &alpn,
            )
            .await
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid,
            password,
            allow_insecure,
            pinned_certchain_sha256,
        } => {
            let uuid = uuid.clone();
            let password = password.clone();
            let allow_insecure = *allow_insecure;
            let pinned_certchain_sha256 = pinned_certchain_sha256.clone();
            handle_juicity_quic_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &uuid,
                &password,
                allow_insecure,
                &pinned_certchain_sha256,
            )
            .await
        }
        _ => Err("QUIC dispatcher received unsupported handler".to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_hysteria2_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    auth: &str,
    pin_sha256: &str,
    max_rx: u64,
) -> Result<Value, String> {
    let mut endpoint = open_marked_quic_endpoint(selection.proxy.mark)?;
    endpoint.set_default_client_config(
        build_hysteria2_pinned_client_config(pin_sha256.to_owned())
            .map_err(|err| format!("build Hysteria2 QUIC client config: {err}"))?,
    );
    let remote = resolve_proxy_udp_addr(&selection.proxy)?;
    let connection = endpoint
        .connect(remote, &selection.proxy.server_name)
        .map_err(|err| format!("connect Hysteria2 QUIC endpoint: {err}"))?
        .await
        .map_err(|err| format!("await Hysteria2 QUIC connect: {err}"))?;
    let auth_report = authenticate_hysteria2_connection(connection.clone(), auth, max_rx)
        .await
        .map_err(|err| format!("authenticate Hysteria2 QUIC connection: {err}"))?;
    if !auth_report.auth_ok {
        connection.close(0x101_u32.into(), b"resident hysteria2 auth failed");
        return Ok(generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "hysteria2",
            &format!("Hysteria2 auth status {}", auth_report.status),
            "async-proxy-quic-tcp-v1",
        ));
    }
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open Hysteria2 TCP stream: {err}"))?;
    write_hysteria2_tcp_request(&mut send, &selection.route.dial_target)
        .await
        .map_err(|err| format!("write Hysteria2 TCP request: {err}"))?;
    let response = read_hysteria2_tcp_response(&mut recv)
        .await
        .map_err(|err| format!("read Hysteria2 TCP response: {err}"))?;
    if !response.ok {
        connection.close(0x101_u32.into(), b"resident hysteria2 tcp response failed");
        return Ok(generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "hysteria2",
            &format!("Hysteria2 TCP response rejected: {}", response.message),
            "async-proxy-quic-tcp-v1",
        ));
    }
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        send.write_all(&sniff.payload)
            .await
            .map_err(|err| format!("write Hysteria2 initial payload: {err}"))?;
        send.flush()
            .await
            .map_err(|err| format!("flush Hysteria2 initial payload: {err}"))?;
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            connection.close(0_u32.into(), b"resident hysteria2 done");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "hysteria2",
                &stats,
                "async-proxy-quic-tcp-v1",
            );
            event["quic_underlay"] = json!("quinn-h3");
            event["hysteria2_udp_enabled"] = json!(auth_report.udp_enabled);
            Ok(event)
        }
        Err(err) => {
            connection.close(0x101_u32.into(), b"resident hysteria2 relay failed");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "hysteria2",
                &err,
                "async-proxy-quic-tcp-v1",
            );
            event["quic_underlay"] = json!("quinn-h3");
            event["hysteria2_udp_enabled"] = json!(auth_report.udp_enabled);
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tuic_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    uuid: &str,
    password: &str,
    alpn: &[String],
) -> Result<Value, String> {
    let mut endpoint = open_marked_quic_endpoint(selection.proxy.mark)?;
    endpoint.set_default_client_config(
        build_tuic_runtime_client_config(alpn)
            .map_err(|err| format!("build TUIC QUIC client config: {err}"))?,
    );
    let remote = resolve_proxy_udp_addr(&selection.proxy)?;
    let connection = endpoint
        .connect(remote, &selection.proxy.server_name)
        .map_err(|err| format!("connect TUIC QUIC endpoint: {err}"))?
        .await
        .map_err(|err| format!("await TUIC QUIC connect: {err}"))?;
    let auth_report = authenticate_tuic_connection(&connection, uuid, password)
        .await
        .map_err(|err| format!("authenticate TUIC QUIC connection: {err}"))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open TUIC TCP stream: {err}"))?;
    write_tuic_connect_request(&mut send, &selection.route.dial_target)
        .await
        .map_err(|err| format!("write TUIC TCP connect: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        send.write_all(&sniff.payload)
            .await
            .map_err(|err| format!("write TUIC initial payload: {err}"))?;
        send.flush()
            .await
            .map_err(|err| format!("flush TUIC initial payload: {err}"))?;
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            connection.close(0_u32.into(), b"resident tuic done");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "tuic",
                &stats,
                "async-proxy-quic-tcp-v1",
            );
            event["quic_underlay"] = json!("quinn");
            event["tuic_auth_token_nonzero"] = json!(auth_report.auth_token_nonzero);
            Ok(event)
        }
        Err(err) => {
            connection.close(0x101_u32.into(), b"resident tuic relay failed");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "tuic",
                &err,
                "async-proxy-quic-tcp-v1",
            );
            event["quic_underlay"] = json!("quinn");
            event["tuic_auth_token_nonzero"] = json!(auth_report.auth_token_nonzero);
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_juicity_quic_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    uuid: &str,
    password: &str,
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
) -> Result<Value, String> {
    let mut endpoint = open_marked_quic_endpoint(selection.proxy.mark)?;
    endpoint.set_default_client_config(
        build_juicity_runtime_client_config(allow_insecure, pinned_certchain_sha256)
            .map_err(|err| format!("build Juicity QUIC client config: {err}"))?,
    );
    let remote = resolve_proxy_udp_addr(&selection.proxy)?;
    let connection = endpoint
        .connect(remote, &selection.proxy.server_name)
        .map_err(|err| format!("connect Juicity QUIC endpoint: {err}"))?
        .await
        .map_err(|err| format!("await Juicity QUIC connect: {err}"))?;
    let (auth_report, mut auth_stream) =
        authenticate_juicity_connection(&connection, uuid, password)
            .await
            .map_err(|err| format!("authenticate Juicity QUIC connection: {err}"))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open Juicity TCP stream: {err}"))?;
    write_juicity_tcp_request(&mut send, &selection.route.dial_target, &sniff.payload)
        .await
        .map_err(|err| format!("write Juicity TCP request: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    match relay_tcp_over_quic_stream_async(inbound, &mut send, &mut recv, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            let _ = auth_stream.finish().await;
            connection.close(0_u32.into(), b"resident juicity done");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "juicity",
                &stats,
                "async-proxy-quic-tcp-v1",
            );
            event["quic_underlay"] = json!("quinn-h3");
            event["juicity_auth_token_nonzero"] = json!(auth_report.auth_token_nonzero);
            event["juicity_certchain_pinned"] = json!(!pinned_certchain_sha256.is_empty());
            event["juicity_allow_insecure"] = json!(allow_insecure);
            Ok(event)
        }
        Err(err) => {
            let _ = auth_stream.finish().await;
            connection.close(0x101_u32.into(), b"resident juicity relay failed");
            endpoint.wait_idle().await;
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "juicity",
                &err,
                "async-proxy-quic-tcp-v1",
            );
            event["quic_underlay"] = json!("quinn-h3");
            event["juicity_auth_token_nonzero"] = json!(auth_report.auth_token_nonzero);
            event["juicity_certchain_pinned"] = json!(!pinned_certchain_sha256.is_empty());
            event["juicity_allow_insecure"] = json!(allow_insecure);
            Ok(event)
        }
    }
}

async fn relay_tcp_over_quic_stream_async(
    inbound: &mut TokioTcpStream,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = send.finish();
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send.write_all(&inbound_buf[..read])
                            .await
                            .map_err(|err| format!("write client payload to QUIC stream: {err}"))?;
                        send.flush()
                            .await
                            .map_err(|err| format!("flush QUIC stream: {err}"))?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for QUIC stream relay: {err}")),
                }
            }
            read = recv.read(&mut proxy_buf), if !proxy_closed => {
                match read {
                    Ok(None) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(Some(read)) => {
                        inbound
                            .write_all(&proxy_buf[..read])
                            .await
                            .map_err(|err| format!("write QUIC stream payload to client: {err}"))?;
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read QUIC stream payload: {err}")),
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident QUIC stream relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}

fn open_marked_quic_endpoint(mark: u32) -> Result<quinn::Endpoint, String> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .map_err(|err| format!("bind QUIC UDP socket: {err}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set QUIC UDP SO_MARK {mark}: {err}"))?;
    }
    let runtime =
        quinn::default_runtime().ok_or_else(|| "no quinn runtime available".to_owned())?;
    quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
        .map_err(|err| format!("create QUIC endpoint: {err}"))
}

fn resolve_proxy_udp_addr(proxy: &ResidentProxyPlan) -> Result<SocketAddr, String> {
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
    target
        .to_socket_addrs()
        .map_err(|err| format!("resolve QUIC endpoint {target}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve QUIC endpoint {target}: no address"))
}

fn set_socket_mark(fd: i32, mark: u32) -> std::io::Result<()> {
    let mark = mark as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_socks5_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    socks5_connect(&mut proxy, &selection.route.dial_target, username, password)?;
    proxy
        .set_nonblocking(true)
        .map_err(|err| format!("set SOCKS5 proxy TCP nonblocking: {err}"))?;
    inbound
        .set_nonblocking(true)
        .map_err(|err| format!("set inbound TCP nonblocking after SOCKS5 handshake: {err}"))?;
    relay_tcp_direct(inbound, &mut proxy, stop, &sniff.payload, metrics)
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "socks5",
                &stats,
                "first-batch-tcp-v1",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "socks5",
                &err,
                "first-batch-tcp-v1",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
fn handle_http_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    http_proxy_connect(&mut proxy, &selection.route.dial_target, username, password)?;
    proxy
        .set_nonblocking(true)
        .map_err(|err| format!("set HTTP proxy TCP nonblocking: {err}"))?;
    inbound
        .set_nonblocking(true)
        .map_err(|err| format!("set inbound TCP nonblocking after HTTP proxy CONNECT: {err}"))?;
    relay_tcp_direct(inbound, &mut proxy, stop, &sniff.payload, metrics)
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "http-proxy",
                &stats,
                "first-batch-tcp-v1",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "http-proxy",
                &err,
                "first-batch-tcp-v1",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
fn handle_shadowsocks_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    proxy
        .set_nonblocking(false)
        .map_err(|err| format!("set Shadowsocks proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks inbound write timeout: {err}"))?;
    let stats = relay_tcp_over_shadowsocks_aead(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        &sniff.payload,
        metrics,
    );
    stats
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "shadowsocks",
                &stats,
                "first-batch-tcp-v1",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "shadowsocks",
                &err,
                "first-batch-tcp-v1",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
fn handle_vmess_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    proxy
        .set_nonblocking(false)
        .map_err(|err| format!("set VMess proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess inbound write timeout: {err}"))?;

    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess AEAD TCP session: {err}"))?;
    proxy
        .write_all(&session.first_write)
        .map_err(|err| format!("write VMess AEAD TCP initial request: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_aead(inbound, &mut proxy, stop, session, initial_stats, metrics)
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "vmess",
                &stats,
                "first-batch-aead-tcp-v1",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "vmess",
                &err,
                "first-batch-aead-tcp-v1",
            ))
        })
}

async fn relay_tcp_over_resident_tls_plain_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        client
                            .write_plain_all(&inbound_buf[..read], "write client payload to proxy TLS")
                            .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for proxy TLS relay: {err}")),
                }
            }
            read = client.read_plain(&mut proxy_buf), if !proxy_closed => {
                match read {
                    Ok(0) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        inbound
                            .write_all(&proxy_buf[..read])
                            .await
                            .map_err(|err| format!("write proxy TLS payload to client: {err}"))?;
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read proxy TLS plaintext: {err}")),
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident proxy TLS relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}

fn open_plain_proxy_tcp_stream(proxy: &ResidentProxyPlan) -> Result<TcpStream, String> {
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
    let connection = open_direct_tcp_connection(&target, proxy.mark, proxy.mptcp)?;
    connection
        .stream
        .set_nonblocking(false)
        .map_err(|err| format!("set proxy TCP blocking for handshake: {err}"))?;
    connection
        .stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set proxy TCP read timeout: {err}"))?;
    connection
        .stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set proxy TCP write timeout: {err}"))?;
    Ok(connection.stream)
}

fn socks5_connect(
    stream: &mut TcpStream,
    target: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    stream
        .write_all(&handshake::greeting(username, password))
        .map_err(|err| format!("write SOCKS5 greeting: {err}"))?;
    let mut method_selection = [0_u8; 2];
    stream
        .read_exact(&mut method_selection)
        .map_err(|err| format!("read SOCKS5 method selection: {err}"))?;
    let method = handshake::parse_method_selection(&method_selection)
        .map_err(|err| format!("parse SOCKS5 method selection: {err}"))?;
    if method == handshake::AUTH_PASSWORD {
        let auth = handshake::username_password_auth(username, password)
            .map_err(|err| format!("build SOCKS5 auth: {err}"))?;
        stream
            .write_all(&auth)
            .map_err(|err| format!("write SOCKS5 auth: {err}"))?;
        let mut auth_reply = [0_u8; 2];
        stream
            .read_exact(&mut auth_reply)
            .map_err(|err| format!("read SOCKS5 auth reply: {err}"))?;
        if auth_reply[0] != handshake::PASSWORD_AUTH_VERSION || auth_reply[1] != 0 {
            return Err(format!("SOCKS5 auth rejected: {:02x?}", auth_reply));
        }
    }
    let target =
        Socks5Address::parse(target).map_err(|err| format!("parse SOCKS5 target: {err}"))?;
    let request = handshake::request(handshake::Socks5Command::Connect, &target)
        .map_err(|err| format!("build SOCKS5 CONNECT: {err}"))?;
    stream
        .write_all(&request)
        .map_err(|err| format!("write SOCKS5 CONNECT: {err}"))?;
    let mut reply_head = [0_u8; 3];
    stream
        .read_exact(&mut reply_head)
        .map_err(|err| format!("read SOCKS5 CONNECT reply: {err}"))?;
    let mut reply = reply_head.to_vec();
    reply.extend(read_socks5_address_bytes(stream).map_err(|err| err.to_string())?);
    handshake::parse_server_reply(&reply)
        .map_err(|err| format!("parse SOCKS5 CONNECT reply: {err}"))?;
    Ok(())
}

fn http_proxy_connect(
    stream: &mut TcpStream,
    target: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    let mut options = HttpConnectOptions::connect(target);
    options.username = username.to_owned();
    options.password = password.to_owned();
    let request = http_request::connect_request(&options);
    stream
        .write_all(&request)
        .map_err(|err| format!("write HTTP CONNECT request: {err}"))?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = stream
            .read(&mut buf)
            .map_err(|err| format!("read HTTP CONNECT response: {err}"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err("HTTP CONNECT response too large".to_owned());
        }
    }
    let status = http_request::parse_connect_response(&response)
        .map_err(|err| format!("parse HTTP CONNECT response: {err}"))?;
    if status != 200 {
        return Err(format!("HTTP CONNECT status: {status}"));
    }
    Ok(())
}

fn read_socks5_address_bytes(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp)?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest)?;
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn relay_tcp_over_shadowsocks_aead(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks target metadata: {err}"))?;
    first_plain.extend_from_slice(initial_payload);
    let mut client_salt = vec![0_u8; salt_len];
    fastrand::fill(&mut client_salt);
    let mut encoder = AeadStreamCodec::new(cipher, password, &client_salt)
        .map_err(|err| format!("create Shadowsocks upload encoder: {err}"))?;
    let mut initial = client_salt.clone();
    initial.extend(
        encoder
            .encrypt_chunk(&first_plain)
            .map_err(|err| format!("encode Shadowsocks initial TCP frame: {err}"))?,
    );
    proxy
        .write_all(&initial)
        .map_err(|err| format!("write Shadowsocks initial TCP frame: {err}"))?;
    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone Shadowsocks proxy stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for Shadowsocks upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks upload read timeout: {err}"))?;
    let relay_done = Arc::new(AtomicBool::new(false));
    let upload_done = Arc::clone(&relay_done);
    let upload = thread::spawn(move || {
        let mut stats = 0_usize;
        let mut buf = [0_u8; 16 * 1024];
        loop {
            if upload_done.load(Ordering::Relaxed) {
                break;
            }
            let read = match upload_inbound.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => read,
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(err) => return Err(format!("read inbound TCP for Shadowsocks upload: {err}")),
            };
            let encrypted = encoder
                .encrypt_chunk(&buf[..read])
                .map_err(|err| format!("encrypt Shadowsocks upload chunk: {err}"))?;
            upload_proxy
                .write_all(&encrypted)
                .map_err(|err| format!("write Shadowsocks upload chunk: {err}"))?;
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let mut server_salt = vec![0_u8; salt_len];
    if let Err(err) = proxy.read_exact(&mut server_salt) {
        relay_done.store(true, Ordering::Relaxed);
        let _ = inbound.shutdown(Shutdown::Read);
        let _ = proxy.shutdown(Shutdown::Write);
        let _ = upload.join();
        return Err(format!("read Shadowsocks server salt: {err}"));
    }
    let mut decoder = match AeadStreamCodec::new(cipher, password, &server_salt) {
        Ok(decoder) => decoder,
        Err(err) => {
            relay_done.store(true, Ordering::Relaxed);
            let _ = inbound.shutdown(Shutdown::Read);
            let _ = proxy.shutdown(Shutdown::Write);
            let _ = upload.join();
            return Err(format!("create Shadowsocks response decoder: {err}"));
        }
    };

    let mut download_error = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match read_encrypted_chunk_from_stream(proxy, &mut decoder) {
            Ok(plain) => {
                if plain.is_empty() {
                    continue;
                }
                inbound
                    .write_all(&plain)
                    .map_err(|err| format!("write Shadowsocks response to inbound: {err}"))?;
                stats.direct_to_client += plain.len();
                metrics.add_download(plain.len());
            }
            Err(err) => {
                let message = err.to_string();
                if message.contains("early eof")
                    || message.contains("failed to fill whole buffer")
                    || message.contains("Connection reset")
                    || message.contains("connection reset")
                    || message.contains("timed out")
                {
                    break;
                }
                download_error = Some(format!("read Shadowsocks response chunk: {message}"));
                break;
            }
        }
    }
    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy.shutdown(Shutdown::Write);
    let upload_bytes = upload
        .join()
        .map_err(|_| "join Shadowsocks upload relay thread failed".to_owned())??;
    if let Some(err) = download_error {
        return Err(err);
    }
    if upload_bytes > 0 {
        stats.client_to_direct += upload_bytes;
        metrics.add_upload(upload_bytes);
    }
    Ok(stats)
}

fn relay_tcp_over_vmess_aead(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone VMess proxy stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for VMess upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VMess upload read timeout: {err}"))?;
    let relay_done = Arc::new(AtomicBool::new(false));
    let upload_done = Arc::clone(&relay_done);
    let mut upload_codec = session.upload;
    let upload = thread::spawn(move || {
        let mut stats = 0_usize;
        let mut buf = [0_u8; 16 * 1024];
        loop {
            if upload_done.load(Ordering::Relaxed) {
                break;
            }
            let read = match upload_inbound.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => read,
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(err) => return Err(format!("read inbound TCP for VMess upload: {err}")),
            };
            let encrypted = upload_codec
                .seal_chunk(&buf[..read])
                .map_err(|err| format!("encode VMess upload chunk: {err}"))?;
            upload_proxy
                .write_all(&encrypted)
                .map_err(|err| format!("write VMess upload chunk: {err}"))?;
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let mut response = match aead_tcp_response_reader_from_stream(proxy, &session.request) {
        Ok(response) => response,
        Err(err) => {
            relay_done.store(true, Ordering::Relaxed);
            let _ = inbound.shutdown(Shutdown::Read);
            let _ = proxy.shutdown(Shutdown::Write);
            let _ = upload.join();
            return Err(format!("read VMess AEAD response header: {err}"));
        }
    };
    let _response_header_len = response.response_header_len;

    let mut download_error = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match response.read_chunk_from_stream(proxy) {
            Ok(plain) => {
                if plain.is_empty() {
                    continue;
                }
                inbound
                    .write_all(&plain)
                    .map_err(|err| format!("write VMess response to inbound: {err}"))?;
                stats.direct_to_client += plain.len();
                metrics.add_download(plain.len());
            }
            Err(err) => {
                let message = err.to_string();
                if message.contains("early eof")
                    || message.contains("failed to fill whole buffer")
                    || message.contains("Connection reset")
                    || message.contains("connection reset")
                    || message.contains("timed out")
                {
                    break;
                }
                download_error = Some(format!("read VMess response chunk: {message}"));
                break;
            }
        }
    }
    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy.shutdown(Shutdown::Write);
    let upload_bytes = upload
        .join()
        .map_err(|_| "join VMess upload relay thread failed".to_owned())??;
    if let Some(err) = download_error {
        return Err(err);
    }
    if upload_bytes > 0 {
        stats.client_to_direct += upload_bytes;
        metrics.add_upload(upload_bytes);
    }
    Ok(stats)
}

fn proxy_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    tls_underlay: &'static str,
    stats: &RelayStats,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_finished",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["tls_underlay"] = json!(tls_underlay);
    append_proxy_relay_stats(&mut event, stats);
    event
}

fn proxy_tcp_failed_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    tls_underlay: &'static str,
    err: &RelayError,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_failed",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["error"] = json!(&err.message);
    event["tls_underlay"] = json!(tls_underlay);
    append_proxy_relay_stats(&mut event, &err.stats);
    event
}

fn generic_proxy_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    handler: &'static str,
    stats: &DirectTcpRelayStats,
    execution: &'static str,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_finished",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["resident_protocol_handler"] = json!(handler);
    event["execution"] = json!(execution);
    append_generic_proxy_relay_stats(&mut event, stats);
    event
}

fn generic_proxy_tcp_failed_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    handler: &'static str,
    err: &str,
    execution: &'static str,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_failed",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["resident_protocol_handler"] = json!(handler);
    event["execution"] = json!(execution);
    event["error"] = json!(err);
    event
}

fn proxy_tcp_base_event(
    event_name: &str,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
) -> Value {
    let mut event = json!({
        "event": event_name,
        "outbound_kind": "proxy",
        "peer": peer.to_string(),
        "original_dst": original_dst.to_string(),
        "dial_target": &selection.route.dial_target,
        "dial_ip": selection.route.dial_ip,
        "initial_outbound": selection.route.initial_outbound,
        "final_outbound": selection.route.final_outbound,
        "final_mark": selection.route.final_mark,
        "userspace_route_executed": selection.route.userspace_route_executed,
        "userspace_route_must": selection.route.userspace_route_must,
        "sniffed_domain": &sniff.domain,
        "sniff_error": &sniff.error,
        "proxy_group": &selection.proxy.group_name,
        "group_policy": &selection.proxy.group_policy,
        "node_tag": &selection.proxy.node_tag,
    });
    append_tcp_route_log_fields(
        &mut event,
        &selection.route,
        &selection.proxy.group_name,
        &selection.proxy.group_policy,
        &selection.proxy.node_tag,
    );
    event
}

fn append_proxy_relay_stats(event: &mut Value, stats: &RelayStats) {
    event["bytes_client_to_proxy"] = json!(stats.client_to_proxy);
    event["bytes_proxy_to_client"] = json!(stats.proxy_to_client);
    event["response_header_stripped"] = json!(stats.response_header_stripped);
    event["vision_unpadding_blocks"] = json!(stats.vision_unpadding_blocks);
    event["vision_direct_command_seen"] = json!(stats.vision_direct_command_seen);
    event["vision_raw_direct_recovered"] = json!(stats.vision_raw_direct_recovered);
    event["vision_downlink_direct_active"] = json!(stats.vision_downlink_direct_active);
}

fn append_generic_proxy_relay_stats(event: &mut Value, stats: &DirectTcpRelayStats) {
    event["bytes_client_to_proxy"] = json!(stats.client_to_direct);
    event["bytes_proxy_to_client"] = json!(stats.direct_to_client);
    event["response_header_stripped"] = json!(false);
    event["vision_unpadding_blocks"] = json!(0);
    event["vision_direct_command_seen"] = json!(false);
    event["vision_raw_direct_recovered"] = json!(false);
    event["vision_downlink_direct_active"] = json!(false);
}

fn handle_direct_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpDirectSelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut direct = open_direct_tcp_connection(
        &selection.route.dial_target,
        selection.route.final_mark,
        selection.mptcp,
    )?;
    let stats = relay_tcp_direct(inbound, &mut direct.stream, stop, &sniff.payload, metrics)?;
    Ok(direct_tcp_finished_event(
        peer,
        original_dst,
        &selection,
        sniff,
        direct.target,
        &direct.report,
        &stats,
        "per-connection-thread-legacy",
    ))
}

async fn handle_direct_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpDirectSelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let direct = open_direct_tcp_connection_async(
        selection.route.dial_target.clone(),
        selection.route.final_mark,
        selection.mptcp,
    )
    .await?;
    let DirectTcpConnection {
        stream,
        report,
        target,
    } = direct;
    let mut direct_stream = TokioTcpStream::from_std(stream)
        .map_err(|err| format!("adopt async direct TCP stream: {err}"))?;
    let stats =
        relay_tcp_direct_async(inbound, &mut direct_stream, stop, &sniff.payload, metrics).await?;
    Ok(direct_tcp_finished_event(
        peer,
        original_dst,
        &selection,
        sniff,
        target,
        &report,
        &stats,
        "async-direct-v1",
    ))
}

fn direct_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpDirectSelection,
    sniff: &TcpSniffReport,
    direct_target: SocketAddrV4,
    direct_report: &TcpDirectDialReport,
    stats: &DirectTcpRelayStats,
    execution: &'static str,
) -> Value {
    let mut event = json!({
        "event": "tcp_connection_finished",
        "outbound_kind": "direct",
        "peer": peer.to_string(),
        "original_dst": original_dst.to_string(),
        "dial_target": &selection.route.dial_target,
        "dial_ip": selection.route.dial_ip,
        "initial_outbound": selection.route.initial_outbound,
        "final_outbound": selection.route.final_outbound,
        "final_mark": selection.route.final_mark,
        "userspace_route_executed": selection.route.userspace_route_executed,
        "userspace_route_must": selection.route.userspace_route_must,
        "sniffed_domain": &sniff.domain,
        "sniff_error": &sniff.error,
        "direct_target": direct_target.to_string(),
        "direct_peer_addr": &direct_report.peer_addr,
        "direct_local_addr": &direct_report.local_addr,
        "direct_so_mark": direct_report.so_mark,
        "direct_so_mark_applied": direct_report.so_mark_applied,
        "direct_mptcp_requested": direct_report.requested_mptcp,
        "direct_mptcp_socket_attempted": direct_report.mptcp_socket_attempted,
        "direct_mptcp_socket_created": direct_report.mptcp_socket_created,
        "direct_mptcp_connect_fallback_used": direct_report.mptcp_connect_fallback_used,
        "bytes_client_to_direct": stats.client_to_direct,
        "bytes_direct_to_client": stats.direct_to_client,
        "execution": execution,
    });
    append_tcp_route_log_fields(&mut event, &selection.route, "direct", "fixed", "direct");
    event
}

fn append_tcp_route_log_fields(
    event: &mut Value,
    route: &TcpRouteSelection,
    outbound: &str,
    policy: &str,
    dialer: &str,
) {
    event["network"] = json!("tcp4");
    event["outbound"] = json!(outbound);
    event["policy"] = json!(policy);
    event["dialer"] = json!(dialer);
    event["sniffed"] = event["sniffed_domain"].clone();
    event["ip"] = event["original_dst"].clone();
    event["pid"] = json!(route.log_metadata.pid);
    event["dscp"] = json!(route.log_metadata.dscp);
    event["pname"] = json!(&route.log_metadata.pname);
    event["mac"] = json!(&route.log_metadata.mac);
}

fn sniff_initial_tcp_payload(
    inbound: &mut TcpStream,
    timeout: Duration,
) -> Result<TcpSniffReport, String> {
    if timeout.is_zero() {
        return Ok(TcpSniffReport {
            payload: Vec::new(),
            domain: String::new(),
            error: None,
        });
    }

    let started = Instant::now();
    let mut payload = Vec::new();
    let mut buf = [0_u8; 4096];
    let mut last_error = None;
    loop {
        loop {
            match inbound.read(&mut buf) {
                Ok(0) => {
                    return Ok(TcpSniffReport {
                        payload,
                        domain: String::new(),
                        error: last_error,
                    });
                }
                Ok(read) => {
                    payload.extend_from_slice(&buf[..read]);
                    if payload.len() > TCP_SNIFF_BUFFER_LIMIT {
                        return Ok(TcpSniffReport {
                            payload,
                            domain: String::new(),
                            error: Some(format!(
                                "sniffing skipped after buffered payload exceeded {TCP_SNIFF_BUFFER_LIMIT} bytes"
                            )),
                        });
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(err) => return Err(format!("read inbound TCP for sniffing: {err}")),
            }
        }

        if !payload.is_empty() {
            match sniff_tcp(&payload) {
                Ok(domain) => {
                    return Ok(TcpSniffReport {
                        payload,
                        domain,
                        error: None,
                    });
                }
                Err(err) if sniff_needs_more(&err) && started.elapsed() < timeout => {
                    last_error = Some(err.to_string());
                }
                Err(err) => {
                    return Ok(TcpSniffReport {
                        payload,
                        domain: String::new(),
                        error: Some(err.to_string()),
                    });
                }
            }
        }

        if started.elapsed() >= timeout {
            return Ok(TcpSniffReport {
                payload,
                domain: String::new(),
                error: last_error.or_else(|| Some("sniffing timeout".to_owned())),
            });
        }
        thread::sleep(RESIDENT_IDLE_SLEEP);
    }
}

async fn sniff_initial_tcp_payload_async(
    inbound: &mut TokioTcpStream,
    timeout: Duration,
) -> Result<TcpSniffReport, String> {
    if timeout.is_zero() {
        return Ok(TcpSniffReport {
            payload: Vec::new(),
            domain: String::new(),
            error: None,
        });
    }

    let deadline = time::Instant::now() + timeout;
    let mut payload = Vec::new();
    let mut buf = [0_u8; 4096];
    let mut last_error = None;
    loop {
        let now = time::Instant::now();
        if now >= deadline {
            return Ok(TcpSniffReport {
                payload,
                domain: String::new(),
                error: last_error.or_else(|| Some("sniffing timeout".to_owned())),
            });
        }
        match time::timeout(
            deadline.saturating_duration_since(now),
            inbound.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                return Ok(TcpSniffReport {
                    payload,
                    domain: String::new(),
                    error: last_error,
                });
            }
            Ok(Ok(read)) => {
                payload.extend_from_slice(&buf[..read]);
                if payload.len() > TCP_SNIFF_BUFFER_LIMIT {
                    return Ok(TcpSniffReport {
                        payload,
                        domain: String::new(),
                        error: Some(format!(
                            "sniffing skipped after buffered payload exceeded {TCP_SNIFF_BUFFER_LIMIT} bytes"
                        )),
                    });
                }
            }
            Ok(Err(err)) => return Err(format!("read inbound TCP for async sniffing: {err}")),
            Err(_) => {
                return Ok(TcpSniffReport {
                    payload,
                    domain: String::new(),
                    error: last_error.or_else(|| Some("sniffing timeout".to_owned())),
                });
            }
        }

        match sniff_tcp(&payload) {
            Ok(domain) => {
                return Ok(TcpSniffReport {
                    payload,
                    domain,
                    error: None,
                });
            }
            Err(err) if sniff_needs_more(&err) => {
                last_error = Some(err.to_string());
            }
            Err(err) => {
                return Ok(TcpSniffReport {
                    payload,
                    domain: String::new(),
                    error: Some(err.to_string()),
                });
            }
        }
    }
}

fn sniff_needs_more(err: &SniffingError) -> bool {
    matches!(err, SniffingError::NeedMore) || err.to_string().contains("need more")
}

fn process_name(raw: &[u8; 16]) -> Option<String> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    (end > 0).then(|| String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn mac_string(raw: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]
    )
}

fn ipv4_mapped_ip_bytes(addr: Ipv4Addr) -> BpfIpBytes {
    let mut out = [0_u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&addr.octets());
    BpfIpBytes { u6_addr8: out }
}

fn bytes_of<T>(value: &T) -> &[u8] {
    unsafe { slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

fn bytes_of_mut<T>(value: &mut T) -> &mut [u8] {
    unsafe { slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), size_of::<T>()) }
}

#[derive(Clone, Debug, Default)]
struct RelayStats {
    client_to_proxy: usize,
    proxy_to_client: usize,
    response_header_stripped: bool,
    vision_unpadding_blocks: usize,
    vision_direct_command_seen: bool,
    vision_raw_direct_recovered: bool,
    vision_downlink_direct_active: bool,
}

#[derive(Debug)]
struct RelayError {
    message: String,
    stats: RelayStats,
}

impl RelayError {
    fn new(message: impl Into<String>, stats: &RelayStats) -> Self {
        Self {
            message: message.into(),
            stats: stats.clone(),
        }
    }
}

fn relay_tcp_over_vless_tls(
    inbound: &mut TcpStream,
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
    flow: &str,
    user_uuid: [u8; 16],
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let vision_enabled = flow == XTLS_RPRX_VISION;
    let mut vision = vision_enabled.then(|| VisionUnpadder::new(user_uuid));
    let mut downlink_direct = false;
    let mut vision_uplink_mode = VisionUplinkMode::Padding;
    let mut vision_tls_state = VisionInnerTlsState::new();
    let mut uplink_uuid_sent = false;
    let mut vision_first_uplink_block = true;
    let mut pending_vision_uplink = Vec::<u8>::new();
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];
    if !initial_payload.is_empty() {
        if vision_enabled {
            pending_vision_uplink.extend_from_slice(initial_payload);
            drain_vision_uplink(
                &mut pending_vision_uplink,
                client,
                stop,
                user_uuid,
                &mut uplink_uuid_sent,
                &mut vision_first_uplink_block,
                &mut vision_uplink_mode,
                &mut vision_tls_state,
            )
            .map_err(|err| RelayError::new(err, &stats))?;
        } else {
            client
                .queue_plain(initial_payload, "queue sniffed client payload to proxy TLS")
                .map_err(|err| RelayError::new(err.to_string(), &stats))?;
        }
        stats.client_to_proxy += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    while !stop.load(Ordering::Relaxed) {
        let mut progressed = false;
        if !inbound_closed {
            match inbound.read(&mut inbound_buf) {
                Ok(0) => {
                    inbound_closed = true;
                    client.send_close_notify();
                    progressed = true;
                }
                Ok(read) => {
                    if vision_enabled {
                        pending_vision_uplink.extend_from_slice(&inbound_buf[..read]);
                        if pending_vision_uplink.len() > TLS_RECORD_MAX_PAYLOAD_LEN * 4 {
                            return Err(RelayError::new(
                                format!(
                                    "pending Vision uplink payload did not form complete TLS records: {} bytes",
                                    pending_vision_uplink.len()
                                ),
                                &stats,
                            ));
                        }
                        drain_vision_uplink(
                            &mut pending_vision_uplink,
                            client,
                            stop,
                            user_uuid,
                            &mut uplink_uuid_sent,
                            &mut vision_first_uplink_block,
                            &mut vision_uplink_mode,
                            &mut vision_tls_state,
                        )
                        .map_err(|err| RelayError::new(err, &stats))?;
                    } else {
                        client
                            .queue_plain(&inbound_buf[..read], "queue client payload to proxy TLS")
                            .map_err(|err| RelayError::new(err.to_string(), &stats))?;
                    }
                    stats.client_to_proxy += read;
                    metrics.add_upload(read);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => {
                    return Err(RelayError::new(format!("read inbound TCP: {err}"), &stats));
                }
            }
        }

        if downlink_direct {
            match client.raw_read(&mut proxy_buf) {
                Ok(0) => {
                    break;
                }
                Ok(read) => {
                    write_all_nonblocking(
                        inbound,
                        &proxy_buf[..read],
                        stop,
                        "write VLESS Vision direct payload to client",
                    )
                    .map_err(|err| RelayError::new(err, &stats))?;
                    stats.proxy_to_client += read;
                    metrics.add_download(read);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => {
                    return Err(RelayError::new(
                        format!("read VLESS Vision direct TCP: {err}"),
                        &stats,
                    ));
                }
            }
        } else {
            match drive_tls_io_record_aware(client)
                .map_err(|err| RelayError::new(err.to_string(), &stats))?
            {
                TlsDriveOutcome::Progressed(tls_progressed) => progressed |= tls_progressed,
                TlsDriveOutcome::DecryptErrorRawRecord { record, error } => {
                    if can_recover_vision_raw_direct_after_tls_error(
                        vision_enabled,
                        stats.response_header_stripped,
                        vision.as_ref(),
                    ) {
                        downlink_direct = true;
                        stats.vision_downlink_direct_active = true;
                        stats.vision_raw_direct_recovered = true;
                        write_all_nonblocking(
                            inbound,
                            &record,
                            stop,
                            "write recovered VLESS Vision raw-direct payload to client",
                        )
                        .map_err(|err| RelayError::new(err, &stats))?;
                        stats.proxy_to_client += record.len();
                        metrics.add_download(record.len());
                        progressed = true;
                    } else {
                        return Err(RelayError::new(error, &stats));
                    }
                }
            }
            loop {
                match client.read_plain(&mut proxy_buf) {
                    Ok(0) => break,
                    Ok(read) => {
                        let mut payload = stripper
                            .consume(&proxy_buf[..read])
                            .map_err(|err| RelayError::new(err, &stats))?;
                        stats.response_header_stripped = stripper.done;
                        if let Some(vision) = vision.as_mut()
                            && !payload.is_empty()
                        {
                            payload = vision
                                .consume(&payload)
                                .map_err(|err| RelayError::new(err, &stats))?;
                            vision_tls_state
                                .observe_server_payload(&payload)
                                .map_err(|err| RelayError::new(err, &stats))?;
                            stats.vision_unpadding_blocks = vision.completed_blocks;
                            stats.vision_direct_command_seen = vision.direct_command_seen;
                            downlink_direct = vision.direct_command_seen;
                            stats.vision_downlink_direct_active = downlink_direct;
                            if !pending_vision_uplink.is_empty() {
                                drain_vision_uplink(
                                    &mut pending_vision_uplink,
                                    client,
                                    stop,
                                    user_uuid,
                                    &mut uplink_uuid_sent,
                                    &mut vision_first_uplink_block,
                                    &mut vision_uplink_mode,
                                    &mut vision_tls_state,
                                )
                                .map_err(|err| RelayError::new(err, &stats))?;
                            }
                        }
                        if !payload.is_empty() {
                            write_all_nonblocking(
                                inbound,
                                &payload,
                                stop,
                                "write VLESS payload to client",
                            )
                            .map_err(|err| RelayError::new(err, &stats))?;
                            stats.proxy_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        progressed = true;
                        if downlink_direct {
                            break;
                        }
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    Err(err) => {
                        return Err(RelayError::new(
                            format!("read VLESS TLS plaintext: {err}"),
                            &stats,
                        ));
                    }
                }
            }
        }

        if inbound_closed && !downlink_direct && client.idle_tls_complete() {
            break;
        }
        if progressed {
            last_activity = Instant::now();
        } else if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
            return Err(RelayError::new("resident TCP relay idle timeout", &stats));
        } else {
            thread::sleep(RESIDENT_IDLE_SLEEP);
        }
    }
    Ok(stats)
}

async fn relay_tcp_over_vless_tls_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncVlessTlsClient,
    stop: Arc<AtomicBool>,
    flow: &str,
    user_uuid: [u8; 16],
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let vision_enabled = flow == XTLS_RPRX_VISION;
    let mut vision = vision_enabled.then(|| VisionUnpadder::new(user_uuid));
    let mut downlink_direct = false;
    let mut vision_uplink_mode = VisionUplinkMode::Padding;
    let mut vision_tls_state = VisionInnerTlsState::new();
    let mut uplink_uuid_sent = false;
    let mut vision_first_uplink_block = true;
    let mut pending_vision_uplink = Vec::<u8>::new();
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    if !initial_payload.is_empty() {
        if vision_enabled {
            pending_vision_uplink.extend_from_slice(initial_payload);
            drain_vision_uplink_async(
                &mut pending_vision_uplink,
                client,
                &stop,
                user_uuid,
                &mut uplink_uuid_sent,
                &mut vision_first_uplink_block,
                &mut vision_uplink_mode,
                &mut vision_tls_state,
            )
            .await
            .map_err(|err| RelayError::new(err, &stats))?;
        } else {
            client
                .write_plain_all(initial_payload, "write sniffed client payload to proxy TLS")
                .await
                .map_err(|err| RelayError::new(err, &stats))?;
        }
        stats.client_to_proxy += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        if vision_enabled {
                            pending_vision_uplink.extend_from_slice(&inbound_buf[..read]);
                            if pending_vision_uplink.len() > TLS_RECORD_MAX_PAYLOAD_LEN * 4 {
                                return Err(RelayError::new(
                                    format!(
                                        "pending Vision uplink payload did not form complete TLS records: {} bytes",
                                        pending_vision_uplink.len()
                                    ),
                                    &stats,
                                ));
                            }
                            drain_vision_uplink_async(
                                &mut pending_vision_uplink,
                                client,
                                &stop,
                                user_uuid,
                                &mut uplink_uuid_sent,
                                &mut vision_first_uplink_block,
                                &mut vision_uplink_mode,
                                &mut vision_tls_state,
                            )
                            .await
                            .map_err(|err| RelayError::new(err, &stats))?;
                        } else {
                            client
                                .write_plain_all(&inbound_buf[..read], "write client payload to proxy TLS")
                                .await
                                .map_err(|err| RelayError::new(err, &stats))?;
                        }
                        stats.client_to_proxy += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read inbound TCP: {err}"), &stats));
                    }
                }
            }
            proxy_read = async {
                if downlink_direct {
                    client.raw_read(&mut proxy_buf).await
                } else {
                    client.read_plain(&mut proxy_buf).await
                }
            } => {
                match proxy_read {
                    Ok(0) => break,
                    Ok(read) => {
                        if downlink_direct {
                            inbound
                                .write_all(&proxy_buf[..read])
                                .await
                                .map_err(|err| RelayError::new(format!("write VLESS Vision direct payload to client: {err}"), &stats))?;
                            stats.proxy_to_client += read;
                            metrics.add_download(read);
                            last_activity = Instant::now();
                            continue;
                        }

                        let mut payload = stripper
                            .consume(&proxy_buf[..read])
                            .map_err(|err| RelayError::new(err, &stats))?;
                        stats.response_header_stripped = stripper.done;
                        if let Some(vision) = vision.as_mut()
                            && !payload.is_empty()
                        {
                            payload = vision
                                .consume(&payload)
                                .map_err(|err| RelayError::new(err, &stats))?;
                            vision_tls_state
                                .observe_server_payload(&payload)
                                .map_err(|err| RelayError::new(err, &stats))?;
                            stats.vision_unpadding_blocks = vision.completed_blocks;
                            stats.vision_direct_command_seen = vision.direct_command_seen;
                            downlink_direct = vision.direct_command_seen;
                            stats.vision_downlink_direct_active = downlink_direct;
                            if !pending_vision_uplink.is_empty() {
                                drain_vision_uplink_async(
                                    &mut pending_vision_uplink,
                                    client,
                                    &stop,
                                    user_uuid,
                                    &mut uplink_uuid_sent,
                                    &mut vision_first_uplink_block,
                                    &mut vision_uplink_mode,
                                    &mut vision_tls_state,
                                )
                                .await
                                .map_err(|err| RelayError::new(err, &stats))?;
                            }
                        }
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| RelayError::new(format!("write VLESS payload to client: {err}"), &stats))?;
                            stats.proxy_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read VLESS TLS plaintext: {err}"), &stats));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed && !downlink_direct {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err(RelayError::new("resident TCP relay idle timeout", &stats));
                }
            }
        }
    }
    Ok(stats)
}

fn can_recover_vision_raw_direct_after_tls_error(
    vision_enabled: bool,
    response_header_stripped: bool,
    vision: Option<&VisionUnpadder>,
) -> bool {
    vision_enabled
        && response_header_stripped
        && vision.is_some_and(|vision| vision.direct_command_seen)
}

#[derive(Default)]
pub(super) struct VlessResponseStripper {
    header: Vec<u8>,
    done: bool,
}

impl VlessResponseStripper {
    fn consume(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if self.done {
            return Ok(input.to_vec());
        }
        self.header.extend_from_slice(input);
        if self.header.len() < 2 {
            return Ok(Vec::new());
        }
        if self.header[0] != VLESS_RESPONSE_VERSION {
            return Err(format!(
                "unexpected VLESS response version: {}",
                self.header[0]
            ));
        }
        let header_len = 2 + self.header[1] as usize;
        if self.header.len() < header_len {
            return Ok(Vec::new());
        }
        self.done = true;
        Ok(self.header.split_off(header_len))
    }
}

#[cfg(test)]
mod tests {
    use super::super::vision::VisionUnpadState;
    use super::*;
    use serde_json::json;

    const FLOW_DIAL_TARGET: &str = "flow-dial-target";
    const FLOW_OUTBOUND: &str = "flow-outbound";
    const FLOW_POLICY: &str = "fixed";
    const FLOW_DIALER: &str = "flow-dialer";
    const FLOW_PROCESS: &str = "flow-process";
    const FLOW_MAC: &str = "flow-mac";
    const FLOW_SNIFFED_DOMAIN: &str = "flow-sniffed-domain";

    #[test]
    fn resident_vless_response_stripper_handles_split_header() {
        let mut stripper = VlessResponseStripper::default();
        assert!(stripper.consume(&[0]).unwrap().is_empty());
        assert!(stripper.consume(&[3, b'a']).unwrap().is_empty());
        assert_eq!(stripper.consume(b"bcOK").unwrap(), b"OK");
        assert!(stripper.done);
        assert_eq!(stripper.consume(b"NEXT").unwrap(), b"NEXT");
    }

    #[test]
    fn proxy_failure_event_carries_relay_diagnostics() {
        let selection = TcpProxySelection {
            route: TcpRouteSelection {
                initial_outbound: 7,
                final_outbound: 7,
                final_mark: 0x55,
                userspace_route_executed: true,
                userspace_route_must: false,
                dial_target: FLOW_DIAL_TARGET.to_owned(),
                dial_ip: false,
                log_metadata: TcpRoutingLogMetadata {
                    pid: 1,
                    dscp: 2,
                    pname: FLOW_PROCESS.to_owned(),
                    mac: FLOW_MAC.to_owned(),
                },
            },
            proxy: dummy_proxy_plan(),
        };
        let sniff = TcpSniffReport {
            payload: Vec::new(),
            domain: FLOW_SNIFFED_DOMAIN.to_owned(),
            error: None,
        };
        let stats = RelayStats {
            client_to_proxy: 128,
            proxy_to_client: 64,
            response_header_stripped: true,
            vision_unpadding_blocks: 2,
            vision_direct_command_seen: false,
            vision_raw_direct_recovered: false,
            vision_downlink_direct_active: false,
        };
        let err = RelayError::new("read proxy plaintext: sample failure", &stats);

        let event = proxy_tcp_failed_event(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100)),
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443),
            &selection,
            &sniff,
            "boringssl",
            &err,
        );

        assert_eq!(event["event"], "tcp_connection_failed");
        assert_eq!(event["tls_underlay"], "boringssl");
        assert_eq!(event["error"], "read proxy plaintext: sample failure");
        assert_eq!(event["bytes_client_to_proxy"], 128);
        assert_eq!(event["bytes_proxy_to_client"], 64);
        assert_eq!(event["response_header_stripped"], true);
        assert_eq!(event["vision_unpadding_blocks"], 2);
        assert_eq!(event["vision_direct_command_seen"], false);
        assert_eq!(event["vision_raw_direct_recovered"], false);
        assert_eq!(event["vision_downlink_direct_active"], false);
        assert_eq!(event["proxy_group"], FLOW_OUTBOUND);
        assert_eq!(event["group_policy"], FLOW_POLICY);
        assert_eq!(event["node_tag"], FLOW_DIALER);
        assert_eq!(event["sniffed_domain"], FLOW_SNIFFED_DOMAIN);
    }

    #[test]
    fn resident_vision_raw_direct_recovery_requires_explicit_direct_command() {
        let key = [7_u8; 16];
        let mut unpadder = VisionUnpadder::new(key);
        assert!(!can_recover_vision_raw_direct_after_tls_error(
            true,
            true,
            Some(&unpadder)
        ));

        let mut uuid_sent = false;
        let end_block = super::super::vision::vision_padding_block(
            b"tail",
            super::super::VISION_COMMAND_END,
            key,
            &mut uuid_sent,
            false,
        );
        let mut ended = VisionUnpadder::new(key);
        assert_eq!(ended.consume(&end_block).unwrap(), b"tail");
        assert!(matches!(ended.state, VisionUnpadState::Raw));
        assert!(!can_recover_vision_raw_direct_after_tls_error(
            true,
            true,
            Some(&ended)
        ));

        let mut uuid_sent = false;
        let block = super::super::vision::vision_padding_block(
            b"hello",
            super::super::VISION_COMMAND_CONTINUE,
            key,
            &mut uuid_sent,
            false,
        );
        assert_eq!(unpadder.consume(&block).unwrap(), b"hello");
        assert!(!can_recover_vision_raw_direct_after_tls_error(
            true,
            true,
            Some(&unpadder)
        ));

        let mut uuid_sent = false;
        let direct_block = super::super::vision::vision_padding_block(
            b"raw",
            super::super::VISION_COMMAND_DIRECT,
            key,
            &mut uuid_sent,
            false,
        );
        let mut direct = VisionUnpadder::new(key);
        assert_eq!(direct.consume(&direct_block).unwrap(), b"raw");
        assert!(direct.direct_command_seen);
        assert!(can_recover_vision_raw_direct_after_tls_error(
            true,
            true,
            Some(&direct)
        ));
        assert!(!can_recover_vision_raw_direct_after_tls_error(
            false,
            true,
            Some(&direct)
        ));
        assert!(!can_recover_vision_raw_direct_after_tls_error(
            true,
            false,
            Some(&direct)
        ));
    }

    #[test]
    fn resident_tcp_selection_allows_builtin_direct_without_proxy_plan() {
        let router =
            tcp_router_for_test(fallback_matcher("user:2", 0), TcpDialMode::DomainPlusPlus);
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100);
        let dst = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443);
        let selection = router
            .select_from_routing_result(
                peer,
                dst,
                "www.example.com",
                BpfRoutingResult {
                    outbound: OUTBOUND_DIRECT,
                    ..BpfRoutingResult::default()
                },
            )
            .unwrap();
        let TcpSelection::Direct(selection) = selection else {
            panic!("expected direct selection");
        };
        assert_eq!(selection.route.initial_outbound, OUTBOUND_DIRECT);
        assert_eq!(selection.route.final_outbound, OUTBOUND_DIRECT);
        assert_eq!(selection.route.final_mark, 0x1234);
        assert_eq!(selection.route.dial_target, dst.to_string());
        assert!(selection.route.dial_ip);
        assert!(!selection.route.userspace_route_executed);
        assert!(selection.mptcp);
    }

    #[test]
    fn resident_tcp_selection_reroutes_control_plane_result_to_direct() {
        let router = tcp_router_for_test(
            fallback_matcher("direct", 0x77),
            TcpDialMode::DomainPlusPlus,
        );
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100);
        let dst = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 99), 443);
        let selection = router
            .select_from_routing_result(
                peer,
                dst,
                "www.reroute.test",
                BpfRoutingResult {
                    outbound: OUTBOUND_CONTROL_PLANE_ROUTING,
                    ..BpfRoutingResult::default()
                },
            )
            .unwrap();
        let TcpSelection::Direct(selection) = selection else {
            panic!("expected direct selection after userspace reroute");
        };
        assert_eq!(
            selection.route.initial_outbound,
            OUTBOUND_CONTROL_PLANE_ROUTING
        );
        assert_eq!(selection.route.final_outbound, OUTBOUND_DIRECT);
        assert_eq!(selection.route.final_mark, 0x77);
        assert_eq!(selection.route.dial_target, dst.to_string());
        assert!(selection.route.userspace_route_executed);
    }

    #[test]
    fn resident_tcp_selection_returns_block_without_proxy_plan() {
        let router = tcp_router_for_test(fallback_matcher("user:2", 0), TcpDialMode::Ip);
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100);
        let dst = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443);
        let selection = router
            .select_from_routing_result(
                peer,
                dst,
                "",
                BpfRoutingResult {
                    outbound: OUTBOUND_BLOCK,
                    ..BpfRoutingResult::default()
                },
            )
            .unwrap();
        let TcpSelection::Block(selection) = selection else {
            panic!("expected block selection");
        };
        assert_eq!(selection.route.final_outbound, OUTBOUND_BLOCK);
        assert_eq!(selection.route.final_mark, 0x1234);
    }

    #[test]
    fn resident_tcp_selection_still_rejects_missing_user_proxy_plan() {
        let router = tcp_router_for_test(fallback_matcher("user:2", 0), TcpDialMode::Ip);
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100);
        let dst = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443);
        let err = router
            .select_from_routing_result(
                peer,
                dst,
                "",
                BpfRoutingResult {
                    outbound: 9,
                    ..BpfRoutingResult::default()
                },
            )
            .unwrap_err();
        assert!(err.contains("no Rust proxy plan is available"));
        assert!(err.contains("unsupported protocol"));
    }

    #[test]
    fn resident_tcp_selection_keeps_ip_target_when_domain_plus_plus_has_no_sniffed_domain() {
        let router = tcp_router_for_test(
            fallback_matcher("direct", 0x77),
            TcpDialMode::DomainPlusPlus,
        );
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100);
        let dst = SocketAddrV4::new(Ipv4Addr::new(91, 108, 56, 177), 443);
        let selection = router
            .select_from_routing_result(
                peer,
                dst,
                "",
                BpfRoutingResult {
                    outbound: OutboundIndex::USER_DEFINED_MIN.value(),
                    mark: 0x55,
                    ..BpfRoutingResult::default()
                },
            )
            .unwrap();
        let TcpSelection::Proxy(selection) = selection else {
            panic!("expected proxy selection");
        };
        assert_eq!(
            selection.route.initial_outbound,
            OutboundIndex::USER_DEFINED_MIN.value()
        );
        assert_eq!(
            selection.route.final_outbound,
            OutboundIndex::USER_DEFINED_MIN.value()
        );
        assert_eq!(selection.route.dial_target, dst.to_string());
        assert!(selection.route.dial_ip);
        assert!(!selection.route.userspace_route_executed);
        assert_eq!(selection.route.final_mark, 0x55);
    }

    fn tcp_router_for_test(
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
    ) -> ResidentTcpRouter {
        let mut proxies = BTreeMap::new();
        proxies.insert(OutboundIndex::USER_DEFINED_MIN.value(), dummy_proxy_plan());
        ResidentTcpRouter::new(
            proxies,
            Some(1),
            routing_matcher,
            dial_mode,
            Duration::from_millis(100),
            0x1234,
            true,
        )
        .unwrap()
    }

    fn fallback_matcher(outbound: &str, mark: u32) -> RoutingMatcher {
        RoutingMatcher::from_fixture_value(&json!({
            "matches": [
                {
                    "type": "fallback",
                    "outbound": outbound,
                    "mark": mark
                }
            ],
            "domain_sets": [],
            "lpm_sets": []
        }))
        .unwrap()
    }

    fn dummy_proxy_plan() -> ResidentProxyPlan {
        ResidentProxyPlan {
            protocol: "vless".to_owned(),
            group_name: FLOW_OUTBOUND.to_owned(),
            group_policy: FLOW_POLICY.to_owned(),
            node_tag: FLOW_DIALER.to_owned(),
            server_host: "127.0.0.1".to_owned(),
            server_port: 443,
            server_name: "example.com".to_owned(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            tls: "tls".to_owned(),
            allow_insecure: false,
            utls_fingerprint: None,
            handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] },
            mark: 0,
            mptcp: false,
        }
    }
}
