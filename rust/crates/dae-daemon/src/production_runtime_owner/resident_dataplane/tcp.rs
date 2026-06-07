use std::collections::{BTreeMap, VecDeque};
use std::future::poll_fn;
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
    Arc, Condvar, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
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
    shadowsocks::{
        AeadStreamCodec, ShadowsocksMetadata, Sip003SimpleObfsHttpOptions,
        read_encrypted_chunk_from_stream, simple_obfs_http_request_with_body,
    },
    shared_transport::{
        DEFAULT_WS_KEY, HttpUpgradeOptions, MeekRoundTripOptions, WS_MASK_KEY, grpc_hunk_frame,
        grpc_hunk_payload, http_upgrade_request, ir, meek_http_request, read_http_head,
        validate_http_status, websocket_client_binary_frame, websocket_handshake_request,
    },
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
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
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
use super::execution::{append_runtime_execution_descriptor, tcp_execution_descriptor};
use super::io::write_all_nonblocking;
use super::plan::{ResidentProxyGroupPlan, ResidentProxyPlan, ResidentProxyProtocolPlan};
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
const ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) struct ResidentTcpRouter {
    proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
    routing_tuple_map_id: u32,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    sniffing_timeout: Duration,
    so_mark_from_dae: u32,
    mptcp: bool,
}

impl ResidentTcpRouter {
    pub(super) fn new(
        proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
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
                let Some(proxy_group) = self.proxies.get(&final_outbound) else {
                    return Err(format!(
                        "resident TCP selected outbound {} but no Rust proxy plan is available; unsupported protocol must stay on Go control plane until implemented",
                        OutboundIndex(final_outbound)
                    ));
                };
                let mut proxy = proxy_group.select_proxy_for_tcp()?;
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

pub(super) fn probe_resident_proxy_tcp(
    proxy: &ResidentProxyPlan,
    scheme: &str,
    target: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|err| format!("bind resident TCP probe loopback listener: {err}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|err| format!("read resident TCP probe listener address: {err}"))?;
    let mut client = TcpStream::connect(listen_addr)
        .map_err(|err| format!("connect resident TCP probe loopback client: {err}"))?;
    client
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("set resident TCP probe read timeout: {err}"))?;
    client
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("set resident TCP probe write timeout: {err}"))?;
    let (accepted, peer) = listener
        .accept()
        .map_err(|err| format!("accept resident TCP probe loopback stream: {err}"))?;
    accepted
        .set_nonblocking(true)
        .map_err(|err| format!("set resident TCP probe inbound nonblocking: {err}"))?;

    let selection = TcpProxySelection {
        route: TcpRouteSelection {
            initial_outbound: 0,
            final_outbound: 0,
            final_mark: proxy.mark,
            userspace_route_executed: false,
            userspace_route_must: false,
            dial_target: target.to_owned(),
            dial_ip: false,
            log_metadata: TcpRoutingLogMetadata {
                pid: 0,
                dscp: 0,
                pname: String::new(),
                mac: String::new(),
            },
        },
        proxy: proxy.clone(),
    };
    let sniff = TcpSniffReport {
        payload: if scheme == "https" {
            Vec::new()
        } else {
            resident_tcp_probe_http_request(method, path, host)
        },
        domain: host.to_owned(),
        error: None,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let handler_stop = Arc::clone(&stop);
    let handler_metrics = Arc::clone(&metrics);
    let original_dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let handle = thread::Builder::new()
        .name("dae-resident-tcp-probe".to_owned())
        .spawn(move || {
            let runtime = runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|err| format!("build resident TCP probe runtime: {err}"))?;
            runtime.block_on(async move {
                let mut inbound = TokioTcpStream::from_std(accepted)
                    .map_err(|err| format!("adopt resident TCP probe inbound stream: {err}"))?;
                if matches!(
                    selection.proxy.handler,
                    ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
                ) {
                    handle_proxy_tcp_connection_async(
                        &mut inbound,
                        peer,
                        original_dst,
                        selection,
                        handler_stop,
                        &sniff,
                        &handler_metrics,
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
                        handler_stop,
                        &sniff,
                        &handler_metrics,
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
                        handler_stop,
                        &sniff,
                        &handler_metrics,
                    )
                    .await
                } else {
                    handle_first_batch_proxy_tcp_connection_async(
                        inbound,
                        peer,
                        original_dst,
                        selection,
                        handler_stop,
                        sniff,
                        handler_metrics,
                    )
                    .await
                }
            })
        })
        .map_err(|err| format!("spawn resident TCP probe handler: {err}"))?;

    let response_result = match scheme {
        "http" => read_resident_tcp_probe_response(&mut client, path),
        "https" => read_resident_tcp_probe_https_response(&mut client, host, path, method),
        other => Err(format!("resident TCP probe unsupported scheme: {other}")),
    };
    stop.store(true, Ordering::Relaxed);
    let _ = client.shutdown(Shutdown::Both);
    let handler_result = handle
        .join()
        .map_err(|_| "join resident TCP probe handler: panicked".to_owned())?;
    match response_result {
        Ok(()) => Ok(()),
        Err(response_err) => match handler_result {
            Ok(event) => Err(format!(
                "{response_err}; handler_event={}",
                sanitize_probe_event(event)
            )),
            Err(handler_err) => Err(format!("{response_err}; handler_error={handler_err}")),
        },
    }
}

fn resident_tcp_probe_http_request(method: &str, path: &str, host: &str) -> Vec<u8> {
    let method = if method.is_empty() { "HEAD" } else { method };
    let path = if path.is_empty() { "/" } else { path };
    format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dae-rust-resident-check\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn read_resident_tcp_probe_https_response(
    stream: &mut TcpStream,
    host: &str,
    path: &str,
    method: &str,
) -> Result<(), String> {
    let config = resident_tcp_probe_tls_config();
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|err| format!("resident TCP probe invalid HTTPS server name {host}: {err}"))?;
    let conn = ClientConnection::new(config, server_name)
        .map_err(|err| format!("resident TCP probe create HTTPS client: {err}"))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let request = resident_tcp_probe_http_request(method, path, host);
    tls.write_all(&request)
        .map_err(|err| format!("write resident HTTPS probe request: {err}"))?;
    tls.flush()
        .map_err(|err| format!("flush resident HTTPS probe request: {err}"))?;
    read_resident_tcp_probe_response(&mut tls, path)
}

fn resident_tcp_probe_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

fn read_resident_tcp_probe_response(stream: &mut impl Read, path: &str) -> Result<(), String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    while response.len() < 8192 {
        let read = stream
            .read(&mut buf)
            .map_err(|err| format!("read resident TCP probe response: {err}"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(2).any(|window| window == b"\r\n") && response.len() >= 12 {
            break;
        }
    }
    if response.is_empty() {
        return Err("resident TCP probe got empty response".to_owned());
    }
    let text = String::from_utf8_lossy(&response);
    let mut fields = text.split_whitespace();
    let version = fields.next().unwrap_or("");
    let status = fields
        .next()
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| format!("resident TCP probe bad HTTP response: {text:?}"))?;
    if !version.starts_with("HTTP/") {
        return Err(format!("resident TCP probe non-HTTP response: {text:?}"));
    }
    if resident_tcp_probe_status_ok(path, status) {
        Ok(())
    } else {
        Err(format!("resident TCP probe bad HTTP status: {status}"))
    }
}

fn resident_tcp_probe_status_ok(path: &str, status: u16) -> bool {
    let page = path.rsplit('/').next().unwrap_or("");
    if let Some(expected) = page.strip_prefix("generate_")
        && let Ok(expected) = expected.parse::<u16>()
    {
        return status == expected;
    }
    (200..500).contains(&status)
}

fn sanitize_probe_event(event: Value) -> String {
    event
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned()
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
    let mut event = json!({
            "event": "tcp_worker_started",
            "proxy_count": router.proxy_count(),
            "dial_mode": router.dial_mode_name(),
            "legacy_flow_stack_bytes": flow_stack_bytes,
    });
    append_tcp_execution_fields(&mut event, "async-accept-direct");
    event["legacyProxyExecution"] = json!("async-proxy-tls");
    event["proxyExecutionDescriptor"] = tcp_execution_descriptor("async-proxy-tls").to_value();
    append_event(&event_file, &event_lock, event);
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
            });
            append_tcp_execution_fields(&mut event, "async-block");
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
                    append_tcp_execution_fields(&mut event, "per-connection-thread-transitional");
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
    let mut event = json!({
            "event": "tcp_worker_started",
            "proxy_count": router.proxy_count(),
            "dial_mode": router.dial_mode_name(),
            "flow_stack_bytes": flow_stack_bytes,
    });
    append_tcp_execution_fields(&mut event, "per-connection-thread-legacy");
    append_event(&event_file, &event_lock, event);
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
        proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "per-connection-thread-legacy",
        )
    })
    .or_else(|err| {
        Ok::<Value, String>(proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "per-connection-thread-legacy",
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
    if selection.proxy.net == "websocket" {
        return handle_vless_websocket_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    if selection.proxy.net == "httpupgrade" {
        return handle_vless_httpupgrade_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    if selection.proxy.net == "grpc" {
        return handle_vless_grpc_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    if selection.proxy.net == "meek" {
        return handle_vless_meek_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    if selection.proxy.net == "xhttp" {
        return handle_vless_xhttp_h2_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
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
        let event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "async-proxy-tls",
        );
        event
    })
    .or_else(|err| {
        let event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "async-proxy-tls",
        );
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_vless_websocket_tcp_connection_async(
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
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &sniff.payload,
    )
    .map_err(|err| format!("build VLESS WebSocket TCP request: {err}"))?;
    write_websocket_binary_frame_over_resident_tls_async(
        &mut client,
        &request,
        "write VLESS websocket request",
    )
    .await?;
    if !sniff.payload.is_empty() {
        metrics.add_upload(sniff.payload.len());
    }
    relay_tcp_over_vless_websocket_tls_async(
        inbound,
        &mut client,
        stop,
        sniff.payload.len(),
        metrics,
    )
    .await
    .map(|stats| {
        let mut event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "async-proxy-websocket-tls",
        );
        event["stream_wrapper"] = json!("websocket");
        event
    })
    .or_else(|err| {
        let mut event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "async-proxy-websocket-tls",
        );
        event["stream_wrapper"] = json!("websocket");
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_vless_httpupgrade_tcp_connection_async(
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
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_resident_tls_async(&mut client, &options).await?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS HTTP Upgrade TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write VLESS HTTP Upgrade TCP request")
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
        let mut event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "async-proxy-httpupgrade-tls",
        );
        event["stream_wrapper"] = json!("httpupgrade");
        event
    })
    .or_else(|err| {
        let mut event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "async-proxy-httpupgrade-tls",
        );
        event["stream_wrapper"] = json!("httpupgrade");
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_vless_meek_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let tls_underlay = if selection.proxy.utls_fingerprint.is_some() {
        "boringssl"
    } else {
        "rustls"
    };
    let key = selection.proxy.vless_key()?;
    let options = meek_options_from_proxy(&selection, peer, original_dst);
    let first_payload = packet::first_write_bytes(
        &key,
        "",
        "tcp",
        &selection.route.dial_target,
        false,
        &sniff.payload,
    )
    .map_err(|err| format!("build VLESS Meek TCP request: {err}"))?;
    let mut stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }
    let mut stripper = VlessResponseStripper::default();
    let mut next_body = Some(first_payload);
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut empty_poll_count = 0_usize;

    while !stop.load(Ordering::Relaxed) {
        let body = if let Some(body) = next_body.take() {
            body
        } else {
            let mut buf = [0_u8; 16 * 1024];
            match time::timeout(Duration::from_millis(150), inbound.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    inbound_closed = true;
                    Vec::new()
                }
                Ok(Ok(read)) => {
                    stats.client_to_direct += read;
                    metrics.add_upload(read);
                    last_activity = Instant::now();
                    empty_poll_count = 0;
                    buf[..read].to_vec()
                }
                Ok(Err(err)) if is_graceful_stream_close_error(&err) => {
                    inbound_closed = true;
                    Vec::new()
                }
                Ok(Err(err)) => return Err(format!("read inbound TCP for Meek relay: {err}")),
                Err(_) => Vec::new(),
            }
        };

        if body.is_empty() {
            empty_poll_count = empty_poll_count.saturating_add(1);
        }
        let response = meek_round_trip_async(&selection.proxy, &options, &body).await?;
        let response_payload = stripper.consume(&response)?;
        if !response_payload.is_empty() {
            inbound
                .write_all(&response_payload)
                .await
                .map_err(|err| format!("write Meek response payload to client: {err}"))?;
            stats.direct_to_client += response_payload.len();
            metrics.add_download(response_payload.len());
            last_activity = Instant::now();
            empty_poll_count = 0;
        }
        if inbound_closed && response_payload.is_empty() {
            break;
        }
        if empty_poll_count >= 3 && last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
            break;
        }
    }

    let mut event = generic_proxy_tcp_finished_event(
        peer,
        original_dst,
        &selection,
        sniff,
        "vless",
        &stats,
        "async-proxy-meek-tls",
    );
    event["tls_underlay"] = json!(tls_underlay);
    event["stream_wrapper"] = json!("meek");
    event["meek_polling"] = json!(true);
    append_proxy_tcp_execution_fields(
        &mut event,
        "async-proxy-meek-tls",
        "vless",
        Some(tls_underlay),
        None,
    );
    Ok(event)
}

fn meek_options_from_proxy(
    selection: &TcpProxySelection,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
) -> MeekRoundTripOptions {
    MeekRoundTripOptions {
        url: format!(
            "https://{}{}",
            selection.proxy.stream_host, selection.proxy.stream_path
        ),
        host: selection.proxy.stream_host.clone(),
        path: selection.proxy.stream_path.clone(),
        session_tag: format!("{}|{}|{}", selection.proxy.graph_id, peer, original_dst).into_bytes(),
    }
}

async fn meek_round_trip_async(
    proxy: &ResidentProxyPlan,
    options: &MeekRoundTripOptions,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let mut client = open_async_resident_tls_client(proxy).await?;
    let request = meek_http_request(options, body);
    client
        .write_plain_all(&request, "write Meek polling request")
        .await?;
    let response = read_meek_http_response_body_async(&mut client).await;
    client.shutdown().await;
    response
}

async fn read_meek_http_response_body_async(
    client: &mut AsyncResidentTlsClient,
) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    let head_end = loop {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read_plain(&mut buf))
            .await
            .map_err(|_| "read Meek response head timeout".to_owned())?
            .map_err(|err| format!("read Meek response head: {err}"))?;
        if read == 0 {
            return Err("Meek response closed before header".to_owned());
        }
        data.extend_from_slice(&buf[..read]);
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if data.len() > 8192 {
            return Err("Meek response header too large".to_owned());
        }
    };
    let head = data[..head_end].to_vec();
    validate_http_status(&head, 200).map_err(|err| format!("validate Meek response: {err}"))?;
    let content_length = http_content_length(&head)?;
    let mut body = data[head_end..].to_vec();
    while body.len() < content_length {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read_plain(&mut buf))
            .await
            .map_err(|_| "read Meek response body timeout".to_owned())?
            .map_err(|err| format!("read Meek response body: {err}"))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read]);
    }
    body.truncate(content_length);
    Ok(body)
}

fn http_content_length(head: &[u8]) -> Result<usize, String> {
    let text =
        std::str::from_utf8(head).map_err(|err| format!("Meek response head utf8: {err}"))?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map_err(|err| format!("parse Meek response Content-Length: {err}"));
        }
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
async fn handle_vless_grpc_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let client = open_async_vless_tls_client(&selection.proxy).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &sniff.payload,
    )
    .map_err(|err| format!("build VLESS gRPC TCP request: {err}"))?;
    let (mut h2_send, mut h2_recv, connection_task) =
        open_grpc_h2_stream(client, &selection.proxy, &request).await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    let result = relay_tcp_over_grpc_h2(
        inbound,
        &mut h2_send,
        &mut h2_recv,
        stop,
        initial_stats,
        metrics,
        true,
    )
    .await;
    connection_task.abort();
    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &stats,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "vless",
                Some(tls_underlay),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &err,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "vless",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
async fn handle_vless_xhttp_h2_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let client = open_async_vless_tls_client(&selection.proxy).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let session_id = new_xhttp_session_id();
    let (mut h2_send, mut h2_recv, connection_task) =
        open_xhttp_h2_packet_up_session(client, &selection.proxy, &session_id).await?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &sniff.payload,
    )
    .map_err(|err| format!("build VLESS xHTTP TCP request: {err}"))?;

    let mut initial_stats = DirectTcpRelayStats::default();
    initial_stats.client_to_direct += sniff.payload.len();
    if !sniff.payload.is_empty() {
        metrics.add_upload(sniff.payload.len());
    }
    let result = async {
        let mut seq = 0_u64;
        send_xhttp_h2_packet_up_request(
            &mut h2_send,
            &selection.proxy,
            &session_id,
            seq,
            Bytes::from(request),
        )
        .await?;
        seq = seq.saturating_add(1);
        relay_tcp_over_xhttp_h2_packet_up(
            inbound,
            &mut h2_send,
            &mut h2_recv,
            &selection.proxy,
            &session_id,
            seq,
            stop,
            initial_stats,
            metrics,
        )
        .await
    }
    .await;
    connection_task.abort();

    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &stats,
                "async-proxy-xhttp-h2-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("xhttp");
            event["xhttp_mode"] = json!("packet-up");
            event["xhttp_alpn"] = json!("h2");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-xhttp-h2-tls",
                "vless",
                Some(tls_underlay),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &err,
                "async-proxy-xhttp-h2-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("xhttp");
            event["xhttp_mode"] = json!("packet-up");
            event["xhttp_alpn"] = json!("h2");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-xhttp-h2-tls",
                "vless",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

async fn handle_first_batch_proxy_tcp_connection_async(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Value, String> {
    if let ResidentProxyProtocolPlan::VmessAeadTcp { id } = &selection.proxy.handler
        && selection.proxy.net == "grpc"
    {
        let id = id.clone();
        return handle_vmess_grpc_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &id,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::HttpProxyTcp { username, password } = &selection.proxy.handler
        && selection.proxy.tls == "tls"
    {
        let username = username.clone();
        let password = password.clone();
        return handle_https_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &username,
            &password,
        )
        .await;
    }
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
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
            cipher,
            password,
            salt_len,
            host,
            path,
        } => handle_shadowsocks_simple_obfs_http_proxy_tcp_connection(
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
            host,
            path,
        ),
        ResidentProxyProtocolPlan::VmessAeadTcp { id } => {
            if selection.proxy.net == "websocket" {
                handle_vmess_websocket_proxy_tcp_connection(
                    inbound,
                    peer,
                    original_dst,
                    &selection,
                    stop,
                    sniff,
                    metrics,
                    id,
                )
            } else if selection.proxy.net == "httpupgrade" {
                handle_vmess_httpupgrade_proxy_tcp_connection(
                    inbound,
                    peer,
                    original_dst,
                    &selection,
                    stop,
                    sniff,
                    metrics,
                    id,
                )
            } else if selection.proxy.net == "grpc" {
                Err(
                    "first-batch VMess gRPC handler must use async TLS HTTP/2 dispatcher"
                        .to_owned(),
                )
            } else {
                handle_vmess_proxy_tcp_connection(
                    inbound,
                    peer,
                    original_dst,
                    &selection,
                    stop,
                    sniff,
                    metrics,
                    id,
                )
            }
        }
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
            if selection.proxy.net == "websocket" {
                handle_trojan_websocket_tls_tcp_connection_async(
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
            } else if selection.proxy.net == "httpupgrade" {
                handle_trojan_httpupgrade_tls_tcp_connection_async(
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
            } else if selection.proxy.net == "grpc" {
                handle_trojan_grpc_tls_tcp_connection_async(
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
            } else {
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
async fn handle_trojan_websocket_tls_tcp_connection_async(
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
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let request = trojan_packet::tcp_request_header(
        password,
        "tcp",
        &selection.route.dial_target,
        &sniff.payload,
    )
    .map_err(|err| format!("build Trojan WebSocket TCP request: {err}"))?;
    write_websocket_binary_frame_over_resident_tls_async(
        &mut client,
        &request,
        "write Trojan websocket request",
    )
    .await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    match relay_tcp_over_trojan_websocket_tls_async(inbound, &mut client, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_stats.client_to_direct;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &stats,
                "async-proxy-websocket-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("websocket");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-websocket-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
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
                "async-proxy-websocket-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("websocket");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-websocket-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_trojan_httpupgrade_tls_tcp_connection_async(
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
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_resident_tls_async(&mut client, &options).await?;
    let request = trojan_packet::tcp_request_header(
        password,
        "tcp",
        &selection.route.dial_target,
        &sniff.payload,
    )
    .map_err(|err| format!("build Trojan HTTP Upgrade TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write Trojan HTTP Upgrade TCP request")
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
                "async-proxy-httpupgrade-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("httpupgrade");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-httpupgrade-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
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
                "async-proxy-httpupgrade-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("httpupgrade");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-httpupgrade-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_trojan_grpc_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    password: &str,
) -> Result<Value, String> {
    let client = open_async_resident_tls_client(&selection.proxy).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let request = trojan_packet::tcp_request_header(
        password,
        "tcp",
        &selection.route.dial_target,
        &sniff.payload,
    )
    .map_err(|err| format!("build Trojan gRPC TCP request: {err}"))?;
    let (mut h2_send, mut h2_recv, connection_task) =
        open_grpc_h2_stream(client, &selection.proxy, &request).await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    let result = relay_tcp_over_grpc_h2(
        inbound,
        &mut h2_send,
        &mut h2_recv,
        stop,
        initial_stats,
        metrics,
        false,
    )
    .await;
    connection_task.abort();
    match result {
        Ok(stats) => {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "trojan",
                &stats,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
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
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
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
                "async-proxy-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
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
                "async-proxy-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-tls",
                "trojan",
                Some(tls_underlay),
                None,
            );
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
                "async-proxy-frame-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-frame-tls",
                "anytls",
                Some(tls_underlay),
                None,
            );
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
                "async-proxy-frame-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-frame-tls",
                "anytls",
                Some(tls_underlay),
                None,
            );
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
    let mut inbound_close_started = None;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        if inbound_close_started.is_none() {
                            inbound_close_started = Some(Instant::now());
                        }
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
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        if inbound_close_started.is_none() {
                            inbound_close_started = Some(Instant::now());
                        }
                        let _ = write_anytls_frame(
                            client,
                            anytls_contract::CMD_FIN,
                            sid,
                            &[],
                            "write AnyTLS FIN after client close",
                        )
                        .await;
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
                            if let Err(err) = inbound.write_all(&frame.data).await {
                                if is_graceful_stream_close_error(&err) {
                                    break;
                                }
                                return Err(format!("write AnyTLS payload to client: {err}"));
                            }
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
                if let Some(started) = inbound_close_started
                    && started.elapsed() >= ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT
                {
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
        let mut event = generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "hysteria2",
            &format!("Hysteria2 auth status {}", auth_report.status),
            "async-proxy-quic-tcp",
        );
        event["quic_underlay"] = json!("quinn-h3");
        append_proxy_tcp_execution_fields(
            &mut event,
            "async-proxy-quic-tcp",
            "hysteria2",
            None,
            Some("quinn-h3"),
        );
        return Ok(event);
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
        let mut event = generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "hysteria2",
            &format!("Hysteria2 TCP response rejected: {}", response.message),
            "async-proxy-quic-tcp",
        );
        event["quic_underlay"] = json!("quinn-h3");
        append_proxy_tcp_execution_fields(
            &mut event,
            "async-proxy-quic-tcp",
            "hysteria2",
            None,
            Some("quinn-h3"),
        );
        return Ok(event);
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
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn-h3");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "hysteria2",
                None,
                Some("quinn-h3"),
            );
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
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn-h3");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "hysteria2",
                None,
                Some("quinn-h3"),
            );
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
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "tuic",
                None,
                Some("quinn"),
            );
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
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "tuic",
                None,
                Some("quinn"),
            );
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
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn-h3");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "juicity",
                None,
                Some("quinn-h3"),
            );
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
                "async-proxy-quic-tcp",
            );
            event["quic_underlay"] = json!("quinn-h3");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-quic-tcp",
                "juicity",
                None,
                Some("quinn-h3"),
            );
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
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = send.finish();
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
                        if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                            if is_graceful_stream_close_error(&err) {
                                break;
                            }
                            return Err(format!("write QUIC stream payload to client: {err}"));
                        }
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

pub(super) fn open_marked_quic_endpoint(mark: u32) -> Result<quinn::Endpoint, String> {
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

pub(super) fn resolve_proxy_udp_addr(proxy: &ResidentProxyPlan) -> Result<SocketAddr, String> {
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
    target
        .to_socket_addrs()
        .map_err(|err| format!("resolve QUIC endpoint {target}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve QUIC endpoint {target}: no address"))
}

pub(super) fn set_socket_mark(fd: i32, mark: u32) -> std::io::Result<()> {
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
                "first-batch-tcp",
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
                "first-batch-tcp",
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
                "first-batch-tcp",
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
                "first-batch-tcp",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
async fn handle_https_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    username: &str,
    password: &str,
) -> Result<Value, String> {
    let mut proxy = open_async_resident_tls_client(&selection.proxy).await?;
    let tls_underlay = async_resident_tls_underlay_name(&proxy);
    http_proxy_connect_async(&mut proxy, &selection.route.dial_target, username, password).await?;
    if !sniff.payload.is_empty() {
        proxy
            .write_plain_all(&sniff.payload, "write HTTPS proxy initial payload")
            .await?;
        metrics.add_upload(sniff.payload.len());
    }
    relay_tcp_over_resident_tls_plain_async(inbound, &mut proxy, stop, metrics)
        .await
        .map(|mut stats| {
            stats.client_to_direct += sniff.payload.len();
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "http-proxy",
                &stats,
                "async-secure-endpoint-connect",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["secure_endpoint"] = json!(true);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-secure-endpoint-connect",
                "http-proxy",
                Some(tls_underlay),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "http-proxy",
                &err,
                "async-secure-endpoint-connect",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["secure_endpoint"] = json!(true);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-secure-endpoint-connect",
                "http-proxy",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

async fn http_proxy_connect_async(
    stream: &mut AsyncResidentTlsClient,
    target: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    let mut options = HttpConnectOptions::connect(target);
    options.username = username.to_owned();
    options.password = password.to_owned();
    let request = http_request::connect_request(&options);
    stream
        .write_plain_all(&request, "write HTTPS proxy CONNECT request")
        .await?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.read_plain(&mut buf))
            .await
            .map_err(|_| "read HTTPS proxy CONNECT response timeout".to_owned())?
            .map_err(|err| format!("read HTTPS proxy CONNECT response: {err}"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err("HTTPS proxy CONNECT response too large".to_owned());
        }
    }
    let status = http_request::parse_connect_response(&response)
        .map_err(|err| format!("parse HTTPS proxy CONNECT response: {err}"))?;
    if status != 200 {
        return Err(format!("HTTPS proxy CONNECT status: {status}"));
    }
    Ok(())
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
                "first-batch-tcp",
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
                "first-batch-tcp",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
fn handle_shadowsocks_simple_obfs_http_proxy_tcp_connection(
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
    host: &str,
    path: &str,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
    proxy
        .set_nonblocking(false)
        .map_err(|err| format!("set Shadowsocks simple-obfs proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs inbound write timeout: {err}"))?;
    let stats = relay_tcp_over_shadowsocks_simple_obfs_http(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        &sniff.payload,
        metrics,
        host,
        path,
    );
    stats
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "shadowsocks",
                &stats,
                "first-batch-tcp",
            );
            event["plugin_wrapper"] = json!("simple-obfs-http");
            append_proxy_tcp_execution_fields(
                &mut event,
                "first-batch-tcp",
                "shadowsocks",
                Some("aead"),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "shadowsocks",
                &err,
                "first-batch-tcp",
            );
            event["plugin_wrapper"] = json!("simple-obfs-http");
            append_proxy_tcp_execution_fields(
                &mut event,
                "first-batch-tcp",
                "shadowsocks",
                Some("aead"),
                None,
            );
            Ok::<Value, String>(event)
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
                "first-batch-aead-tcp",
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
                "first-batch-aead-tcp",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
fn handle_vmess_websocket_proxy_tcp_connection(
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
        .map_err(|err| format!("set VMess WebSocket proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess WebSocket proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess WebSocket proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess WebSocket inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess WebSocket inbound write timeout: {err}"))?;

    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_plain_stream(&mut proxy, &options)?;
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess WebSocket AEAD TCP session: {err}"))?;
    write_websocket_binary_frame_to_stream(
        &mut proxy,
        &session.first_write,
        "write VMess websocket request",
    )?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_websocket_aead(inbound, &mut proxy, stop, session, initial_stats, metrics)
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "vmess",
                &stats,
                "first-batch-websocket-aead",
            );
            event["stream_wrapper"] = json!("websocket");
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "vmess",
                &err,
                "first-batch-websocket-aead",
            );
            event["stream_wrapper"] = json!("websocket");
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
fn handle_vmess_httpupgrade_proxy_tcp_connection(
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
        .map_err(|err| format!("set VMess HTTP Upgrade proxy blocking: {err}"))?;
    proxy
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess HTTP Upgrade proxy read timeout: {err}"))?;
    proxy
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess HTTP Upgrade proxy write timeout: {err}"))?;
    inbound
        .set_read_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess HTTP Upgrade inbound read timeout: {err}"))?;
    inbound
        .set_write_timeout(Some(RESIDENT_TCP_IDLE_TIMEOUT))
        .map_err(|err| format!("set VMess HTTP Upgrade inbound write timeout: {err}"))?;

    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_plain_stream(&mut proxy, &options)?;
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess HTTP Upgrade AEAD TCP session: {err}"))?;
    proxy
        .write_all(&session.first_write)
        .map_err(|err| format!("write VMess HTTP Upgrade request: {err}"))?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    relay_tcp_over_vmess_aead(inbound, &mut proxy, stop, session, initial_stats, metrics)
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                selection,
                sniff,
                "vmess",
                &stats,
                "first-batch-httpupgrade-aead",
            );
            event["stream_wrapper"] = json!("httpupgrade");
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                selection,
                sniff,
                "vmess",
                &err,
                "first-batch-httpupgrade-aead",
            );
            event["stream_wrapper"] = json!("httpupgrade");
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
async fn handle_vmess_grpc_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    id: &str,
) -> Result<Value, String> {
    let client = open_async_resident_tls_client(&selection.proxy).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let session = aead_tcp_client_session_start(id, &selection.route.dial_target, &sniff.payload)
        .map_err(|err| format!("build VMess gRPC AEAD TCP session: {err}"))?;
    let (mut h2_send, mut h2_recv, connection_task) =
        open_grpc_h2_stream(client, &selection.proxy, &session.first_write).await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    let result = relay_tcp_over_vmess_grpc_h2(
        inbound,
        &mut h2_send,
        &mut h2_recv,
        stop,
        session,
        initial_stats,
        metrics,
    )
    .await;
    connection_task.abort();
    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &stats,
                "first-batch-grpc-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "first-batch-grpc-aead",
                "vmess",
                Some(tls_underlay),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vmess",
                &err,
                "first-batch-grpc-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "first-batch-grpc-aead",
                "vmess",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

async fn open_grpc_h2_stream(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    first_payload: &[u8],
) -> Result<
    (
        h2::SendStream<Bytes>,
        h2::RecvStream,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let (mut sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| "gRPC HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("gRPC HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let authority = grpc_authority(proxy);
    let uri = format!(
        "https://{}{}",
        authority,
        grpc_request_path(&proxy.stream_path)
    );
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .header(http::header::USER_AGENT, "dae-rust-native-resident")
        .body(())
        .map_err(|err| format!("build gRPC HTTP/2 request: {err}"))?;
    let (response, send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send gRPC HTTP/2 request headers: {err}"))?;
    let mut send_stream = send_stream;
    send_grpc_hunk(&mut send_stream, first_payload, false).await?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "gRPC HTTP/2 response headers timeout".to_owned())?
        .map_err(|err| format!("read gRPC HTTP/2 response headers: {err}"))?;
    if !response.status().is_success() {
        connection_task.abort();
        return Err(format!("gRPC HTTP/2 response status {}", response.status()));
    }
    Ok((send_stream, response.into_body(), connection_task))
}

fn grpc_authority(proxy: &ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

fn grpc_request_path(service_name: &str) -> String {
    let service_name = if service_name.is_empty() {
        "GunService"
    } else {
        service_name.trim_start_matches('/')
    };
    format!("/{service_name}/Tun")
}

async fn open_xhttp_h2_packet_up_session(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    session_id: &str,
) -> Result<
    (
        h2::client::SendRequest<Bytes>,
        h2::RecvStream,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let (mut sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| "xHTTP HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("xHTTP HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = xhttp_h2_request(
        http::Method::GET,
        proxy,
        &xhttp_session_path_suffix(session_id, None),
        false,
    )?;
    let (response, _send_stream) = sender
        .send_request(request, true)
        .map_err(|err| format!("send xHTTP HTTP/2 download request headers: {err}"))?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "xHTTP HTTP/2 download response headers timeout".to_owned())?
        .map_err(|err| format!("read xHTTP HTTP/2 download response headers: {err}"))?;
    if !response.status().is_success() {
        connection_task.abort();
        return Err(format!(
            "xHTTP HTTP/2 download response status {}",
            response.status()
        ));
    }
    Ok((sender, response.into_body(), connection_task))
}

async fn send_xhttp_h2_packet_up_request(
    sender: &mut h2::client::SendRequest<Bytes>,
    proxy: &ResidentProxyPlan,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    let request = xhttp_h2_request(
        http::Method::POST,
        proxy,
        &xhttp_session_path_suffix(session_id, Some(seq)),
        true,
    )?;
    let (response, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send xHTTP HTTP/2 packet-up request headers: {err}"))?;
    send_h2_data_with_context(&mut send_stream, payload, true, "xHTTP HTTP/2 packet-up").await?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "xHTTP HTTP/2 packet-up response headers timeout".to_owned())?
        .map_err(|err| format!("read xHTTP HTTP/2 packet-up response headers: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "xHTTP HTTP/2 packet-up response status {}",
            response.status()
        ));
    }
    drain_xhttp_h2_response_body(response.into_body()).await
}

fn xhttp_h2_request(
    method: http::Method,
    proxy: &ResidentProxyPlan,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let uri = xhttp_uri(proxy, path_suffix);
    let referer = xhttp_padding_referer(&xhttp_uri(proxy, ""));
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::USER_AGENT, "Mozilla/5.0")
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .header("pragma", "no-cache")
        .header(http::header::REFERER, referer);
    if has_body {
        builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP HTTP/2 request: {err}"))
}

fn xhttp_uri(proxy: &ResidentProxyPlan, path_suffix: &str) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(&proxy.stream_path);
    let mut path = normalized.path;
    path.push_str(path_suffix);
    let mut uri = format!("https://{}{}", xhttp_authority(proxy), path);
    if !normalized.query.is_empty() {
        uri.push('?');
        uri.push_str(&normalized.query);
    }
    uri
}

fn xhttp_padding_referer(base_uri: &str) -> String {
    const DEFAULT_PADDING_LEN: usize = 128;
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    format!(
        "{base_without_query}?x_padding={}",
        "X".repeat(DEFAULT_PADDING_LEN)
    )
}

fn xhttp_authority(proxy: &ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

fn xhttp_session_path_suffix(session_id: &str, seq: Option<u64>) -> String {
    match seq {
        Some(seq) => format!("{session_id}/{seq}"),
        None => session_id.to_owned(),
    }
}

fn new_xhttp_session_id() -> String {
    let high = fastrand::u64(..);
    let low = fastrand::u64(..);
    let value = ((high as u128) << 64) | low as u128;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) as u32,
        ((value >> 80) & 0xffff) as u16,
        ((value >> 64) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
        value & 0xffff_ffff_ffff
    )
}

async fn drain_xhttp_h2_response_body(mut body: h2::RecvStream) -> Result<(), String> {
    loop {
        let data = time::timeout(RESIDENT_CONNECT_TIMEOUT, body.data())
            .await
            .map_err(|_| "xHTTP HTTP/2 packet-up response body timeout".to_owned())?;
        let Some(data) = data else {
            return Ok(());
        };
        let bytes =
            data.map_err(|err| format!("read xHTTP HTTP/2 packet-up response body: {err}"))?;
        body.flow_control()
            .release_capacity(bytes.len())
            .map_err(|err| format!("release xHTTP HTTP/2 packet-up response capacity: {err}"))?;
    }
}

async fn send_grpc_hunk(
    send_stream: &mut h2::SendStream<Bytes>,
    payload: &[u8],
    end_stream: bool,
) -> Result<(), String> {
    let hunk = grpc_hunk_frame(payload).map_err(|err| format!("build gRPC hunk: {err}"))?;
    send_h2_data(send_stream, Bytes::from(hunk), end_stream).await
}

async fn send_h2_data(
    send_stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
) -> Result<(), String> {
    send_h2_data_with_context(send_stream, data, end_stream, "gRPC HTTP/2").await
}

async fn send_h2_data_with_context(
    send_stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
    context: &str,
) -> Result<(), String> {
    let required = data.len();
    if required > 0 {
        send_stream.reserve_capacity(required);
        while send_stream.capacity() < required {
            let Some(capacity) = poll_fn(|cx| send_stream.poll_capacity(cx)).await else {
                return Err(format!(
                    "{context} send stream closed before capacity became available"
                ));
            };
            capacity.map_err(|err| format!("reserve {context} send capacity: {err}"))?;
        }
    }
    send_stream
        .send_data(data, end_stream)
        .map_err(|err| format!("send {context} data: {err}"))
}

async fn relay_tcp_over_grpc_h2(
    inbound: &mut TokioTcpStream,
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_buf = Vec::new();
    let mut vless_response_stripper =
        strip_vless_response_header.then(VlessResponseStripper::default);

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_grpc_hunk(send_stream, &inbound_buf[..read], false).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                    }
                    Err(err) => return Err(format!("read inbound TCP for gRPC relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release gRPC HTTP/2 response capacity: {err}"))?;
                        response_buf.extend_from_slice(&bytes);
                        while let Some(payload) = pop_grpc_hunk_payload(&mut response_buf)? {
                            let payload = if let Some(stripper) = vless_response_stripper.as_mut() {
                                stripper.consume(&payload)?
                            } else {
                                payload
                            };
                            if !payload.is_empty() {
                                inbound
                                    .write_all(&payload)
                                    .await
                                    .map_err(|err| format!("write gRPC response to inbound: {err}"))?;
                                stats.direct_to_client += payload.len();
                                metrics.add_download(payload.len());
                            }
                        }
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read gRPC HTTP/2 response data: {err}")),
                    None => {
                        response_closed = true;
                        if !response_buf.is_empty() {
                            return Err("gRPC response stream ended with partial hunk".to_owned());
                        }
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if (inbound_closed && response_closed) || last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    break;
                }
            }
        }
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
async fn relay_tcp_over_xhttp_h2_packet_up(
    inbound: &mut TokioTcpStream,
    sender: &mut h2::client::SendRequest<Bytes>,
    recv_stream: &mut h2::RecvStream,
    proxy: &ResidentProxyPlan,
    session_id: &str,
    mut seq: u64,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_stripper = VlessResponseStripper::default();

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_xhttp_h2_packet_up_request(
                            sender,
                            proxy,
                            session_id,
                            seq,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                        )
                        .await?;
                        seq = seq.saturating_add(1);
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for xHTTP relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release xHTTP HTTP/2 download capacity: {err}"))?;
                        let payload = response_stripper.consume(&bytes)?;
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| format!("write xHTTP response to inbound: {err}"))?;
                            stats.direct_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read xHTTP HTTP/2 download data: {err}")),
                    None => {
                        response_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if response_closed || (inbound_closed && response_closed) {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident xHTTP HTTP/2 relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}

async fn relay_tcp_over_vmess_grpc_h2(
    inbound: &mut TokioTcpStream,
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: Arc<AtomicBool>,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let encrypted_queue = Arc::new(VmessGrpcEncryptedQueue::default());
    let (decrypted_tx, decrypted_rx) = mpsc::channel();
    let request = session.request.clone();
    let decoder_queue = VmessGrpcEncryptedReader::new(Arc::clone(&encrypted_queue));
    let decoder = thread::spawn(move || {
        decode_vmess_grpc_response_stream(decoder_queue, request, decrypted_tx)
    });
    let mut upload_codec = session.upload;
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut decoder_disconnected = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_buf = Vec::new();
    let mut decode_error = None;

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode VMess gRPC upload chunk: {err}"))?;
                        send_grpc_hunk(send_stream, &encrypted, false).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for VMess gRPC relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release VMess gRPC HTTP/2 response capacity: {err}"))?;
                        response_buf.extend_from_slice(&bytes);
                        while let Some(payload) = pop_grpc_hunk_payload(&mut response_buf)? {
                            if !payload.is_empty() {
                                encrypted_queue.push(&payload);
                            }
                        }
                        let (plain_chunks, disconnected) = collect_vmess_grpc_decrypted(
                            &decrypted_rx,
                            &mut decode_error,
                        );
                        decoder_disconnected = disconnected;
                        write_vmess_grpc_decrypted(
                            inbound,
                            &mut stats,
                            metrics,
                            plain_chunks,
                        )
                        .await?;
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read VMess gRPC HTTP/2 response data: {err}")),
                    None => {
                        response_closed = true;
                        encrypted_queue.close();
                        if !response_buf.is_empty() {
                            return Err("VMess gRPC response stream ended with partial hunk".to_owned());
                        }
                        let (plain_chunks, disconnected) = collect_vmess_grpc_decrypted(
                            &decrypted_rx,
                            &mut decode_error,
                        );
                        decoder_disconnected = disconnected;
                        write_vmess_grpc_decrypted(
                            inbound,
                            &mut stats,
                            metrics,
                            plain_chunks,
                        )
                        .await?;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                let (plain_chunks, disconnected) = collect_vmess_grpc_decrypted(
                    &decrypted_rx,
                    &mut decode_error,
                );
                decoder_disconnected = disconnected;
                write_vmess_grpc_decrypted(
                    inbound,
                    &mut stats,
                    metrics,
                    plain_chunks,
                )
                .await?;
                if inbound_closed && response_closed && decoder_disconnected {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    break;
                }
            }
        }

        if let Some(err) = decode_error.take() {
            encrypted_queue.close();
            let _ = decoder.join();
            return Err(err);
        }
        if inbound_closed && response_closed && decoder_disconnected {
            break;
        }
    }
    encrypted_queue.close();
    let decoder_result = decoder
        .join()
        .map_err(|_| "join VMess gRPC response decoder failed".to_owned())?;
    if let Err(err) = decoder_result {
        return Err(err);
    }
    Ok(stats)
}

fn collect_vmess_grpc_decrypted(
    decrypted_rx: &mpsc::Receiver<Result<Vec<u8>, String>>,
    decode_error: &mut Option<String>,
) -> (Vec<Vec<u8>>, bool) {
    let mut chunks = Vec::new();
    loop {
        match decrypted_rx.try_recv() {
            Ok(Ok(plain)) => {
                chunks.push(plain);
            }
            Ok(Err(err)) => {
                *decode_error = Some(err);
                return (chunks, false);
            }
            Err(mpsc::TryRecvError::Empty) => return (chunks, false),
            Err(mpsc::TryRecvError::Disconnected) => return (chunks, true),
        }
    }
}

async fn write_vmess_grpc_decrypted(
    inbound: &mut TokioTcpStream,
    stats: &mut DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    chunks: Vec<Vec<u8>>,
) -> Result<(), String> {
    for plain in chunks {
        if !plain.is_empty() {
            inbound
                .write_all(&plain)
                .await
                .map_err(|err| format!("write VMess gRPC response to inbound: {err}"))?;
            stats.direct_to_client += plain.len();
            metrics.add_download(plain.len());
        }
    }
    Ok(())
}

fn decode_vmess_grpc_response_stream(
    mut reader: VmessGrpcEncryptedReader,
    request: dae_outbound::vmess::VMessAeadTcpRequest,
    decrypted_tx: mpsc::Sender<Result<Vec<u8>, String>>,
) -> Result<(), String> {
    let mut response = match aead_tcp_response_reader_from_stream(&mut reader, &request) {
        Ok(response) => response,
        Err(err) => {
            let message = err.to_string();
            if is_vmess_grpc_graceful_decode_close(&message) {
                return Ok(());
            }
            let _ = decrypted_tx.send(Err(format!(
                "read VMess gRPC AEAD response header: {message}"
            )));
            return Ok(());
        }
    };
    loop {
        match response.read_chunk_from_stream(&mut reader) {
            Ok(plain) => {
                if decrypted_tx.send(Ok(plain)).is_err() {
                    return Ok(());
                }
            }
            Err(err) => {
                let message = err.to_string();
                if is_vmess_grpc_graceful_decode_close(&message) {
                    return Ok(());
                }
                let _ =
                    decrypted_tx.send(Err(format!("read VMess gRPC response chunk: {message}")));
                return Ok(());
            }
        }
    }
}

fn is_vmess_grpc_graceful_decode_close(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("failed to fill whole buffer")
        || message.contains("Connection reset")
        || message.contains("connection reset")
        || message.contains("timed out")
}

#[derive(Default)]
struct VmessGrpcEncryptedQueue {
    inner: Mutex<VmessGrpcEncryptedQueueInner>,
    ready: Condvar,
}

#[derive(Default)]
struct VmessGrpcEncryptedQueueInner {
    bytes: VecDeque<u8>,
    closed: bool,
}

impl VmessGrpcEncryptedQueue {
    fn push(&self, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().expect("VMess gRPC queue poisoned");
        inner.bytes.extend(payload);
        self.ready.notify_all();
    }

    fn close(&self) {
        let mut inner = self.inner.lock().expect("VMess gRPC queue poisoned");
        inner.closed = true;
        self.ready.notify_all();
    }
}

struct VmessGrpcEncryptedReader {
    queue: Arc<VmessGrpcEncryptedQueue>,
}

impl VmessGrpcEncryptedReader {
    fn new(queue: Arc<VmessGrpcEncryptedQueue>) -> Self {
        Self { queue }
    }
}

impl Read for VmessGrpcEncryptedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut inner = self
            .queue
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("VMess gRPC encrypted queue lock poisoned"))?;
        while inner.bytes.is_empty() && !inner.closed {
            inner =
                self.queue.ready.wait(inner).map_err(|_| {
                    std::io::Error::other("VMess gRPC encrypted queue wait poisoned")
                })?;
        }
        if inner.bytes.is_empty() && inner.closed {
            return Ok(0);
        }
        let read = buf.len().min(inner.bytes.len());
        for slot in &mut buf[..read] {
            *slot = inner.bytes.pop_front().expect("queue length checked");
        }
        Ok(read)
    }
}

fn pop_grpc_hunk_payload(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err("compressed gRPC hunk is not admitted by resident relay".to_owned());
    }
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if buffer.len() < 5 + len {
        return Ok(None);
    }
    let payload = grpc_hunk_payload(&buffer[5..5 + len])
        .map_err(|err| format!("decode gRPC Hunk protobuf payload: {err}"))?;
    buffer.drain(..5 + len);
    Ok(Some(payload))
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
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        client.shutdown().await;
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
                        if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                            if is_graceful_stream_close_error(&err) {
                                break;
                            }
                            return Err(format!("write proxy TLS payload to client: {err}"));
                        }
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_tls_plain_close_error(&err) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
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
    if let Some(parent) = proxy.chain_parent.as_deref() {
        return open_plain_proxy_tcp_stream_through_parent(proxy, parent);
    }
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

fn open_plain_proxy_tcp_stream_through_parent(
    proxy: &ResidentProxyPlan,
    parent: &ResidentProxyPlan,
) -> Result<TcpStream, String> {
    let parent_target = format!("{}:{}", parent.server_host, parent.server_port);
    let connection = open_direct_tcp_connection(&parent_target, parent.mark, parent.mptcp)?;
    connection
        .stream
        .set_nonblocking(false)
        .map_err(|err| format!("set parent proxy TCP blocking for chain handshake: {err}"))?;
    connection
        .stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set parent proxy TCP read timeout: {err}"))?;
    connection
        .stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set parent proxy TCP write timeout: {err}"))?;
    let mut stream = connection.stream;
    let child_target = format!("{}:{}", proxy.server_host, proxy.server_port);
    match &parent.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            socks5_connect(&mut stream, &child_target, username, password)?;
        }
        ResidentProxyProtocolPlan::HttpProxyTcp { username, password } if parent.tls == "none" => {
            http_proxy_connect(&mut stream, &child_target, username, password)?;
        }
        _ => {
            return Err(format!(
                "resident chain parent {} is not backed by a plain parent CONNECT executor",
                parent.protocol
            ));
        }
    }
    stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set chained child TCP read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set chained child TCP write timeout: {err}"))?;
    Ok(stream)
}

fn read_http_head_and_leftover_from_stream(
    stream: &mut impl Read,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("read http head: {err}"))?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if let Some(index) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let leftover = response[index + 4..].to_vec();
            response.truncate(index + 4);
            return Ok((response, leftover));
        }
        if response.len() > 8192 {
            return Err("http response header too large".to_owned());
        }
    }
    Err("incomplete http response header".to_owned())
}

struct PrefixTcpReader<'a> {
    prefix: VecDeque<u8>,
    stream: &'a mut TcpStream,
}

impl<'a> PrefixTcpReader<'a> {
    fn new(prefix: Vec<u8>, stream: &'a mut TcpStream) -> Self {
        Self {
            prefix: VecDeque::from(prefix),
            stream,
        }
    }

    fn shutdown_write(&mut self) -> std::io::Result<()> {
        self.stream.shutdown(Shutdown::Write)
    }
}

impl Read for PrefixTcpReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < buf.len() {
            let Some(byte) = self.prefix.pop_front() else {
                break;
            };
            buf[written] = byte;
            written += 1;
        }
        if written > 0 {
            return Ok(written);
        }
        self.stream.read(buf)
    }
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
                Err(err) if is_graceful_stream_close_error(&err) => break,
                Err(err) => return Err(format!("read inbound TCP for Shadowsocks upload: {err}")),
            };
            let encrypted = encoder
                .encrypt_chunk(&buf[..read])
                .map_err(|err| format!("encrypt Shadowsocks upload chunk: {err}"))?;
            if let Err(err) = upload_proxy.write_all(&encrypted) {
                if is_graceful_stream_close_error(&err) {
                    break;
                }
                return Err(format!("write Shadowsocks upload chunk: {err}"));
            }
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

#[allow(clippy::too_many_arguments)]
fn relay_tcp_over_shadowsocks_simple_obfs_http(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
    host: &str,
    path: &str,
) -> Result<DirectTcpRelayStats, String> {
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks simple-obfs target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks simple-obfs target metadata: {err}"))?;
    first_plain.extend_from_slice(initial_payload);
    let mut client_salt = vec![0_u8; salt_len];
    fastrand::fill(&mut client_salt);
    let mut encoder = AeadStreamCodec::new(cipher, password, &client_salt)
        .map_err(|err| format!("create Shadowsocks simple-obfs upload encoder: {err}"))?;
    let mut encrypted_initial = client_salt.clone();
    encrypted_initial.extend(
        encoder
            .encrypt_chunk(&first_plain)
            .map_err(|err| format!("encode Shadowsocks simple-obfs initial frame: {err}"))?,
    );
    let options = Sip003SimpleObfsHttpOptions::new(host, path);
    let obfs_request = simple_obfs_http_request_with_body(&options, &encrypted_initial);
    proxy
        .write_all(&obfs_request)
        .map_err(|err| format!("write Shadowsocks simple-obfs request: {err}"))?;
    let (response_head, response_leftover) = read_http_head_and_leftover_from_stream(proxy)
        .map_err(|err| format!("read Shadowsocks simple-obfs response head: {err}"))?;
    validate_http_status(&response_head, 200)
        .map_err(|err| format!("validate Shadowsocks simple-obfs response status: {err}"))?;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone Shadowsocks simple-obfs stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for Shadowsocks simple-obfs upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs upload read timeout: {err}"))?;
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
                Err(err) if is_graceful_stream_close_error(&err) => break,
                Err(err) => {
                    return Err(format!(
                        "read inbound TCP for Shadowsocks simple-obfs upload: {err}"
                    ));
                }
            };
            let encrypted = encoder
                .encrypt_chunk(&buf[..read])
                .map_err(|err| format!("encrypt Shadowsocks simple-obfs upload chunk: {err}"))?;
            if let Err(err) = upload_proxy.write_all(&encrypted) {
                if is_graceful_stream_close_error(&err) {
                    break;
                }
                return Err(format!("write Shadowsocks simple-obfs upload chunk: {err}"));
            }
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let mut proxy_reader = PrefixTcpReader::new(response_leftover, proxy);
    let mut server_salt = vec![0_u8; salt_len];
    if let Err(err) = proxy_reader.read_exact(&mut server_salt) {
        relay_done.store(true, Ordering::Relaxed);
        let _ = inbound.shutdown(Shutdown::Read);
        let _ = proxy_reader.shutdown_write();
        let _ = upload.join();
        return Err(format!("read Shadowsocks simple-obfs server salt: {err}"));
    }
    let mut decoder = match AeadStreamCodec::new(cipher, password, &server_salt) {
        Ok(decoder) => decoder,
        Err(err) => {
            relay_done.store(true, Ordering::Relaxed);
            let _ = inbound.shutdown(Shutdown::Read);
            let _ = proxy_reader.shutdown_write();
            let _ = upload.join();
            return Err(format!(
                "create Shadowsocks simple-obfs response decoder: {err}"
            ));
        }
    };

    let mut download_error = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match read_encrypted_chunk_from_stream(&mut proxy_reader, &mut decoder) {
            Ok(plain) => {
                if plain.is_empty() {
                    continue;
                }
                inbound
                    .write_all(&plain)
                    .map_err(|err| format!("write Shadowsocks simple-obfs response: {err}"))?;
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
                download_error = Some(format!("read Shadowsocks simple-obfs response: {message}"));
                break;
            }
        }
    }
    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy_reader.shutdown_write();
    let upload_bytes = upload
        .join()
        .map_err(|_| "join Shadowsocks simple-obfs upload relay thread failed".to_owned())??;
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
                Err(err) if is_graceful_stream_close_error(&err) => break,
                Err(err) => return Err(format!("read inbound TCP for VMess upload: {err}")),
            };
            let encrypted = upload_codec
                .seal_chunk(&buf[..read])
                .map_err(|err| format!("encode VMess upload chunk: {err}"))?;
            if let Err(err) = upload_proxy.write_all(&encrypted) {
                if is_graceful_stream_close_error(&err) {
                    break;
                }
                return Err(format!("write VMess upload chunk: {err}"));
            }
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

fn relay_tcp_over_vmess_websocket_aead(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone VMess WebSocket proxy stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for VMess WebSocket upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VMess WebSocket upload read timeout: {err}"))?;
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
                Err(err) if is_graceful_stream_close_error(&err) => break,
                Err(err) => {
                    return Err(format!(
                        "read inbound TCP for VMess WebSocket upload: {err}"
                    ));
                }
            };
            let encrypted = upload_codec
                .seal_chunk(&buf[..read])
                .map_err(|err| format!("encode VMess WebSocket upload chunk: {err}"))?;
            write_websocket_binary_frame_to_stream(
                &mut upload_proxy,
                &encrypted,
                "write VMess websocket upload frame",
            )?;
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let download_result = {
        let mut ws_reader = WebSocketPayloadReader::new(proxy);
        let mut response =
            aead_tcp_response_reader_from_stream(&mut ws_reader, &session.request)
                .map_err(|err| format!("read VMess WebSocket AEAD response header: {err}"))?;
        let _response_header_len = response.response_header_len;

        let mut download_error = None;
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match response.read_chunk_from_stream(&mut ws_reader) {
                Ok(plain) => {
                    if plain.is_empty() {
                        continue;
                    }
                    inbound.write_all(&plain).map_err(|err| {
                        format!("write VMess WebSocket response to inbound: {err}")
                    })?;
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
                    download_error =
                        Some(format!("read VMess WebSocket response chunk: {message}"));
                    break;
                }
            }
        }
        if let Some(err) = download_error {
            Err(err)
        } else {
            Ok(())
        }
    };

    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy.shutdown(Shutdown::Write);
    let upload_bytes = upload
        .join()
        .map_err(|_| "join VMess WebSocket upload relay thread failed".to_owned())??;
    download_result?;
    if upload_bytes > 0 {
        stats.client_to_direct += upload_bytes;
        metrics.add_upload(upload_bytes);
    }
    Ok(stats)
}

fn is_graceful_stream_close_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
    )
}

fn is_graceful_stream_close_message(message: &str) -> bool {
    message.contains("Broken pipe")
        || message.contains("Connection reset")
        || message.contains("Connection aborted")
        || message.contains("Not connected")
        || message.contains("broken pipe")
        || message.contains("connection reset")
        || message.contains("connection aborted")
        || message.contains("not connected")
}

fn is_graceful_tls_plain_close_error(err: &std::io::Error) -> bool {
    if is_graceful_stream_close_error(err) {
        return true;
    }
    let message = err.to_string();
    is_graceful_stream_close_message(&message)
        || message.contains("peer closed connection without sending TLS close_notify")
        || message.contains("without sending TLS close_notify")
}

fn append_tcp_execution_fields(event: &mut Value, execution: &str) {
    append_runtime_execution_descriptor(event, tcp_execution_descriptor(execution));
}

fn append_proxy_tcp_execution_fields(
    event: &mut Value,
    execution: &str,
    handler: &str,
    tls_underlay: Option<&str>,
    quic_underlay: Option<&str>,
) {
    let mut descriptor = tcp_execution_descriptor(execution).with_protocol_framing(handler);
    let graph_id = event
        .get("graphId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(graph_id) = graph_id.as_deref() {
        descriptor = descriptor.with_graph_id(graph_id);
    }
    if let Some(tls_underlay) = tls_underlay {
        descriptor = descriptor.with_security_underlay(tls_underlay);
    }
    if let Some(quic_underlay) = quic_underlay {
        descriptor = descriptor.with_transport_underlay(quic_underlay);
    }
    append_runtime_execution_descriptor(event, descriptor);
}

fn proxy_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    sniff: &TcpSniffReport,
    tls_underlay: &'static str,
    stats: &RelayStats,
    execution: &'static str,
) -> Value {
    let mut event = proxy_tcp_base_event(
        "tcp_connection_finished",
        peer,
        original_dst,
        selection,
        sniff,
    );
    event["tls_underlay"] = json!(tls_underlay);
    event["resident_protocol_handler"] = json!("vless");
    append_proxy_tcp_execution_fields(&mut event, execution, "vless", Some(tls_underlay), None);
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
    execution: &'static str,
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
    event["resident_protocol_handler"] = json!("vless");
    append_proxy_tcp_execution_fields(&mut event, execution, "vless", Some(tls_underlay), None);
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
    append_proxy_tcp_execution_fields(&mut event, execution, handler, None, None);
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
    append_proxy_tcp_execution_fields(&mut event, execution, handler, None, None);
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
        "graphId": &selection.proxy.graph_id,
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
        "async-direct",
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
    });
    append_tcp_execution_fields(&mut event, execution);
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
                Err(err) if is_graceful_stream_close_error(&err) => {
                    inbound_closed = true;
                    client.send_close_notify();
                    progressed = true;
                }
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
                    match write_all_nonblocking(
                        inbound,
                        &proxy_buf[..read],
                        stop,
                        "write VLESS Vision direct payload to client",
                    ) {
                        Ok(()) => {}
                        Err(err) if is_graceful_stream_close_message(&err) => break,
                        Err(err) => return Err(RelayError::new(err, &stats)),
                    }
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
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        client.shutdown().await;
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
                            if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                                if is_graceful_stream_close_error(&err) {
                                    break;
                                }
                                return Err(RelayError::new(
                                    format!("write VLESS Vision direct payload to client: {err}"),
                                    &stats,
                                ));
                            }
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

async fn websocket_handshake_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    options: &HttpUpgradeOptions,
) -> Result<(), String> {
    let request = websocket_handshake_request(options, DEFAULT_WS_KEY);
    client
        .write_plain_all(&request, "write websocket handshake")
        .await?;
    let response =
        read_http_head_over_resident_tls_async(client, "read websocket handshake").await?;
    validate_http_status(&response, 101).map_err(|err| format!("validate websocket upgrade: {err}"))
}

async fn httpupgrade_handshake_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    options: &HttpUpgradeOptions,
) -> Result<(), String> {
    let request = http_upgrade_request(options);
    client
        .write_plain_all(&request, "write HTTP Upgrade handshake")
        .await?;
    let response =
        read_http_head_over_resident_tls_async(client, "read HTTP Upgrade handshake").await?;
    validate_http_status(&response, 101).map_err(|err| format!("validate HTTP Upgrade: {err}"))
}

fn websocket_handshake_over_plain_stream(
    stream: &mut TcpStream,
    options: &HttpUpgradeOptions,
) -> Result<(), String> {
    let request = websocket_handshake_request(options, DEFAULT_WS_KEY);
    stream
        .write_all(&request)
        .map_err(|err| format!("write websocket handshake: {err}"))?;
    let response =
        read_http_head(stream).map_err(|err| format!("read websocket handshake: {err}"))?;
    validate_http_status(&response, 101).map_err(|err| format!("validate websocket upgrade: {err}"))
}

fn httpupgrade_handshake_over_plain_stream(
    stream: &mut TcpStream,
    options: &HttpUpgradeOptions,
) -> Result<(), String> {
    let request = http_upgrade_request(options);
    stream
        .write_all(&request)
        .map_err(|err| format!("write HTTP Upgrade handshake: {err}"))?;
    let response =
        read_http_head(stream).map_err(|err| format!("read HTTP Upgrade handshake: {err}"))?;
    validate_http_status(&response, 101).map_err(|err| format!("validate HTTP Upgrade: {err}"))
}

fn write_websocket_binary_frame_to_stream(
    stream: &mut TcpStream,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    let frame = websocket_client_binary_frame(payload, WS_MASK_KEY)
        .map_err(|err| format!("{label}: {err}"))?;
    stream
        .write_all(&frame)
        .map_err(|err| format!("{label}: {err}"))
}

async fn read_http_head_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read_plain(&mut buf))
            .await
            .map_err(|_| format!("{label}: timeout"))?
            .map_err(|err| format!("{label}: {err}"))?;
        if read == 0 {
            return Err(format!("{label}: early eof"));
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(response);
        }
        if response.len() > 16 * 1024 {
            return Err(format!("{label}: response head too large"));
        }
    }
}

async fn write_websocket_binary_frame_over_resident_tls_async(
    client: &mut AsyncVlessTlsClient,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    let frame = websocket_client_binary_frame(payload, WS_MASK_KEY)
        .map_err(|err| format!("{label}: {err}"))?;
    client.write_plain_all(&frame, label).await
}

async fn relay_tcp_over_vless_websocket_tls_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncVlessTlsClient,
    stop: Arc<AtomicBool>,
    initial_payload_len: usize,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let mut ws_decoder = WebSocketBinaryFrameDecoder::default();
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

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
                        write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &inbound_buf[..read],
                            "write client payload websocket frame",
                        )
                        .await
                        .map_err(|err| RelayError::new(err, &stats))?;
                        stats.client_to_proxy += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read inbound TCP: {err}"), &stats));
                    }
                }
            }
            proxy_read = client.read_plain(&mut proxy_buf) => {
                match proxy_read {
                    Ok(0) => break,
                    Ok(read) => {
                        let frames = ws_decoder
                            .push(&proxy_buf[..read])
                            .map_err(|err| RelayError::new(err, &stats))?;
                        for frame in frames {
                            let payload = stripper
                                .consume(&frame)
                                .map_err(|err| RelayError::new(err, &stats))?;
                            stats.response_header_stripped = stripper.done;
                            if !payload.is_empty() {
                                inbound
                                    .write_all(&payload)
                                    .await
                                    .map_err(|err| RelayError::new(format!("write VLESS websocket payload to client: {err}"), &stats))?;
                                stats.proxy_to_client += payload.len();
                                metrics.add_download(payload.len());
                            }
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read websocket TLS plaintext: {err}"), &stats));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err(RelayError::new("resident websocket relay idle timeout", &stats));
                }
            }
        }
    }
    stats.client_to_proxy += initial_payload_len;
    Ok(stats)
}

async fn relay_tcp_over_trojan_websocket_tls_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut ws_decoder = WebSocketBinaryFrameDecoder::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &inbound_buf[..read],
                            "write client payload websocket frame",
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for Trojan websocket relay: {err}")),
                }
            }
            proxy_read = client.read_plain(&mut proxy_buf), if !proxy_closed => {
                match proxy_read {
                    Ok(0) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let frames = ws_decoder
                            .push(&proxy_buf[..read])
                            .map_err(|err| format!("decode Trojan websocket frame: {err}"))?;
                        for payload in frames {
                            if !payload.is_empty() {
                                if let Err(err) = inbound.write_all(&payload).await {
                                    if is_graceful_stream_close_error(&err) {
                                        break;
                                    }
                                    return Err(format!("write Trojan websocket payload to client: {err}"));
                                }
                                stats.direct_to_client += payload.len();
                                metrics.add_download(payload.len());
                            }
                        }
                        if ws_decoder.is_closed() {
                            proxy_closed = true;
                            let _ = inbound.shutdown().await;
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read Trojan websocket TLS plaintext: {err}")),
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if proxy_closed || inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident Trojan websocket relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
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

#[derive(Default)]
struct WebSocketBinaryFrameDecoder {
    pending: Vec<u8>,
    closed: bool,
}

impl WebSocketBinaryFrameDecoder {
    fn push(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if self.closed {
            return Ok(Vec::new());
        }
        self.pending.extend_from_slice(input);
        let mut frames = Vec::new();
        loop {
            if self.pending.len() < 2 {
                break;
            }
            let fin = self.pending[0] & 0x80 != 0;
            let opcode = self.pending[0] & 0x0f;
            if !fin || !matches!(opcode, 2 | 8) {
                return Err(format!(
                    "unexpected websocket frame: fin={fin} opcode={opcode}"
                ));
            }
            let masked = self.pending[1] & 0x80 != 0;
            let mut len = (self.pending[1] & 0x7f) as usize;
            let mut header_len = 2_usize;
            if len == 126 {
                if self.pending.len() < 4 {
                    break;
                }
                len = u16::from_be_bytes([self.pending[2], self.pending[3]]) as usize;
                header_len = 4;
            } else if len == 127 {
                return Err("websocket 64-bit length unsupported in resident relay".to_owned());
            }
            let mask_key = if masked {
                if self.pending.len() < header_len + 4 {
                    break;
                }
                let key = [
                    self.pending[header_len],
                    self.pending[header_len + 1],
                    self.pending[header_len + 2],
                    self.pending[header_len + 3],
                ];
                header_len += 4;
                Some(key)
            } else {
                None
            };
            if self.pending.len() < header_len + len {
                break;
            }
            let mut payload = self.pending[header_len..header_len + len].to_vec();
            if let Some(mask_key) = mask_key {
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask_key[index % 4];
                }
            }
            self.pending.drain(..header_len + len);
            if opcode == 8 {
                self.closed = true;
                break;
            }
            frames.push(payload);
        }
        Ok(frames)
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

struct WebSocketPayloadReader<'a> {
    stream: &'a mut TcpStream,
    decoder: WebSocketBinaryFrameDecoder,
    pending: VecDeque<u8>,
    buffer: [u8; 16 * 1024],
}

impl<'a> WebSocketPayloadReader<'a> {
    fn new(stream: &'a mut TcpStream) -> Self {
        Self {
            stream,
            decoder: WebSocketBinaryFrameDecoder::default(),
            pending: VecDeque::new(),
            buffer: [0_u8; 16 * 1024],
        }
    }
}

impl Read for WebSocketPayloadReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pending.is_empty() {
            if self.decoder.is_closed() {
                return Ok(0);
            }
            let read = self.stream.read(&mut self.buffer)?;
            if read == 0 {
                return Ok(0);
            }
            let frames = self
                .decoder
                .push(&self.buffer[..read])
                .map_err(|err| std::io::Error::new(ErrorKind::InvalidData, err))?;
            for frame in frames {
                self.pending.extend(frame);
            }
        }
        let len = out.len().min(self.pending.len());
        for byte in &mut out[..len] {
            *byte = self.pending.pop_front().unwrap_or_default();
        }
        Ok(len)
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
    fn resident_upload_relay_treats_peer_close_as_graceful_end() {
        assert!(is_graceful_stream_close_error(&std::io::Error::from(
            ErrorKind::BrokenPipe
        )));
        assert!(is_graceful_stream_close_error(&std::io::Error::from(
            ErrorKind::ConnectionReset
        )));
        assert!(is_graceful_stream_close_error(&std::io::Error::from(
            ErrorKind::ConnectionAborted
        )));
        assert!(!is_graceful_stream_close_error(&std::io::Error::from(
            ErrorKind::TimedOut
        )));
        assert!(is_graceful_tls_plain_close_error(&std::io::Error::other(
            "peer closed connection without sending TLS close_notify",
        )));
    }

    #[test]
    fn resident_tcp_probe_http_request_uses_configured_method_path_and_host() {
        let request = String::from_utf8(resident_tcp_probe_http_request(
            "HEAD",
            "/generate_204",
            "check.example",
        ))
        .unwrap();
        assert!(request.starts_with("HEAD /generate_204 HTTP/1.1\r\n"));
        assert!(request.contains("Host: check.example\r\n"));
        assert!(request.contains("Connection: close\r\n"));
    }

    #[test]
    fn resident_tcp_probe_status_matches_go_http_check_rules() {
        assert!(resident_tcp_probe_status_ok("/generate_204", 204));
        assert!(!resident_tcp_probe_status_ok("/generate_204", 200));
        assert!(resident_tcp_probe_status_ok("/", 204));
        assert!(resident_tcp_probe_status_ok("/", 404));
        assert!(!resident_tcp_probe_status_ok("/", 500));
    }

    #[test]
    fn xhttp_h2_uri_uses_path_session_placement() {
        let mut proxy = dummy_proxy_plan();
        proxy.net = "xhttp".to_owned();
        proxy.server_name = "tls.name.invalid".to_owned();
        proxy.stream_host = "edge.transport.invalid".to_owned();
        proxy.stream_path = "/resource?ed=2048".to_owned();

        assert_eq!(
            xhttp_uri(&proxy, &xhttp_session_path_suffix("session-id", None)),
            "https://edge.transport.invalid/resource/session-id?ed=2048"
        );
        assert_eq!(
            xhttp_uri(&proxy, &xhttp_session_path_suffix("session-id", Some(7))),
            "https://edge.transport.invalid/resource/session-id/7?ed=2048"
        );
    }

    #[test]
    fn xhttp_h2_request_uses_default_referer_padding() {
        let mut proxy = dummy_proxy_plan();
        proxy.net = "xhttp".to_owned();
        proxy.server_name = "tls.name.invalid".to_owned();
        proxy.stream_host = "edge.transport.invalid".to_owned();
        proxy.stream_path = "/resource?ed=2048".to_owned();

        let request = xhttp_h2_request(
            http::Method::GET,
            &proxy,
            &xhttp_session_path_suffix("session-id", None),
            false,
        )
        .unwrap();
        assert_eq!(
            request.uri().to_string(),
            "https://edge.transport.invalid/resource/session-id?ed=2048"
        );
        let referer = request
            .headers()
            .get(http::header::REFERER)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(referer.starts_with("https://edge.transport.invalid/resource/?x_padding="));
        let padding = referer.split_once("x_padding=").unwrap().1;
        assert_eq!(padding.len(), 128);
        assert!(padding.bytes().all(|byte| byte == b'X'));
    }

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
    fn resident_websocket_decoder_treats_close_frame_as_eof() {
        let mut decoder = WebSocketBinaryFrameDecoder::default();
        let frames = decoder
            .push(&[0x82, 0x03, b'o', b'n', b'e', 0x88, 0x00])
            .unwrap();
        assert_eq!(frames, vec![b"one".to_vec()]);
        assert!(decoder.is_closed());
        assert!(
            decoder
                .push(&[0x82, 0x03, b't', b'w', b'o'])
                .unwrap()
                .is_empty()
        );
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
            "async-proxy-tls",
        );

        assert_eq!(event["event"], "tcp_connection_failed");
        assert_eq!(event["tls_underlay"], "boringssl");
        assert_eq!(event["legacyExecution"], "async-proxy-tls");
        assert!(event.get("execution").is_none());
        assert_eq!(event["executionDescriptor"]["schemaVersion"], 1);
        assert_eq!(event["executionDescriptor"]["executor"], "tcp-relay");
        assert_eq!(
            event["executionDescriptor"]["capability"],
            "stream-transport"
        );
        assert_eq!(event["executionDescriptor"]["network"], "tcp");
        assert_eq!(
            event["executionDescriptor"]["securityUnderlay"],
            "boringssl"
        );
        assert_eq!(event["executionDescriptor"]["protocolFraming"], "vless");
        assert_eq!(
            event["executionDescriptor"]["graphId"],
            "resident-graph:test-flow"
        );
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
        proxies.insert(
            OutboundIndex::USER_DEFINED_MIN.value(),
            ResidentProxyGroupPlan::fixed_single_for_test(dummy_proxy_plan()),
        );
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
            graph_id: "resident-graph:test-flow".to_owned(),
            graph_link_hash: "sha256:test-flow".to_owned(),
            redacted_link_source: "vless:<redacted>#flow".to_owned(),
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
            stream_host: String::new(),
            stream_path: String::new(),
            tls: "tls".to_owned(),
            allow_insecure: false,
            utls_fingerprint: None,
            handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] },
            chain_parent: None,
            mark: 0,
            mptcp: false,
        }
    }
}
