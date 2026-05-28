use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
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
    choose_dial_target,
};
use dae_ebpf_support::{
    BpfIpBytes, BpfRoutingResult, BpfTuplesKey, lookup_map_elem_bytes, open_map_fd,
};
use dae_outbound::vless::packet;
use dae_routing::{Query, RoutingMatcher};
use dae_sniffing::{SniffingError, sniff_tcp};
use serde_json::{Value, json};

use super::client::{VlessTlsClient, drive_tls_io_record_aware, open_vless_tls_client};
use super::direct::{open_direct_tcp_connection, relay_tcp_direct};
use super::events::append_event;
use super::io::write_all_nonblocking;
use super::plan::ResidentProxyPlan;
use super::vision::{VisionInnerTlsState, VisionUnpadder, VisionUplinkMode, drain_vision_uplink};
use super::{
    RESIDENT_IDLE_SLEEP, RESIDENT_TCP_ACCEPT_SLEEP, RESIDENT_TCP_IDLE_TIMEOUT,
    TLS_RECORD_MAX_PAYLOAD_LEN, VLESS_RESPONSE_VERSION, XTLS_RPRX_VISION,
};

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
) {
    if let Err(err) = listener.set_nonblocking(true) {
        append_event(
            &event_file,
            &event_lock,
            json!({"event": "tcp_listener_nonblocking_failed", "error": err.to_string()}),
        );
        return;
    }
    append_event(
        &event_file,
        &event_lock,
        json!({"event": "tcp_worker_started", "proxy_count": router.proxy_count(), "dial_mode": router.dial_mode_name()}),
    );
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let router = Arc::clone(&router);
                let stop = Arc::clone(&stop);
                let event_file = event_file.clone();
                let event_lock = Arc::clone(&event_lock);
                thread::spawn(move || {
                    let result = handle_tcp_connection(stream, peer, router, stop);
                    match result {
                        Ok(event) => append_event(&event_file, &event_lock, event),
                        Err(err) => append_event(
                            &event_file,
                            &event_lock,
                            json!({"event": "tcp_connection_failed", "peer": peer.to_string(), "error": err}),
                        ),
                    }
                });
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
        TcpSelection::Proxy(selection) => {
            handle_proxy_tcp_connection(&mut inbound, peer, original_dst, selection, &stop, &sniff)
        }
        TcpSelection::Direct(selection) => {
            handle_direct_tcp_connection(&mut inbound, peer, original_dst, selection, &stop, &sniff)
        }
        TcpSelection::Block(selection) => {
            let _ = inbound.shutdown(Shutdown::Both);
            Ok(json!({
                "event": "tcp_connection_blocked",
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
            }))
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
) -> Result<Value, String> {
    let mut client = open_vless_tls_client(&selection.proxy)?;
    client
        .tcp
        .set_nonblocking(true)
        .map_err(|err| format!("set proxy tcp nonblocking: {err}"))?;
    let request = packet::first_write_bytes(
        &selection.proxy.key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS TCP request: {err}"))?;
    client
        .conn
        .writer()
        .write_all(&request)
        .map_err(|err| format!("queue VLESS TCP request: {err}"))?;
    relay_tcp_over_vless_tls(
        inbound,
        &mut client,
        stop,
        &selection.proxy.flow,
        selection.proxy.key,
        &sniff.payload,
    )
    .map(|stats| {
        json!({
            "event": "tcp_connection_finished",
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
            "node_tag": &selection.proxy.node_tag,
            "bytes_client_to_proxy": stats.client_to_proxy,
            "bytes_proxy_to_client": stats.proxy_to_client,
            "response_header_stripped": stats.response_header_stripped,
            "vision_unpadding_blocks": stats.vision_unpadding_blocks,
            "vision_direct_command_seen": stats.vision_direct_command_seen,
        })
    })
}

fn handle_direct_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpDirectSelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
) -> Result<Value, String> {
    let mut direct = open_direct_tcp_connection(
        &selection.route.dial_target,
        selection.route.final_mark,
        selection.mptcp,
    )?;
    let stats = relay_tcp_direct(inbound, &mut direct.stream, stop, &sniff.payload)?;
    Ok(json!({
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
        "direct_target": direct.target.to_string(),
        "direct_peer_addr": &direct.report.peer_addr,
        "direct_local_addr": &direct.report.local_addr,
        "direct_so_mark": direct.report.so_mark,
        "direct_so_mark_applied": direct.report.so_mark_applied,
        "direct_mptcp_requested": direct.report.requested_mptcp,
        "direct_mptcp_socket_attempted": direct.report.mptcp_socket_attempted,
        "direct_mptcp_socket_created": direct.report.mptcp_socket_created,
        "direct_mptcp_connect_fallback_used": direct.report.mptcp_connect_fallback_used,
        "bytes_client_to_direct": stats.client_to_direct,
        "bytes_direct_to_client": stats.direct_to_client,
    }))
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

fn sniff_needs_more(err: &SniffingError) -> bool {
    matches!(err, SniffingError::NeedMore) || err.to_string().contains("need more")
}

fn process_name(raw: &[u8; 16]) -> Option<String> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    (end > 0).then(|| String::from_utf8_lossy(&raw[..end]).into_owned())
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

#[derive(Default)]
struct RelayStats {
    client_to_proxy: usize,
    proxy_to_client: usize,
    response_header_stripped: bool,
    vision_unpadding_blocks: usize,
    vision_direct_command_seen: bool,
}

fn relay_tcp_over_vless_tls(
    inbound: &mut TcpStream,
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
    flow: &str,
    user_uuid: [u8; 16],
    initial_payload: &[u8],
) -> Result<RelayStats, String> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let vision_enabled = flow == XTLS_RPRX_VISION;
    let mut vision = vision_enabled.then(|| VisionUnpadder::new(user_uuid));
    let mut downlink_direct = false;
    let mut vision_uplink_mode = VisionUplinkMode::Padding;
    let mut vision_tls_state = VisionInnerTlsState::new();
    let mut uplink_uuid_sent = false;
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
                &mut vision_uplink_mode,
                &mut vision_tls_state,
            )?;
        } else {
            client
                .conn
                .writer()
                .write_all(initial_payload)
                .map_err(|err| format!("queue sniffed client payload to proxy TLS: {err}"))?;
        }
        stats.client_to_proxy += initial_payload.len();
    }
    while !stop.load(Ordering::Relaxed) {
        let mut progressed = false;
        if !inbound_closed {
            match inbound.read(&mut inbound_buf) {
                Ok(0) => {
                    inbound_closed = true;
                    client.conn.send_close_notify();
                    progressed = true;
                }
                Ok(read) => {
                    if vision_enabled {
                        pending_vision_uplink.extend_from_slice(&inbound_buf[..read]);
                        if pending_vision_uplink.len() > TLS_RECORD_MAX_PAYLOAD_LEN * 4 {
                            return Err(format!(
                                "pending Vision uplink payload did not form complete TLS records: {} bytes",
                                pending_vision_uplink.len()
                            ));
                        }
                        drain_vision_uplink(
                            &mut pending_vision_uplink,
                            client,
                            stop,
                            user_uuid,
                            &mut uplink_uuid_sent,
                            &mut vision_uplink_mode,
                            &mut vision_tls_state,
                        )?;
                    } else {
                        client
                            .conn
                            .writer()
                            .write_all(&inbound_buf[..read])
                            .map_err(|err| format!("queue client payload to proxy TLS: {err}"))?;
                    }
                    stats.client_to_proxy += read;
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => return Err(format!("read inbound TCP: {err}")),
            }
        }

        if downlink_direct {
            match client.tcp.read(&mut proxy_buf) {
                Ok(0) => {
                    break;
                }
                Ok(read) => {
                    write_all_nonblocking(
                        inbound,
                        &proxy_buf[..read],
                        stop,
                        "write VLESS Vision direct payload to client",
                    )?;
                    stats.proxy_to_client += read;
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => return Err(format!("read VLESS Vision direct TCP: {err}")),
            }
        } else {
            progressed |= drive_tls_io_record_aware(client)?;
            loop {
                match client.conn.reader().read(&mut proxy_buf) {
                    Ok(0) => break,
                    Ok(read) => {
                        let mut payload = stripper.consume(&proxy_buf[..read])?;
                        stats.response_header_stripped = stripper.done;
                        if let Some(vision) = vision.as_mut()
                            && !payload.is_empty()
                        {
                            payload = vision.consume(&payload)?;
                            vision_tls_state.observe_server_payload(&payload)?;
                            stats.vision_unpadding_blocks = vision.completed_blocks;
                            stats.vision_direct_command_seen = vision.direct_command_seen;
                            downlink_direct = vision.direct_command_seen;
                            if !pending_vision_uplink.is_empty() {
                                drain_vision_uplink(
                                    &mut pending_vision_uplink,
                                    client,
                                    stop,
                                    user_uuid,
                                    &mut uplink_uuid_sent,
                                    &mut vision_uplink_mode,
                                    &mut vision_tls_state,
                                )?;
                            }
                        }
                        if !payload.is_empty() {
                            write_all_nonblocking(
                                inbound,
                                &payload,
                                stop,
                                "write VLESS payload to client",
                            )?;
                            stats.proxy_to_client += payload.len();
                        }
                        progressed = true;
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    Err(err) => return Err(format!("read VLESS TLS plaintext: {err}")),
                }
            }
        }

        if inbound_closed
            && !downlink_direct
            && !client.conn.wants_write()
            && !client.conn.wants_read()
        {
            break;
        }
        if progressed {
            last_activity = Instant::now();
        } else if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
            return Err("resident TCP relay idle timeout".to_owned());
        } else {
            thread::sleep(RESIDENT_IDLE_SLEEP);
        }
    }
    Ok(stats)
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
    use super::*;
    use serde_json::json;

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
            group_name: "proxy".to_owned(),
            node_tag: "node".to_owned(),
            server_host: "127.0.0.1".to_owned(),
            server_port: 443,
            server_name: "example.com".to_owned(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            tls: "tls".to_owned(),
            allow_insecure: false,
            key: [0; 16],
            mark: 0,
            mptcp: false,
        }
    }
}
