use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dae_ebpf_support::open_transparent_udp_socket_bound_in_netns;
use dae_outbound::{
    anytls::{contract as anytls_contract, link as anytls_link},
    hysteria2::{authenticate_hysteria2_connection, build_hysteria2_pinned_client_config},
    juicity::{
        authenticate_juicity_connection, build_juicity_runtime_client_config,
        decode_stream_packet_frame, seal_stream_packet_frame,
    },
    shadowsocks::{decode_udp_packet as decode_shadowsocks_udp_packet, encode_udp_packet},
    socks5::{Socks5Address, udp_associate_control_over_stream, udp_packet},
    trojan::{decode_udp_packet as decode_trojan_udp_packet, packet as trojan_packet},
    tuic::{authenticate_tuic_connection, build_tuic_runtime_client_config},
    vless::packet,
    vmess,
};
use serde_json::json;
use tokio::runtime;
use tokio::time;

use super::super::PRODUCTION_NETNS;
use super::super::udp_io::{UdpOriginalDstPacket, recv_udp_with_original_dst};
use super::client::{
    VlessTlsClient, drive_tls_io_blocking, open_vless_tls_client, tls_underlay_name,
};
use super::direct::open_direct_tcp_connection;
use super::dns::{ResidentDnsPlan, handle_resident_dns_udp};
use super::events::append_event;
use super::plan::{ResidentProxyGroupPlan, ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::tcp::{open_marked_quic_endpoint, resolve_proxy_udp_addr, set_socket_mark};
use super::vision::{VisionUnpadState, VisionUnpadder, vision_padding_block};
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_IDLE_SLEEP, RESIDENT_UDP_RESPONSE_TIMEOUT,
    ResidentDataplaneMetrics, VISION_COMMAND_CONTINUE, VLESS_RESPONSE_VERSION, XTLS_RPRX_VISION,
    XUDP_COMMAND_NEW, XUDP_MUX_TARGET, XUDP_NETWORK_UDP, XUDP_OPTION_DATA,
};

pub(super) fn resident_udp_loop(
    socket: std::net::UdpSocket,
    proxy_group: Arc<ResidentProxyGroupPlan>,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    worker_limit: usize,
    worker_stack_bytes: usize,
) {
    if let Err(err) = socket.set_nonblocking(true) {
        append_event(
            &event_file,
            &event_lock,
            json!({"event": "udp_socket_nonblocking_failed", "error": err.to_string()}),
        );
        return;
    }
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "udp_worker_started",
            "proxy_group": proxy_group.group_name,
            "group_policy": proxy_group.group_policy_name(),
            "candidate_count": proxy_group.candidate_count(),
            "admitted_candidate_count": proxy_group.admitted_candidate_count(),
            "worker_limit": worker_limit,
            "worker_stack_bytes": worker_stack_bytes,
        }),
    );
    let active_workers = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        let packet = match recv_udp_with_original_dst(&socket, 2048) {
            Ok(packet) => packet,
            Err(err)
                if err.contains("WouldBlock")
                    || err.contains("Resource temporarily unavailable") =>
            {
                continue;
            }
            Err(err) => {
                if !stop.load(Ordering::Relaxed) {
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({"event": "udp_receive_failed", "error": err}),
                    );
                }
                continue;
            }
        };
        let Some(original_dst) = packet.original_dst else {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_packet_skipped", "reason": "missing original destination", "peer": packet.peer.to_string()}),
            );
            continue;
        };
        let active = active_workers.load(Ordering::Relaxed);
        if active >= worker_limit {
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_packet_dropped",
                    "reason": "resident UDP packet worker limit reached",
                    "peer": packet.peer.to_string(),
                    "original_dst": original_dst.to_string(),
                    "active_workers": active,
                    "worker_limit": worker_limit,
                }),
            );
            continue;
        }

        active_workers.fetch_add(1, Ordering::Relaxed);
        let active_workers_for_task = Arc::clone(&active_workers);
        let proxy_group = Arc::clone(&proxy_group);
        let dns = Arc::clone(&dns);
        let task_event_file = event_file.clone();
        let task_event_lock = Arc::clone(&event_lock);
        let metrics = Arc::clone(&metrics);
        let spawn_peer = packet.peer.to_string();
        let spawn_original_dst = original_dst.to_string();
        let spawn_result = thread::Builder::new()
            .name("dae-resident-udp-packet".to_owned())
            .stack_size(worker_stack_bytes)
            .spawn(move || {
                let packet_metrics = Arc::clone(&metrics);
                let _guard = UdpPacketWorkerGuard::new(active_workers_for_task, metrics);
                handle_udp_packet(
                    proxy_group,
                    dns,
                    packet,
                    original_dst,
                    task_event_file,
                    task_event_lock,
                    packet_metrics,
                );
            });
        if let Err(err) = spawn_result {
            active_workers.fetch_sub(1, Ordering::Relaxed);
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_worker_spawn_failed",
                    "peer": spawn_peer,
                    "original_dst": spawn_original_dst,
                    "error": err.to_string(),
                }),
            );
        }
    }
    append_event(
        &event_file,
        &event_lock,
        json!({"event": "udp_worker_stopped"}),
    );
}

struct UdpPacketWorkerGuard {
    active_workers: Arc<AtomicUsize>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl UdpPacketWorkerGuard {
    fn new(active_workers: Arc<AtomicUsize>, metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        metrics.udp_opened();
        Self {
            active_workers,
            metrics,
        }
    }
}

impl Drop for UdpPacketWorkerGuard {
    fn drop(&mut self) {
        self.metrics.udp_closed();
        self.active_workers.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct UdpExchangeResult {
    payload: Vec<u8>,
    execution: &'static str,
    tls_underlay: Option<&'static str>,
    quic_underlay: Option<&'static str>,
}

impl UdpExchangeResult {
    fn new(payload: Vec<u8>, execution: &'static str) -> Self {
        Self {
            payload,
            execution,
            tls_underlay: None,
            quic_underlay: None,
        }
    }

    fn with_tls_underlay(mut self, tls_underlay: &'static str) -> Self {
        self.tls_underlay = Some(tls_underlay);
        self
    }

    fn with_quic_underlay(mut self, quic_underlay: &'static str) -> Self {
        self.quic_underlay = Some(quic_underlay);
        self
    }
}

fn handle_udp_packet(
    proxy_group: Arc<ResidentProxyGroupPlan>,
    dns: Arc<ResidentDnsPlan>,
    packet: UdpOriginalDstPacket,
    original_dst: SocketAddrV4,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    let request_len = packet.payload.len();
    let peer = packet.peer;
    metrics.add_upload(request_len);
    let proxy = match proxy_group.select_proxy_for_udp() {
        Ok(proxy) => proxy,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_exchange_failed",
                    "peer": peer.to_string(),
                    "original_dst": original_dst.to_string(),
                    "error": err,
                    "proxy_group": proxy_group.group_name,
                    "group_policy": proxy_group.group_policy_name(),
                    "network": "udp4",
                    "outbound": proxy_group.group_name,
                    "policy": proxy_group.group_policy_name(),
                }),
            );
            return;
        }
    };
    let exchange = if original_dst.port() == 53 {
        handle_resident_dns_udp(&dns, original_dst, &packet.payload).map(|response| {
            (
                "udp_dns_packet_finished",
                UdpExchangeResult::new(response, "resident-dns-udp-v1"),
            )
        })
    } else {
        exchange_proxy_udp(&proxy, original_dst, &packet.payload)
            .map(|response| ("udp_packet_finished", response))
    };
    match exchange {
        Ok((event, response)) => match send_udp_reply(original_dst, peer, &response.payload) {
            Ok(()) => {
                metrics.add_download(response.payload.len());
                let handler = resident_udp_handler_name(&proxy.handler);
                let mut event_json = json!({
                    "event": event,
                    "peer": peer.to_string(),
                    "original_dst": original_dst.to_string(),
                    "request_len": request_len,
                    "response_len": response.payload.len(),
                    "proxy_group": proxy.group_name,
                    "group_policy": proxy.group_policy,
                    "node_tag": proxy.node_tag,
                    "network": "udp4",
                    "outbound": proxy.group_name,
                    "policy": proxy.group_policy,
                    "dialer": proxy.node_tag,
                    "sniffed": "",
                    "ip": original_dst.to_string(),
                    "protocol": proxy.protocol,
                    "handler": handler,
                    "execution": response.execution,
                });
                if let Some(tls_underlay) = response.tls_underlay {
                    event_json["tls_underlay"] = json!(tls_underlay);
                }
                if let Some(quic_underlay) = response.quic_underlay {
                    event_json["quic_underlay"] = json!(quic_underlay);
                }
                append_event(&event_file, &event_lock, event_json)
            }
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_reply_failed", "peer": peer.to_string(), "original_dst": original_dst.to_string(), "error": err}),
            ),
        },
        Err(err) => {
            let handler = resident_udp_handler_name(&proxy.handler);
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_exchange_failed",
                    "peer": peer.to_string(),
                    "original_dst": original_dst.to_string(),
                    "error": err,
                    "protocol": proxy.protocol,
                    "handler": handler,
                    "proxy_group": proxy.group_name,
                    "group_policy": proxy.group_policy,
                    "node_tag": proxy.node_tag,
                    "network": "udp4",
                    "outbound": proxy.group_name,
                    "policy": proxy.group_policy,
                    "dialer": proxy.node_tag,
                    "ip": original_dst.to_string(),
                }),
            )
        }
    }
}

fn exchange_proxy_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
) -> Result<UdpExchangeResult, String> {
    match &proxy.handler {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => {
            exchange_vless_udp(proxy, original_dst, payload)
        }
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher,
            password,
            salt_len,
        } => exchange_shadowsocks_udp(proxy, original_dst, payload, cipher, password, *salt_len),
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            exchange_socks5_udp(proxy, original_dst, payload, username, password)
        }
        ResidentProxyProtocolPlan::TrojanTcpTls { password } => {
            exchange_trojan_udp(proxy, original_dst, payload, password)
        }
        ResidentProxyProtocolPlan::VmessAeadTcp { id } => {
            exchange_vmess_udp(proxy, original_dst, payload, id)
        }
        ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } => {
            exchange_anytls_udp(proxy, original_dst, payload, auth)
        }
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            pin_sha256,
            max_rx,
        } => exchange_hysteria2_udp(proxy, original_dst, payload, auth, pin_sha256, *max_rx),
        ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid,
            password,
            alpn,
        } => exchange_tuic_udp(proxy, original_dst, payload, uuid, password, alpn),
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid,
            password,
            allow_insecure,
            pinned_certchain_sha256,
        } => exchange_juicity_udp(
            proxy,
            original_dst,
            payload,
            uuid,
            password,
            *allow_insecure,
            pinned_certchain_sha256,
        ),
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => Err(format!(
            "unsupported_udp_handler: resident UDP adapter dispatch selected handler {} for protocol {}; HTTP CONNECT has no UDP relay semantics and is fail-closed without Go fallback",
            resident_udp_handler_name(&proxy.handler),
            proxy.protocol
        )),
    }
}

pub(super) fn probe_resident_proxy_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
) -> serde_json::Value {
    let started = Instant::now();
    let handler = resident_udp_handler_name(&proxy.handler);
    match exchange_proxy_udp(proxy, original_dst, payload) {
        Ok(response) => {
            let payload_match = response.payload == payload;
            let mut report = json!({
                "status": if payload_match { "pass" } else { "fail" },
                "ok": payload_match,
                "protocol_closed": false,
                "handler": handler,
                "execution": response.execution,
                "request_len": payload.len(),
                "response_len": response.payload.len(),
                "payload_match": payload_match,
                "elapsed_ms": started.elapsed().as_millis(),
            });
            if let Some(tls_underlay) = response.tls_underlay {
                report["tls_underlay"] = json!(tls_underlay);
            }
            if let Some(quic_underlay) = response.quic_underlay {
                report["quic_underlay"] = json!(quic_underlay);
            }
            report
        }
        Err(err)
            if matches!(
                proxy.handler,
                ResidentProxyProtocolPlan::HttpProxyTcp { .. }
            ) =>
        {
            json!({
                "status": "protocol-closed",
                "ok": true,
                "protocol_closed": true,
                "handler": handler,
                "request_len": payload.len(),
                "response_len": 0,
                "payload_match": false,
                "elapsed_ms": started.elapsed().as_millis(),
                "error": err,
            })
        }
        Err(err) => json!({
            "status": "fail",
            "ok": false,
            "protocol_closed": false,
            "handler": handler,
            "request_len": payload.len(),
            "response_len": 0,
            "payload_match": false,
            "elapsed_ms": started.elapsed().as_millis(),
            "error": err,
        }),
    }
}

pub(super) fn probe_resident_proxy_dns_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    lookup_host: &str,
) -> Result<(), String> {
    let id = fastrand::u16(0..=u16::MAX);
    let query = build_dns_a_query(id, lookup_host)?;
    let response = exchange_proxy_udp(proxy, original_dst, &query)?;
    dns_a_response_has_answer(id, &response.payload)
}

fn build_dns_a_query(id: u16, lookup_host: &str) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_qname(&mut query, lookup_host)?;
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn encode_dns_qname(out: &mut Vec<u8>, lookup_host: &str) -> Result<(), String> {
    let lookup_host = lookup_host.trim_end_matches('.');
    if lookup_host.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in lookup_host.split('.') {
        if label.is_empty() {
            return Err(format!(
                "invalid DNS lookup host {lookup_host}: empty label"
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "invalid DNS lookup host {lookup_host}: label exceeds 63 bytes"
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn dns_a_response_has_answer(query_id: u16, response: &[u8]) -> Result<(), String> {
    if response.len() < 12 {
        return Err(format!("DNS response too short: {} bytes", response.len()));
    }
    let response_id = u16::from_be_bytes([response[0], response[1]]);
    if response_id != query_id {
        return Err(format!(
            "DNS response id mismatch: got {response_id}, expected {query_id}"
        ));
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS response is not a response packet".to_owned());
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("DNS response rcode={rcode}"));
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return Err("DNS response has no answer records".to_owned());
    }
    let mut offset = 12_usize;
    for _ in 0..qdcount {
        skip_dns_name(response, &mut offset)?;
        if response.len().saturating_sub(offset) < 4 {
            return Err("DNS response question section truncated".to_owned());
        }
        offset += 4;
    }
    for _ in 0..ancount {
        skip_dns_name(response, &mut offset)?;
        if response.len().saturating_sub(offset) < 10 {
            return Err("DNS response answer section truncated".to_owned());
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        if response.len().saturating_sub(offset) < rdlen {
            return Err("DNS response answer data truncated".to_owned());
        }
        if record_type == 1 && class == 1 && rdlen == 4 {
            return Ok(());
        }
        offset += rdlen;
    }
    Err("DNS response has no A answer records".to_owned())
}

fn skip_dns_name(packet: &[u8], offset: &mut usize) -> Result<(), String> {
    let mut jumps = 0_usize;
    loop {
        if *offset >= packet.len() {
            return Err("DNS name truncated".to_owned());
        }
        let len = packet[*offset];
        if len & 0xc0 == 0xc0 {
            if packet.len().saturating_sub(*offset) < 2 {
                return Err("DNS compressed name pointer truncated".to_owned());
            }
            *offset += 2;
            return Ok(());
        }
        if len & 0xc0 != 0 {
            return Err(format!("unsupported DNS name label marker: 0x{len:02x}"));
        }
        *offset += 1;
        if len == 0 {
            return Ok(());
        }
        let len = len as usize;
        if packet.len().saturating_sub(*offset) < len {
            return Err("DNS name label truncated".to_owned());
        }
        *offset += len;
        jumps += 1;
        if jumps > 128 {
            return Err("DNS name too deep".to_owned());
        }
    }
}

fn resident_udp_handler_name(handler: &ResidentProxyProtocolPlan) -> &'static str {
    match handler {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => "vless-vision-tcp-tls",
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => "socks5-tcp",
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => "http-proxy-tcp",
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => "shadowsocks-aead-tcp",
        ResidentProxyProtocolPlan::TrojanTcpTls { .. } => "trojan-tcp-tls",
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => "anytls-tcp-tls",
        ResidentProxyProtocolPlan::VmessAeadTcp { .. } => "vmess-aead-tcp",
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => "hysteria2-quic-tcp",
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => "tuic-quic-tcp",
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => "juicity-quic-tcp",
    }
}

fn exchange_vless_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
) -> Result<UdpExchangeResult, String> {
    let key = proxy.vless_key()?;
    let mut client = open_vless_tls_client(proxy)?;
    let tls_underlay = tls_underlay_name(&client);
    let request = build_vless_udp_request(proxy, original_dst, payload)?;
    client.queue_plain(&request, "queue VLESS UDP request")?;
    flush_tls_writes_for_udp(&mut client)?;
    read_vless_udp_response(&mut client, &proxy.flow, key).map(|payload| {
        UdpExchangeResult::new(payload, "vless-xudp-v1").with_tls_underlay(tls_underlay)
    })
}

fn exchange_shadowsocks_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<UdpExchangeResult, String> {
    let mut salt = vec![0_u8; salt_len];
    fastrand::fill(&mut salt);
    let request = encode_udp_packet(cipher, password, &salt, &original_dst.to_string(), payload)
        .map_err(|err| format!("encode Shadowsocks UDP packet: {err}"))?;
    let response = exchange_udp_datagram_with_proxy(proxy, &request, "Shadowsocks")?;
    let decoded = decode_shadowsocks_udp_packet(cipher, password, &response)
        .map_err(|err| format!("decode Shadowsocks UDP packet: {err}"))?;
    Ok(UdpExchangeResult::new(
        decoded.payload,
        "udp-datagram-aead-v1",
    ))
}

fn exchange_socks5_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    username: &str,
    password: &str,
) -> Result<UdpExchangeResult, String> {
    let mut control = open_plain_proxy_tcp_stream(proxy, "SOCKS5 UDP associate")?;
    let report = udp_associate_control_over_stream(
        &mut control,
        &proxy_server_authority(proxy),
        "0.0.0.0:0",
        username,
        password,
    )
    .map_err(|err| format!("SOCKS5 UDP associate control: {err}"))?;
    let relay = socks5_udp_relay_addr(proxy, &report.bind)?;
    let request = udp_packet::wrap_target(&original_dst.to_string(), payload)
        .map_err(|err| format!("wrap SOCKS5 UDP packet: {err}"))?;
    let response = exchange_udp_datagram_to_addr(proxy, relay, &request, "SOCKS5")?;
    let decoded =
        udp_packet::unwrap(&response).map_err(|err| format!("unwrap SOCKS5 UDP packet: {err}"))?;
    Ok(UdpExchangeResult::new(
        decoded.payload,
        "socks5-udp-associate-v1",
    ))
}

fn exchange_trojan_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    password: &str,
) -> Result<UdpExchangeResult, String> {
    let mut client = open_vless_tls_client(proxy)?;
    let tls_underlay = tls_underlay_name(&client);
    let packet = trojan_packet::udp_packet(&original_dst.to_string(), payload)
        .map_err(|err| format!("build Trojan UDP packet: {err}"))?;
    let request =
        trojan_packet::tcp_request_header(password, "udp", &original_dst.to_string(), &packet)
            .map_err(|err| format!("build Trojan UDP-over-TCP request: {err}"))?;
    write_tls_plain_all(&mut client, &request, "write Trojan UDP-over-TCP request")?;
    read_tls_plain_until(&mut client, "read Trojan UDP-over-TCP response", |buffer| {
        decode_trojan_udp_packet(buffer).map(|packet| packet.payload)
    })
    .map(|payload| {
        UdpExchangeResult::new(payload, "tls-udp-over-tcp-v1").with_tls_underlay(tls_underlay)
    })
}

fn exchange_vmess_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    id: &str,
) -> Result<UdpExchangeResult, String> {
    let mut stream = open_plain_proxy_tcp_stream(proxy, "VMess UDP-over-TCP")?;
    let report = vmess::aead_udp_over_tcp_exchange_over_stream(
        &mut stream,
        &proxy_server_authority(proxy),
        id,
        &original_dst.to_string(),
        payload,
    )
    .map_err(|err| format!("VMess AEAD UDP-over-TCP exchange: {err}"))?;
    Ok(UdpExchangeResult::new(
        report.echoed_payload,
        "aead-udp-over-tcp-v1",
    ))
}

fn exchange_anytls_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    auth: &str,
) -> Result<UdpExchangeResult, String> {
    let mut client = open_vless_tls_client(proxy)?;
    let tls_underlay = tls_underlay_name(&client);
    write_tls_plain_all(
        &mut client,
        &anytls_link::handshake_auth_bytes(auth),
        "write AnyTLS auth handshake",
    )?;
    write_tls_plain_all(
        &mut client,
        &anytls_link::frame(
            anytls_contract::CMD_SETTINGS,
            1,
            &anytls_link::settings_bytes(),
        ),
        "write AnyTLS settings",
    )?;
    write_tls_plain_all(
        &mut client,
        &anytls_link::frame(anytls_contract::CMD_SYN, 1, &[]),
        "write AnyTLS SYN",
    )?;
    let stream_target = anytls_link::udp_stream_target(&original_dst.to_string())
        .map_err(|err| format!("build AnyTLS UDP stream target: {err}"))?;
    let stream_target_addr = anytls_link::socks_addr(&stream_target)
        .map_err(|err| format!("build AnyTLS UDP stream address: {err}"))?;
    write_tls_plain_all(
        &mut client,
        &anytls_link::frame(anytls_contract::CMD_PSH, 1, &stream_target_addr),
        "write AnyTLS UDP stream target",
    )?;
    let packet = anytls_link::packet_first_write(&original_dst.to_string(), payload)
        .map_err(|err| format!("build AnyTLS UDP packet write: {err}"))?;
    write_tls_plain_all(
        &mut client,
        &anytls_link::frame(anytls_contract::CMD_PSH, 1, &packet),
        "write AnyTLS UDP packet",
    )?;
    wait_anytls_udp_synack(&mut client)?;
    let response = read_anytls_udp_payload(&mut client)?;
    Ok(
        UdpExchangeResult::new(response, "frame-tls-udp-packet-stream-v1")
            .with_tls_underlay(tls_underlay),
    )
}

fn exchange_hysteria2_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    auth: &str,
    pin_sha256: &str,
    max_rx: u64,
) -> Result<UdpExchangeResult, String> {
    run_quic_udp_exchange("Hysteria2 UDP", async move {
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_hysteria2_pinned_client_config(pin_sha256.to_owned())
                .map_err(|err| format!("build Hysteria2 QUIC client config: {err}"))?,
        );
        let remote = resolve_proxy_udp_addr(proxy)?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect Hysteria2 QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await Hysteria2 QUIC connect: {err}"))?;
        let auth_report = authenticate_hysteria2_connection(connection.clone(), auth, max_rx)
            .await
            .map_err(|err| format!("authenticate Hysteria2 QUIC connection: {err}"))?;
        if !auth_report.auth_ok || !auth_report.udp_enabled {
            connection.close(0x101_u32.into(), b"resident hysteria2 udp auth failed");
            endpoint.wait_idle().await;
            return Err(format!(
                "Hysteria2 UDP unavailable after auth: status={} udp_enabled={}",
                auth_report.status, auth_report.udp_enabled
            ));
        }
        let packet_id = fastrand::u16(1..=u16::MAX);
        let session_id = fastrand::u32(1..=u32::MAX);
        let request =
            build_hysteria2_udp_message(session_id, packet_id, &original_dst.to_string(), payload)?;
        connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| format!("send Hysteria2 UDP datagram: {err}"))?;
        let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.read_datagram())
            .await
            .map_err(|_| "read Hysteria2 UDP datagram timeout".to_owned())?
            .map_err(|err| format!("read Hysteria2 UDP datagram: {err}"))?;
        let parsed = parse_hysteria2_udp_message(&response)?;
        connection.close(0_u32.into(), b"resident hysteria2 udp done");
        endpoint.wait_idle().await;
        Ok(
            UdpExchangeResult::new(parsed.payload, "quic-udp-datagram-v1")
                .with_quic_underlay("quinn-h3"),
        )
    })
}

fn exchange_tuic_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    uuid: &str,
    password: &str,
    alpn: &[String],
) -> Result<UdpExchangeResult, String> {
    run_quic_udp_exchange("TUIC UDP", async move {
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_tuic_runtime_client_config(alpn)
                .map_err(|err| format!("build TUIC QUIC client config: {err}"))?,
        );
        let remote = resolve_proxy_udp_addr(proxy)?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect TUIC QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await TUIC QUIC connect: {err}"))?;
        authenticate_tuic_connection(&connection, uuid, password)
            .await
            .map_err(|err| format!("authenticate TUIC QUIC connection: {err}"))?;
        let packet_id = fastrand::u16(1..=u16::MAX);
        let request = build_tuic_packet_frame(1, packet_id, &original_dst.to_string(), payload)?;
        connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| format!("send TUIC UDP datagram: {err}"))?;
        let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.read_datagram())
            .await
            .map_err(|_| "read TUIC UDP datagram timeout".to_owned())?
            .map_err(|err| format!("read TUIC UDP datagram: {err}"))?;
        let parsed = parse_tuic_packet_frame(&response)?;
        connection.close(0_u32.into(), b"resident tuic udp done");
        endpoint.wait_idle().await;
        Ok(
            UdpExchangeResult::new(parsed.payload, "quic-udp-datagram-v1")
                .with_quic_underlay("quinn"),
        )
    })
}

fn exchange_juicity_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    uuid: &str,
    password: &str,
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
) -> Result<UdpExchangeResult, String> {
    run_quic_udp_exchange("Juicity UDP", async move {
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_juicity_runtime_client_config(allow_insecure, pinned_certchain_sha256)
                .map_err(|err| format!("build Juicity QUIC client config: {err}"))?,
        );
        let remote = resolve_proxy_udp_addr(proxy)?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect Juicity QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await Juicity QUIC connect: {err}"))?;
        let (_auth_report, mut auth_stream) =
            authenticate_juicity_connection(&connection, uuid, password)
                .await
                .map_err(|err| format!("authenticate Juicity QUIC connection: {err}"))?;
        let request_frame = seal_stream_packet_frame(&original_dst.to_string(), payload)
            .map_err(|err| format!("build Juicity UDP stream packet: {err}"))?;
        let request =
            build_juicity_stream_packet_request(&original_dst.to_string(), &request_frame.encoded)?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|err| format!("open Juicity UDP stream: {err}"))?;
        send.write_all(&request)
            .await
            .map_err(|err| format!("write Juicity UDP stream packet: {err}"))?;
        send.finish()
            .map_err(|err| format!("finish Juicity UDP stream packet: {err}"))?;
        let response = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            read_juicity_stream_packet_response(&mut recv),
        )
        .await
        .map_err(|_| "read Juicity UDP stream response timeout".to_owned())??;
        let parsed = decode_stream_packet_frame(&response)
            .map_err(|err| format!("decode Juicity UDP stream packet: {err}"))?;
        let _ = auth_stream.finish().await;
        connection.close(0_u32.into(), b"resident juicity udp done");
        endpoint.wait_idle().await;
        Ok(
            UdpExchangeResult::new(parsed.payload, "quic-udp-stream-packet-v1")
                .with_quic_underlay("quinn-h3"),
        )
    })
}

async fn read_juicity_stream_packet_response(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        if let Ok(frame) = decode_stream_packet_frame(&response) {
            return Ok(frame.encoded);
        }
        if response.len() > 64 * 1024 {
            return Err(format!(
                "Juicity UDP stream response too large: {} bytes",
                response.len()
            ));
        }
        match recv
            .read(&mut buf)
            .await
            .map_err(|err| format!("read Juicity UDP stream response: {err}"))?
        {
            Some(0) => {}
            Some(read) => response.extend_from_slice(&buf[..read]),
            None => {
                return Err(
                    "Juicity UDP stream closed before a complete packet frame was decoded"
                        .to_owned(),
                );
            }
        }
    }
}

fn open_plain_proxy_tcp_stream(
    proxy: &ResidentProxyPlan,
    label: &str,
) -> Result<TcpStream, String> {
    let stream =
        open_direct_tcp_connection(&proxy_server_authority(proxy), proxy.mark, proxy.mptcp)
            .map_err(|err| format!("open {label} proxy TCP stream: {err}"))?
            .stream;
    stream
        .set_nonblocking(false)
        .map_err(|err| format!("set {label} proxy TCP blocking: {err}"))?;
    stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set {label} proxy TCP read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set {label} proxy TCP write timeout: {err}"))?;
    stream
        .set_nodelay(true)
        .map_err(|err| format!("set {label} proxy TCP_NODELAY: {err}"))?;
    Ok(stream)
}

fn proxy_server_authority(proxy: &ResidentProxyPlan) -> String {
    format!("{}:{}", proxy.server_host, proxy.server_port)
}

fn resolve_proxy_udp_socket_addr(proxy: &ResidentProxyPlan) -> Result<SocketAddr, String> {
    proxy_server_authority(proxy)
        .to_socket_addrs()
        .map_err(|err| format!("resolve UDP proxy {}: {err}", proxy_server_authority(proxy)))?
        .next()
        .ok_or_else(|| {
            format!(
                "resolve UDP proxy {}: no address",
                proxy_server_authority(proxy)
            )
        })
}

fn exchange_udp_datagram_with_proxy(
    proxy: &ResidentProxyPlan,
    request: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    let remote = resolve_proxy_udp_socket_addr(proxy)?;
    exchange_udp_datagram_to_addr(proxy, remote, request, label)
}

fn exchange_udp_datagram_to_addr(
    proxy: &ResidentProxyPlan,
    remote: SocketAddr,
    request: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    let bind = match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).map_err(|err| format!("bind {label} UDP socket: {err}"))?;
    if proxy.mark != 0 {
        set_socket_mark(socket.as_raw_fd(), proxy.mark)
            .map_err(|err| format!("set {label} UDP SO_MARK {}: {err}", proxy.mark))?;
    }
    socket
        .set_read_timeout(Some(RESIDENT_UDP_RESPONSE_TIMEOUT))
        .map_err(|err| format!("set {label} UDP read timeout: {err}"))?;
    socket
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set {label} UDP write timeout: {err}"))?;
    socket
        .send_to(request, remote)
        .map_err(|err| format!("send {label} UDP datagram: {err}"))?;
    let mut response = vec![0_u8; 64 * 1024];
    let (read, _) = socket
        .recv_from(&mut response)
        .map_err(|err| format!("receive {label} UDP datagram: {err}"))?;
    response.truncate(read);
    Ok(response)
}

fn socks5_udp_relay_addr(proxy: &ResidentProxyPlan, bind: &str) -> Result<SocketAddr, String> {
    let parsed =
        Socks5Address::parse(bind).map_err(|err| format!("parse SOCKS5 UDP bind: {err}"))?;
    let port = parsed.port();
    if port == 0 {
        return Err("SOCKS5 UDP associate returned port 0".to_owned());
    }
    let host = parsed.host();
    let authority = if host == "0.0.0.0" || host == "::" || host.is_empty() {
        format!("{}:{port}", proxy.server_host)
    } else {
        parsed.authority()
    };
    authority
        .to_socket_addrs()
        .map_err(|err| format!("resolve SOCKS5 UDP relay {authority}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve SOCKS5 UDP relay {authority}: no address"))
}

fn write_tls_plain_all(
    client: &mut VlessTlsClient,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    client.queue_plain(payload, label)?;
    flush_tls_writes_for_udp(client)
}

fn read_tls_plain_until<T, F>(
    client: &mut VlessTlsClient,
    label: &str,
    mut decode: F,
) -> Result<T, String>
where
    F: FnMut(&[u8]) -> Result<T, dae_outbound::OutboundError>,
{
    let started = Instant::now();
    let mut plaintext = Vec::new();
    let mut buf = [0_u8; 4096];
    let mut last_decode_error = "no data decoded yet".to_owned();
    loop {
        if started.elapsed() > RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err(format!(
                "{label}: timeout{}",
                format!(" after decode error: {last_decode_error}")
            ));
        }
        match decode(&plaintext) {
            Ok(value) => return Ok(value),
            Err(err) => last_decode_error = err.to_string(),
        }
        let _ = drive_tls_io_blocking(client);
        match client.read_plain(&mut buf) {
            Ok(0) => thread::sleep(RESIDENT_IDLE_SLEEP),
            Ok(read) => plaintext.extend_from_slice(&buf[..read]),
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(RESIDENT_IDLE_SLEEP);
            }
            Err(err) => return Err(format!("{label}: {err}")),
        }
    }
}

fn wait_anytls_udp_synack(client: &mut VlessTlsClient) -> Result<(), String> {
    loop {
        let frame = read_anytls_frame_blocking(client)?;
        if frame.cmd == anytls_contract::CMD_SYNACK && frame.sid == 1 && frame.data.is_empty() {
            return Ok(());
        }
        if frame.cmd == anytls_contract::CMD_ALERT {
            return Err(format!(
                "AnyTLS UDP alert before SYNACK: {} bytes",
                frame.data.len()
            ));
        }
        if matches!(
            frame.cmd,
            anytls_contract::CMD_WASTE
                | anytls_contract::CMD_SERVER_SETTINGS
                | anytls_contract::CMD_UPDATE_PADDING
                | anytls_contract::CMD_HEART_RESPONSE
        ) {
            continue;
        }
        return Err(format!(
            "unexpected AnyTLS UDP frame before SYNACK: cmd={} sid={} len={}",
            frame.cmd,
            frame.sid,
            frame.data.len()
        ));
    }
}

fn read_anytls_udp_payload(client: &mut VlessTlsClient) -> Result<Vec<u8>, String> {
    loop {
        let frame = read_anytls_frame_blocking(client)?;
        if frame.cmd == anytls_contract::CMD_PSH && frame.sid == 1 {
            let packet = dae_outbound::anytls::decode_packet_next_write(&frame.data)
                .map_err(|err| format!("decode AnyTLS UDP response packet: {err}"))?;
            return Ok(packet.payload);
        }
        if frame.cmd == anytls_contract::CMD_ALERT {
            return Err(format!(
                "AnyTLS UDP alert frame: {} bytes",
                frame.data.len()
            ));
        }
        if matches!(
            frame.cmd,
            anytls_contract::CMD_WASTE
                | anytls_contract::CMD_SERVER_SETTINGS
                | anytls_contract::CMD_UPDATE_PADDING
                | anytls_contract::CMD_HEART_RESPONSE
        ) {
            continue;
        }
        return Err(format!(
            "unexpected AnyTLS UDP response frame: cmd={} sid={} len={}",
            frame.cmd,
            frame.sid,
            frame.data.len()
        ));
    }
}

fn read_anytls_frame_blocking(client: &mut VlessTlsClient) -> Result<AnyTlsRuntimeFrame, String> {
    let mut header = [0_u8; anytls_contract::HEADER_OVERHEAD_SIZE];
    read_tls_plain_exact(client, &mut header, "read AnyTLS UDP frame header")?;
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0_u8; len];
    read_tls_plain_exact(client, &mut data, "read AnyTLS UDP frame data")?;
    Ok(AnyTlsRuntimeFrame {
        cmd: header[0],
        sid: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        data,
    })
}

struct AnyTlsRuntimeFrame {
    cmd: u8,
    sid: u32,
    data: Vec<u8>,
}

fn read_tls_plain_exact(
    client: &mut VlessTlsClient,
    mut out: &mut [u8],
    label: &str,
) -> Result<(), String> {
    let started = Instant::now();
    while !out.is_empty() {
        if started.elapsed() > RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err(format!("{label}: timeout"));
        }
        let _ = drive_tls_io_blocking(client);
        match client.read_plain(out) {
            Ok(0) => thread::sleep(RESIDENT_IDLE_SLEEP),
            Ok(read) => {
                let tmp = out;
                out = &mut tmp[read..];
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(RESIDENT_IDLE_SLEEP);
            }
            Err(err) => return Err(format!("{label}: {err}")),
        }
    }
    Ok(())
}

fn run_quic_udp_exchange<F>(label: &str, future: F) -> Result<UdpExchangeResult, String>
where
    F: std::future::Future<Output = Result<UdpExchangeResult, String>>,
{
    let runtime = runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("build {label} runtime: {err}"))?;
    runtime.block_on(async {
        time::timeout(
            RESIDENT_CONNECT_TIMEOUT + RESIDENT_UDP_RESPONSE_TIMEOUT,
            future,
        )
        .await
        .map_err(|_| format!("{label} timeout"))?
    })
}

#[allow(dead_code)]
struct Hysteria2UdpMessage {
    session_id: u32,
    packet_id: u16,
    payload: Vec<u8>,
}

fn build_hysteria2_udp_message(
    session_id: u32,
    packet_id: u16,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if payload.is_empty() || payload.len() > 4096 {
        return Err(format!(
            "invalid Hysteria2 UDP payload length: {}",
            payload.len()
        ));
    }
    let mut out = Vec::with_capacity(16 + target.len() + payload.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(0);
    out.push(1);
    append_quic_varint(&mut out, target.len() as u64)?;
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn parse_hysteria2_udp_message(input: &[u8]) -> Result<Hysteria2UdpMessage, String> {
    if input.len() < 9 {
        return Err("short Hysteria2 UDP message".to_owned());
    }
    let session_id = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let frag_id = input[6];
    let frag_count = input[7];
    let (addr_len, mut offset) = read_quic_varint(input, 8)?;
    let addr_len =
        usize::try_from(addr_len).map_err(|_| "Hysteria2 UDP address too large".to_owned())?;
    if frag_id != 0 || frag_count != 1 {
        return Err(format!(
            "fragmented Hysteria2 UDP response is unsupported: frag_id={frag_id} frag_count={frag_count}"
        ));
    }
    if addr_len == 0 || input.len() <= offset + addr_len {
        return Err("invalid Hysteria2 UDP address length".to_owned());
    }
    offset += addr_len;
    Ok(Hysteria2UdpMessage {
        session_id,
        packet_id,
        payload: input[offset..].to_vec(),
    })
}

#[allow(dead_code)]
struct TuicPacketFrame {
    assoc_id: u16,
    packet_id: u16,
    payload: Vec<u8>,
}

fn build_tuic_packet_frame(
    assoc_id: u16,
    packet_id: u16,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return Err(format!(
            "invalid TUIC UDP payload length: {}",
            payload.len()
        ));
    }
    let target = Socks5Address::parse(target).map_err(|err| format!("parse TUIC target: {err}"))?;
    let mut out = Vec::with_capacity(10 + payload.len() + 32);
    out.push(0x05);
    out.push(0x02);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    write_tuic_address(&target, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn parse_tuic_packet_frame(input: &[u8]) -> Result<TuicPacketFrame, String> {
    if input.len() < 10 {
        return Err("short TUIC packet frame".to_owned());
    }
    if input[1] != 0x02 {
        return Err(format!("bad TUIC packet command type: {:#x}", input[1]));
    }
    let assoc_id = u16::from_be_bytes([input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let frag_total = input[6];
    let frag_id = input[7];
    let size = u16::from_be_bytes([input[8], input[9]]) as usize;
    if frag_total != 1 || frag_id != 0 {
        return Err(format!(
            "fragmented TUIC UDP response is unsupported: frag_total={frag_total} frag_id={frag_id}"
        ));
    }
    let offset = read_tuic_address(input, 10)?;
    let payload_end = offset + size;
    if input.len() != payload_end {
        return Err("TUIC packet payload length mismatch".to_owned());
    }
    Ok(TuicPacketFrame {
        assoc_id,
        packet_id,
        payload: input[offset..payload_end].to_vec(),
    })
}

fn write_tuic_address(address: &Socks5Address, out: &mut Vec<u8>) -> Result<(), String> {
    match address {
        Socks5Address::Ipv4 { addr, port } => {
            out.push(1);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5Address::Ipv6 { addr, port } => {
            out.push(2);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5Address::Domain { hostname, port } => {
            if hostname.len() > u8::MAX as usize {
                return Err("TUIC domain address too long".to_owned());
            }
            out.push(0);
            out.push(hostname.len() as u8);
            out.extend_from_slice(hostname.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn read_tuic_address(input: &[u8], offset: usize) -> Result<usize, String> {
    let Some(&atyp) = input.get(offset) else {
        return Err("missing TUIC address type".to_owned());
    };
    let mut cursor = offset + 1;
    match atyp {
        0 => {
            let Some(&len) = input.get(cursor) else {
                return Err("missing TUIC domain length".to_owned());
            };
            cursor += 1 + len as usize;
        }
        1 => cursor += 4,
        2 => cursor += 16,
        255 => return Ok(cursor),
        value => return Err(format!("unsupported TUIC address type: {value}")),
    }
    if input.len() < cursor + 2 {
        return Err("short TUIC address port".to_owned());
    }
    Ok(cursor + 2)
}

fn build_juicity_stream_packet_request(target: &str, frame: &[u8]) -> Result<Vec<u8>, String> {
    let metadata = dae_outbound::trojan::TrojanMetadata::parse("udp", target)
        .map_err(|err| format!("build Juicity UDP metadata: {err}"))?;
    let metadata = metadata
        .encode()
        .map_err(|err| format!("encode Juicity UDP metadata: {err}"))?;
    let mut out = Vec::with_capacity(1 + metadata.len() + frame.len());
    out.push(3);
    out.extend_from_slice(&metadata);
    out.extend_from_slice(frame);
    Ok(out)
}

fn append_quic_varint(out: &mut Vec<u8>, value: u64) -> Result<(), String> {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => {
            out.push(((value >> 8) as u8) | 0x40);
            out.push(value as u8);
        }
        16_384..=1_073_741_823 => {
            out.push(((value >> 24) as u8) | 0x80);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        _ => return Err(format!("QUIC varint too large: {value}")),
    }
    Ok(())
}

fn read_quic_varint(input: &[u8], offset: usize) -> Result<(u64, usize), String> {
    let Some(&first) = input.get(offset) else {
        return Err("missing QUIC varint".to_owned());
    };
    match first >> 6 {
        0 => Ok(((first & 0x3f) as u64, offset + 1)),
        1 => {
            if input.len() < offset + 2 {
                return Err("short two-byte QUIC varint".to_owned());
            }
            Ok((
                (((first & 0x3f) as u64) << 8) | input[offset + 1] as u64,
                offset + 2,
            ))
        }
        2 => {
            if input.len() < offset + 4 {
                return Err("short four-byte QUIC varint".to_owned());
            }
            Ok((
                (((first & 0x3f) as u64) << 24)
                    | ((input[offset + 1] as u64) << 16)
                    | ((input[offset + 2] as u64) << 8)
                    | input[offset + 3] as u64,
                offset + 4,
            ))
        }
        _ => Err("eight-byte QUIC varint is not needed for UDP address length".to_owned()),
    }
}

fn flush_tls_writes_for_udp(client: &mut VlessTlsClient) -> Result<(), String> {
    let stop = AtomicBool::new(false);
    super::client::flush_tls_writes(client, &stop)
}

fn build_vless_udp_request(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let key = proxy.vless_key()?;
    if proxy.flow != XTLS_RPRX_VISION {
        return packet::first_write_bytes(
            &key,
            &proxy.flow,
            "udp",
            &original_dst.to_string(),
            false,
            payload,
        )
        .map_err(|err| format!("build VLESS UDP request: {err}"));
    }
    let mut request = packet::request_header(&key, &proxy.flow, "tcp", XUDP_MUX_TARGET, true, &[])
        .map_err(|err| format!("build VLESS Vision XUDP mux request header: {err}"))?;
    let frame = xudp_frame(original_dst, payload)?;
    let mut uuid_sent = false;
    request.extend_from_slice(&vision_padding_block(
        &frame,
        VISION_COMMAND_CONTINUE,
        key,
        &mut uuid_sent,
        false,
    ));
    Ok(request)
}

fn xudp_frame(original_dst: SocketAddrV4, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err(format!("XUDP payload too large: {} bytes", payload.len()));
    }
    let mut metadata = Vec::with_capacity(2 + 3 + 2 + 1 + 4);
    metadata.extend_from_slice(&0_u16.to_be_bytes());
    metadata.push(XUDP_COMMAND_NEW);
    metadata.push(XUDP_OPTION_DATA);
    metadata.push(XUDP_NETWORK_UDP);
    metadata.extend_from_slice(&original_dst.port().to_be_bytes());
    metadata.push(1);
    metadata.extend_from_slice(&original_dst.ip().octets());
    if metadata.len() > u16::MAX as usize {
        return Err(format!("XUDP metadata too large: {} bytes", metadata.len()));
    }
    let mut frame = Vec::with_capacity(2 + metadata.len() + 2 + payload.len());
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn send_udp_reply(
    original_dst: SocketAddrV4,
    peer: SocketAddrV4,
    payload: &[u8],
) -> Result<(), String> {
    let reply = open_transparent_udp_socket_bound_in_netns(PRODUCTION_NETNS, original_dst)
        .map_err(|err| format!("open transparent UDP reply socket: {err}"))?;
    reply
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| format!("set UDP reply timeout: {err}"))?;
    reply
        .send_to(payload, peer)
        .map_err(|err| format!("send transparent UDP reply: {err}"))?;
    Ok(())
}

fn read_vless_udp_response(
    client: &mut VlessTlsClient,
    flow: &str,
    user_uuid: [u8; 16],
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let mut plaintext = Vec::new();
    let mut buf = [0_u8; 2048];
    loop {
        if let Some(payload) = parse_vless_udp_response(&plaintext, flow, user_uuid)? {
            return Ok(payload);
        }
        if started.elapsed() > RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err("VLESS UDP response timeout".to_owned());
        }
        let _ = drive_tls_io_blocking(client);
        loop {
            match client.read_plain(&mut buf) {
                Ok(0) => break,
                Ok(read) => plaintext.extend_from_slice(&buf[..read]),
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(err) => return Err(format!("read VLESS UDP plaintext: {err}")),
            }
        }
        thread::sleep(RESIDENT_IDLE_SLEEP);
    }
}

fn parse_vless_udp_response(
    input: &[u8],
    flow: &str,
    user_uuid: [u8; 16],
) -> Result<Option<Vec<u8>>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    if input[0] != VLESS_RESPONSE_VERSION {
        return Err(format!("unexpected VLESS response version: {}", input[0]));
    }
    let header_len = 2 + input[1] as usize;
    if input.len() < header_len {
        return Ok(None);
    }
    if flow == XTLS_RPRX_VISION {
        if input.len() == header_len {
            return Ok(None);
        }
        let mut unpadder = VisionUnpadder::new(user_uuid);
        let payload = unpadder.consume(&input[header_len..])?;
        if payload.is_empty() && !matches!(unpadder.state, VisionUnpadState::Raw) {
            return Ok(None);
        }
        return parse_xudp_response_payload(&payload);
    }
    if input.len() < header_len + 2 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([input[header_len], input[header_len + 1]]) as usize;
    if input.len() < header_len + 2 + payload_len {
        return Ok(None);
    }
    Ok(Some(
        input[header_len + 2..header_len + 2 + payload_len].to_vec(),
    ))
}

fn parse_xudp_response_payload(input: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    let metadata_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    let payload_len_offset = 2 + metadata_len;
    if input.len() < payload_len_offset + 2 {
        return Ok(None);
    }
    let payload_len =
        u16::from_be_bytes([input[payload_len_offset], input[payload_len_offset + 1]]) as usize;
    let payload_offset = payload_len_offset + 2;
    if input.len() < payload_offset + payload_len {
        return Ok(None);
    }
    Ok(Some(
        input[payload_offset..payload_offset + payload_len].to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::super::plan::ResidentProxyProtocolPlan;
    use super::*;

    #[test]
    fn resident_vless_udp_response_parser_handles_vision_payload() {
        let key = [1_u8; 16];
        let frame = xudp_frame(
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
            &[0x12, 0x34],
        )
        .unwrap();
        let mut response = vec![0, 0];
        response.extend_from_slice(&key);
        response.push(VISION_COMMAND_CONTINUE);
        response.extend_from_slice(&(frame.len() as u16).to_be_bytes());
        response.extend_from_slice(&3_u16.to_be_bytes());
        response.extend_from_slice(&frame);
        response.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let payload = parse_vless_udp_response(&response, XTLS_RPRX_VISION, key)
            .unwrap()
            .unwrap();
        assert_eq!(payload, [0x12, 0x34]);
    }

    #[test]
    fn resident_vless_vision_udp_request_uses_xudp_mux_target() {
        let proxy = ResidentProxyPlan {
            protocol: "vless".to_owned(),
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "vless_live".to_owned(),
            server_host: "156.246.90.2".to_owned(),
            server_port: 443,
            server_name: "office.example".to_owned(),
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            flow: XTLS_RPRX_VISION.to_owned(),
            net: "tcp".to_owned(),
            tls: "tls".to_owned(),
            allow_insecure: false,
            utls_fingerprint: None,
            handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [9_u8; 16] },
            mark: 0,
            mptcp: false,
        };
        let request = build_vless_udp_request(
            &proxy,
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
            &[0xde, 0xad],
        )
        .unwrap();
        assert_eq!(request[0], VLESS_RESPONSE_VERSION);
        assert_eq!(&request[1..17], &[9_u8; 16]);
        assert!(request.windows(16).any(|window| window == [9_u8; 16]));
        assert!(request.windows(2).any(|window| window == [0xde, 0xad]));
    }

    #[test]
    fn resident_udp_dispatch_fails_closed_for_protocol_closed_handler() {
        let proxy = ResidentProxyPlan {
            protocol: "http-proxy".to_owned(),
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "plain-http-connect".to_owned(),
            server_host: "127.0.0.1".to_owned(),
            server_port: 8080,
            server_name: String::new(),
            alpn: vec![],
            flow: String::new(),
            net: "tcp".to_owned(),
            tls: String::new(),
            allow_insecure: false,
            utls_fingerprint: None,
            handler: ResidentProxyProtocolPlan::HttpProxyTcp {
                username: String::new(),
                password: String::new(),
            },
            mark: 0,
            mptcp: false,
        };
        let err = exchange_proxy_udp(
            &proxy,
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
            &[0xde, 0xad],
        )
        .unwrap_err();
        assert!(err.contains("unsupported_udp_handler"));
        assert!(err.contains("no UDP relay semantics"));
        assert!(err.contains("without Go fallback"));
        assert!(err.contains("http-proxy-tcp"));
        assert!(err.contains("http-proxy"));
    }

    #[test]
    fn resident_dns_udp_check_accepts_a_answer() {
        let id = 0x1234;
        let query = build_dns_a_query(id, "connectivitycheck.gstatic.com.").unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[142, 250, 72, 238]);
        dns_a_response_has_answer(id, &response).unwrap();
    }

    #[test]
    fn resident_dns_udp_check_rejects_response_without_a_answer() {
        let id = 0x3456;
        let query = build_dns_a_query(id, "connectivitycheck.gstatic.com.").unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&28_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u32.to_be_bytes());
        response.extend_from_slice(&16_u16.to_be_bytes());
        response.extend_from_slice(&[0; 16]);
        let err = dns_a_response_has_answer(id, &response).unwrap_err();
        assert!(err.contains("no A answer"));
    }

    #[test]
    fn resident_udp_quic_wire_helpers_roundtrip() {
        let target = "203.0.113.53:5353";
        let payload = b"resident-udp-live-matrix";

        let hy2 = build_hysteria2_udp_message(0x1122_3344, 0x5566, target, payload).unwrap();
        let parsed_hy2 = parse_hysteria2_udp_message(&hy2).unwrap();
        assert_eq!(parsed_hy2.session_id, 0x1122_3344);
        assert_eq!(parsed_hy2.packet_id, 0x5566);
        assert_eq!(parsed_hy2.payload, payload);

        let tuic = build_tuic_packet_frame(7, 9, target, payload).unwrap();
        let parsed_tuic = parse_tuic_packet_frame(&tuic).unwrap();
        assert_eq!(parsed_tuic.assoc_id, 7);
        assert_eq!(parsed_tuic.packet_id, 9);
        assert_eq!(parsed_tuic.payload, payload);

        let juicity_frame = seal_stream_packet_frame(target, payload).unwrap();
        let juicity_request =
            build_juicity_stream_packet_request(target, &juicity_frame.encoded).unwrap();
        assert_eq!(juicity_request[0], 3);
        let (initial_address, initial_metadata_len) =
            Socks5Address::decode(&juicity_request[1..]).unwrap();
        assert_eq!(initial_address.authority(), target);
        let decoded =
            decode_stream_packet_frame(&juicity_request[1 + initial_metadata_len..]).unwrap();
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.payload, payload);
    }
}
