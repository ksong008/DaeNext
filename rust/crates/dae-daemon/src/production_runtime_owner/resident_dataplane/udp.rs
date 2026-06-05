use std::io::ErrorKind;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use dae_ebpf_support::open_transparent_udp_socket_bound_in_netns;
use dae_outbound::vless::packet;
use serde_json::json;

use super::super::PRODUCTION_NETNS;
use super::super::udp_io::{UdpOriginalDstPacket, recv_udp_with_original_dst};
use super::client::{VlessTlsClient, drive_tls_io_blocking, open_vless_tls_client};
use super::dns::{ResidentDnsPlan, handle_resident_dns_udp};
use super::events::append_event;
use super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::vision::{VisionUnpadState, VisionUnpadder, vision_padding_block};
use super::{
    RESIDENT_IDLE_SLEEP, RESIDENT_UDP_RESPONSE_TIMEOUT, ResidentDataplaneMetrics,
    VISION_COMMAND_CONTINUE, VLESS_RESPONSE_VERSION, XTLS_RPRX_VISION, XUDP_COMMAND_NEW,
    XUDP_MUX_TARGET, XUDP_NETWORK_UDP, XUDP_OPTION_DATA,
};

pub(super) fn resident_udp_loop(
    socket: std::net::UdpSocket,
    proxy: Arc<ResidentProxyPlan>,
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
            "proxy_group": proxy.group_name,
            "node_tag": proxy.node_tag,
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
        let proxy = Arc::clone(&proxy);
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
                    proxy,
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

fn handle_udp_packet(
    proxy: Arc<ResidentProxyPlan>,
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
    let exchange = if original_dst.port() == 53 {
        handle_resident_dns_udp(&dns, original_dst, &packet.payload)
            .map(|response| ("udp_dns_packet_finished", response))
    } else {
        exchange_proxy_udp(&proxy, original_dst, &packet.payload)
            .map(|response| ("udp_packet_finished", response))
    };
    match exchange {
        Ok((event, response)) => match send_udp_reply(original_dst, peer, &response) {
            Ok(()) => {
                metrics.add_download(response.len());
                append_event(
                    &event_file,
                    &event_lock,
                    json!({
                        "event": event,
                        "peer": peer.to_string(),
                        "original_dst": original_dst.to_string(),
                        "request_len": request_len,
                        "response_len": response.len(),
                        "proxy_group": proxy.group_name,
                        "group_policy": proxy.group_policy,
                        "node_tag": proxy.node_tag,
                        "network": "udp4",
                        "outbound": proxy.group_name,
                        "policy": proxy.group_policy,
                        "dialer": proxy.node_tag,
                        "sniffed": "",
                        "ip": original_dst.to_string(),
                    }),
                )
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
) -> Result<Vec<u8>, String> {
    match &proxy.handler {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => {
            exchange_vless_udp(proxy, original_dst, payload)
        }
        _ => Err(format!(
            "unsupported_udp_handler: resident UDP adapter dispatch selected handler {} for protocol {}; this handler is not wired for UDP yet and is fail-closed",
            resident_udp_handler_name(&proxy.handler),
            proxy.protocol
        )),
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
) -> Result<Vec<u8>, String> {
    let key = proxy.vless_key()?;
    let mut client = open_vless_tls_client(proxy)?;
    let request = build_vless_udp_request(proxy, original_dst, payload)?;
    client.queue_plain(&request, "queue VLESS UDP request")?;
    flush_tls_writes_for_udp(&mut client)?;
    read_vless_udp_response(&mut client, &proxy.flow, key)
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
    fn resident_udp_dispatch_fails_closed_for_unwired_handler() {
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
        assert!(err.contains("http-proxy-tcp"));
        assert!(err.contains("http-proxy"));
    }
}
