use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use dae_outbound::vless::packet;
use serde_json::{Value, json};

use super::client::{VlessTlsClient, drive_tls_io_record_aware, open_vless_tls_client};
use super::events::append_event;
use super::io::write_all_nonblocking;
use super::plan::ResidentProxyPlan;
use super::vision::{VisionUnpadder, drain_vision_uplink_until_direct};
use super::{
    RESIDENT_IDLE_SLEEP, RESIDENT_TCP_ACCEPT_SLEEP, RESIDENT_TCP_IDLE_TIMEOUT,
    TLS_RECORD_MAX_PAYLOAD_LEN, VLESS_RESPONSE_VERSION, XTLS_RPRX_VISION,
};

pub(super) fn resident_tcp_accept_loop(
    listener: TcpListener,
    proxy: Arc<ResidentProxyPlan>,
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
        json!({"event": "tcp_worker_started", "proxy_group": proxy.group_name, "node_tag": proxy.node_tag}),
    );
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let proxy = Arc::clone(&proxy);
                let stop = Arc::clone(&stop);
                let event_file = event_file.clone();
                let event_lock = Arc::clone(&event_lock);
                thread::spawn(move || {
                    let result = handle_tcp_connection(stream, peer.to_string(), proxy, stop);
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
    peer: String,
    proxy: Arc<ResidentProxyPlan>,
    stop: Arc<AtomicBool>,
) -> Result<Value, String> {
    let original_dst = match inbound
        .local_addr()
        .map_err(|err| format!("read original TCP destination: {err}"))?
    {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "resident VLESS dataplane currently supports IPv4 original destinations only: {addr}"
            ));
        }
    };
    inbound
        .set_nonblocking(true)
        .map_err(|err| format!("set inbound nonblocking: {err}"))?;
    inbound
        .set_nodelay(true)
        .map_err(|err| format!("set inbound TCP_NODELAY: {err}"))?;
    let mut client = open_vless_tls_client(&proxy)?;
    client
        .tcp
        .set_nonblocking(true)
        .map_err(|err| format!("set proxy tcp nonblocking: {err}"))?;
    let request = packet::first_write_bytes(
        &proxy.key,
        &proxy.flow,
        "tcp",
        &original_dst.to_string(),
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS TCP request: {err}"))?;
    client
        .conn
        .writer()
        .write_all(&request)
        .map_err(|err| format!("queue VLESS TCP request: {err}"))?;
    relay_tcp_over_vless_tls(&mut inbound, &mut client, &stop, &proxy.flow, proxy.key).map(
        |stats| {
            json!({
                "event": "tcp_connection_finished",
                "peer": peer,
                "original_dst": original_dst.to_string(),
                "proxy_group": proxy.group_name,
                "node_tag": proxy.node_tag,
                "bytes_client_to_proxy": stats.client_to_proxy,
                "bytes_proxy_to_client": stats.proxy_to_client,
                "response_header_stripped": stats.response_header_stripped,
                "vision_unpadding_blocks": stats.vision_unpadding_blocks,
                "vision_direct_command_seen": stats.vision_direct_command_seen,
            })
        },
    )
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
) -> Result<RelayStats, String> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let mut vision = (flow == XTLS_RPRX_VISION).then(|| VisionUnpadder::new(user_uuid));
    let mut downlink_direct = false;
    let mut uplink_direct = false;
    let mut uplink_uuid_sent = false;
    let mut pending_direct_uplink = Vec::<u8>::new();
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];
    while !stop.load(Ordering::Relaxed) {
        let mut progressed = false;
        if !inbound_closed {
            match inbound.read(&mut inbound_buf) {
                Ok(0) => {
                    inbound_closed = true;
                    if !uplink_direct {
                        client.conn.send_close_notify();
                    }
                    progressed = true;
                }
                Ok(read) => {
                    if uplink_direct {
                        write_all_nonblocking(
                            &mut client.tcp,
                            &inbound_buf[..read],
                            stop,
                            "write client payload to VLESS direct TCP",
                        )?;
                    } else if downlink_direct {
                        pending_direct_uplink.extend_from_slice(&inbound_buf[..read]);
                        if pending_direct_uplink.len() > TLS_RECORD_MAX_PAYLOAD_LEN * 4 {
                            return Err(format!(
                                "pending VLESS Vision uplink direct payload did not form complete TLS application-data records: {} bytes",
                                pending_direct_uplink.len()
                            ));
                        }
                        drain_vision_uplink_until_direct(
                            &mut pending_direct_uplink,
                            client,
                            stop,
                            user_uuid,
                            &mut uplink_uuid_sent,
                            &mut uplink_direct,
                        )?;
                    } else {
                        client
                            .conn
                            .writer()
                            .write_all(&inbound_buf[..read])
                            .map_err(|err| format!("queue client payload to VLESS TLS: {err}"))?;
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
                        "write VLESS direct payload to client",
                    )?;
                    stats.proxy_to_client += read;
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    // No direct payload available yet.
                }
                Err(err) => return Err(format!("read VLESS direct TCP: {err}")),
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
                            stats.vision_unpadding_blocks = vision.completed_blocks;
                            stats.vision_direct_command_seen = vision.direct_command_seen;
                            downlink_direct = vision.direct_command_seen;
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

    #[test]
    fn resident_vless_response_stripper_handles_split_header() {
        let mut stripper = VlessResponseStripper::default();
        assert!(stripper.consume(&[0]).unwrap().is_empty());
        assert!(stripper.consume(&[3, b'a']).unwrap().is_empty());
        assert_eq!(stripper.consume(b"bcOK").unwrap(), b"OK");
        assert!(stripper.done);
        assert_eq!(stripper.consume(b"NEXT").unwrap(), b"NEXT");
    }
}
