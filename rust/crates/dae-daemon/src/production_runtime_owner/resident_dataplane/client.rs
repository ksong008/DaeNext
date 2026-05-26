use std::io::{Cursor, ErrorKind, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Instant;

use dae_datapath::{TcpDirectDialOptions, magic_tcp_connect};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};

use super::plan::ResidentProxyPlan;
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_IDLE_SLEEP, TLS_RECORD_HEADER_LEN,
    TLS_RECORD_MAX_PAYLOAD_LEN,
};

pub(super) struct VlessTlsClient {
    pub(super) tcp: TcpStream,
    pub(super) conn: ClientConnection,
    pub(super) tls_records: TlsRecordReader,
}

#[derive(Default)]
pub(super) struct TlsRecordReader {
    header: Vec<u8>,
    body: Vec<u8>,
    body_len: Option<usize>,
}

impl TlsRecordReader {
    fn read_one(
        &mut self,
        conn: &mut ClientConnection,
        tcp: &mut TcpStream,
    ) -> Result<bool, String> {
        let mut progressed = false;
        while self.header.len() < TLS_RECORD_HEADER_LEN {
            let mut byte = [0_u8; 1];
            match tcp.read(&mut byte) {
                Ok(0) => return Ok(progressed),
                Ok(_) => {
                    self.header.push(byte[0]);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(progressed);
                }
                Err(err) => return Err(format!("read VLESS TLS record header: {err}")),
            }
        }
        let record_type = self.header[0];
        if !matches!(record_type, 20 | 21 | 22 | 23) {
            return Err(format!(
                "unexpected VLESS TLS record type before Vision direct switch: {record_type}"
            ));
        }
        let body_len = *self
            .body_len
            .get_or_insert_with(|| u16::from_be_bytes([self.header[3], self.header[4]]) as usize);
        if body_len > TLS_RECORD_MAX_PAYLOAD_LEN {
            return Err(format!("VLESS TLS record too large: {body_len} bytes"));
        }
        while self.body.len() < body_len {
            let need = body_len - self.body.len();
            let mut buf = [0_u8; 4096];
            let want = need.min(buf.len());
            match tcp.read(&mut buf[..want]) {
                Ok(0) => return Ok(progressed),
                Ok(read) => {
                    self.body.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(progressed);
                }
                Err(err) => return Err(format!("read VLESS TLS record body: {err}")),
            }
        }
        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + body_len);
        record.extend_from_slice(&self.header);
        record.extend_from_slice(&self.body);
        self.header.clear();
        self.body.clear();
        self.body_len = None;

        let mut cursor = Cursor::new(record);
        conn.read_tls(&mut cursor)
            .map_err(|err| format!("feed VLESS TLS record: {err}"))?;
        conn.process_new_packets()
            .map_err(|err| format!("process VLESS TLS record: {err}"))?;
        Ok(true)
    }
}

pub(super) fn open_vless_tls_client(proxy: &ResidentProxyPlan) -> Result<VlessTlsClient, String> {
    let target = resolve_proxy_addr(proxy)?;
    let mut connected = magic_tcp_connect(
        target,
        &TcpDirectDialOptions {
            mark: proxy.mark,
            mptcp: proxy.mptcp,
            timeout: RESIDENT_CONNECT_TIMEOUT,
        },
    )
    .map_err(|err| format!("connect VLESS server {target}: {err}"))?;
    connected
        .stream
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VLESS TCP read timeout: {err}"))?;
    connected
        .stream
        .set_write_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VLESS TCP write timeout: {err}"))?;
    connected
        .stream
        .set_nodelay(true)
        .map_err(|err| format!("set VLESS TCP_NODELAY: {err}"))?;
    let config = vless_client_config(proxy)?;
    let server_name = ServerName::try_from(proxy.server_name.clone())
        .map_err(|err| format!("invalid VLESS TLS server name {}: {err}", proxy.server_name))?;
    let mut conn = ClientConnection::new(config, server_name)
        .map_err(|err| format!("create VLESS TLS client: {err}"))?;
    drive_tls_io_blocking(&mut conn, &mut connected.stream)?;
    Ok(VlessTlsClient {
        tcp: connected.stream,
        conn,
        tls_records: TlsRecordReader::default(),
    })
}

fn vless_client_config(proxy: &ResidentProxyPlan) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = proxy
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

fn resolve_proxy_addr(proxy: &ResidentProxyPlan) -> Result<SocketAddrV4, String> {
    if let Ok(addr) = proxy.server_host.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(addr, proxy.server_port));
    }
    (proxy.server_host.as_str(), proxy.server_port)
        .to_socket_addrs()
        .map_err(|err| {
            format!(
                "resolve VLESS server {}:{}: {err}",
                proxy.server_host, proxy.server_port
            )
        })?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            format!(
                "resolve VLESS server {}:{} returned no IPv4 address",
                proxy.server_host, proxy.server_port
            )
        })
}

pub(super) fn drive_tls_io_record_aware(client: &mut VlessTlsClient) -> Result<bool, String> {
    let mut progressed = false;
    while client.conn.wants_write() {
        match client.conn.write_tls(&mut client.tcp) {
            Ok(0) => break,
            Ok(_) => progressed = true,
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                break;
            }
            Err(err) => return Err(format!("write VLESS TLS record: {err}")),
        }
    }
    if client.conn.wants_read() {
        progressed |= client
            .tls_records
            .read_one(&mut client.conn, &mut client.tcp)?;
    }
    Ok(progressed)
}

pub(super) fn flush_tls_writes(
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
) -> Result<(), String> {
    let started = Instant::now();
    while client.conn.wants_write() && !stop.load(Ordering::Relaxed) {
        match client.conn.write_tls(&mut client.tcp) {
            Ok(0) => return Err("flush VLESS TLS writes: wrote zero bytes".to_owned()),
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if started.elapsed() > RESIDENT_CONNECT_TIMEOUT {
                    return Err("flush VLESS TLS writes timeout".to_owned());
                }
                thread::sleep(RESIDENT_IDLE_SLEEP);
            }
            Err(err) => return Err(format!("flush VLESS TLS writes: {err}")),
        }
    }
    Ok(())
}

pub(super) fn drive_tls_io_blocking(
    conn: &mut ClientConnection,
    tcp: &mut TcpStream,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match conn.complete_io(tcp) {
            Ok(_) if !conn.is_handshaking() && !conn.wants_write() => return Ok(()),
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) && started.elapsed() <= RESIDENT_CONNECT_TIMEOUT => {}
            Err(err) => return Err(format!("drive VLESS TLS handshake: {err}")),
        }
        if started.elapsed() > RESIDENT_CONNECT_TIMEOUT {
            return Err("VLESS TLS handshake timeout".to_owned());
        }
    }
}
