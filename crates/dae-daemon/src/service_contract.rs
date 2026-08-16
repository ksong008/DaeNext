use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use dae_config::Config;
use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR, RELOAD_PROCESSING, RELOAD_SEND};
use serde_json::{Value, json};

use crate::config_validate::load_config_file;
use crate::production_runtime_owner::{
    ResidentProductionRuntime, configured_lan_ifaces, configured_wan_ifaces,
    start_resident_production_runtime_with_asset_dirs, validate_resident_runtime_interfaces,
};

mod types;
pub use self::types::*;
mod base_capabilities;
pub use self::base_capabilities::*;
mod datapath_capabilities;
use self::datapath_capabilities::*;
mod outbound_fingerprint;
use self::outbound_fingerprint::*;
mod outbound_matrix;
use self::outbound_matrix::*;
mod source_shapes;
use self::source_shapes::*;
mod resident_live_adapter;
use self::resident_live_adapter::*;
mod resident_service;
pub use self::resident_service::*;

const NETWORK_WAIT_LINKS: &[&str] = &[
    "http://edge.microsoft.com/captiveportal/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://www.qualcomm.cn/generate_204",
];

// Last successful network-readiness probe, cached so the reload path (which
// runs on the daemon's single signal thread) can reuse the startup probe
// result instead of blocking SIGTERM handling a second time.
static NETWORK_READY_CACHE: OnceLock<bool> = OnceLock::new();

pub(crate) fn network_ready_cached() -> bool {
    NETWORK_READY_CACHE.get().is_some_and(|ready| *ready)
}

pub(crate) fn mark_network_ready() {
    let _ = NETWORK_READY_CACHE.set(true);
}

/// Bounded hostname resolution for network-readiness probes.
///
/// `std::net::ToSocketAddrs` has no timeout: a wedged resolver would block
/// the caller (the daemon's single signal thread, or an HTTP worker) forever.
/// A per-call `thread::spawn` + `recv_timeout` would leak a detached thread
/// whenever the resolution outlives the timeout. Instead a single
/// process-lifetime resolver thread serves a bounded one-request queue. If
/// `getaddrinfo` wedges, later probes fail admission immediately instead of
/// accumulating an unbounded queue. Thread creation failure also degrades to
/// an empty result rather than panicking the daemon.
pub(crate) fn resolve_probe_addresses_bounded(host: &str, port: u16) -> Vec<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;

    const DNS_TIMEOUT: Duration = Duration::from_secs(5);
    type Request = (
        String,
        u16,
        std::sync::mpsc::Sender<Vec<std::net::SocketAddr>>,
    );
    static RESOLVER: OnceLock<Option<std::sync::mpsc::SyncSender<Request>>> = OnceLock::new();
    let sender = RESOLVER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Request>(1);
        let thread = std::thread::Builder::new()
            .name("dae-probe-resolver".to_owned())
            .spawn(move || {
                while let Ok((host, port, reply)) = rx.recv() {
                    let addresses = (host.as_str(), port)
                        .to_socket_addrs()
                        .map(|iter| iter.collect::<Vec<_>>())
                        .unwrap_or_default();
                    let _ = reply.send(addresses);
                }
            });
        thread.ok().map(|_| tx)
    });
    let Some(sender) = sender else {
        return Vec::new();
    };
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    if sender.try_send((host.to_owned(), port, reply_tx)).is_err() {
        return Vec::new();
    }
    reply_rx.recv_timeout(DNS_TIMEOUT).unwrap_or_default()
}

pub(crate) fn wait_for_network_before_subscriptions() -> Result<(), String> {
    // A probe that already succeeded for this process is authoritative:
    // re-probing here would only wedge the signal thread again while the
    // daemon already runs on a network that was reachable.
    if network_ready_cached() {
        return Ok(());
    }
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    const RETRY_DELAY: Duration = Duration::from_secs(5);
    // Default to a bounded retry budget so an unreachable network fails the
    // service instead of wedging the daemon's single signal thread forever.
    // DAED_NETWORK_WAIT_MAX_ATTEMPTS overrides the budget; an explicit 0
    // opts back into the legacy unbounded behavior.
    let max_attempts = env::var("DAED_NETWORK_WAIT_MAX_ATTEMPTS")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(60);
    let mut attempts = 0_u32;
    loop {
        attempts = attempts.saturating_add(1);
        for link in NETWORK_WAIT_LINKS {
            let Ok(url) = url::Url::parse(link) else {
                continue;
            };
            let Some(host) = url.host_str() else {
                continue;
            };
            let port = url.port_or_known_default().unwrap_or(80);
            let addresses = resolve_probe_addresses_bounded(host, port);
            for address in addresses {
                let Ok(mut stream) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) else {
                    continue;
                };
                // Bound the whole probe: a peer that accepts the connection
                // but never responds must not wedge the signal thread.
                let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
                let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
                let request = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    url.path(),
                    host
                );
                if stream.write_all(request.as_bytes()).is_err() {
                    continue;
                }
                let mut response = [0_u8; 128];
                let Ok(read) = stream.read(&mut response) else {
                    continue;
                };
                let ready = std::str::from_utf8(&response[..read])
                    .ok()
                    .and_then(|line| line.strip_prefix("HTTP/"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|status| status.parse::<u16>().ok())
                    .is_some_and(|status| (200..500).contains(&status));
                if ready {
                    mark_network_ready();
                    return Ok(());
                }
            }
        }
        if max_attempts != 0 && attempts >= max_attempts {
            return Err(format!(
                "network did not become ready after {attempts} probe attempts (max_attempts={max_attempts})"
            ));
        }
        thread::sleep(RETRY_DELAY);
    }
}
#[cfg(test)]
mod tests;
