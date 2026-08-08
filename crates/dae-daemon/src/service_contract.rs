use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
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

pub(crate) fn wait_for_network_before_subscriptions() -> Result<(), String> {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    const RETRY_DELAY: Duration = Duration::from_secs(5);
    let max_attempts = env::var("DAED_NETWORK_WAIT_MAX_ATTEMPTS")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0);
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
            let Ok(addresses) = (host, port).to_socket_addrs() else {
                continue;
            };
            for address in addresses {
                let Ok(mut stream) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) else {
                    continue;
                };
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
                    return Ok(());
                }
            }
        }
        if max_attempts != 0 && attempts >= max_attempts {
            return Err(format!(
                "network did not become ready after {attempts} probe attempts"
            ));
        }
        thread::sleep(RETRY_DELAY);
    }
}
#[cfg(test)]
mod tests;
