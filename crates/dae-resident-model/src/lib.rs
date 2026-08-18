use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use dae_outbound::canonical_link_without_display_name;
use dae_outbound::hysteria2::Hysteria2CongestionConfig;
use dae_outbound::shared_transport::{
    EchConfigList, GrpcMode, Mldsa65VerifyKey, TlsFragmentOptions,
};
use dae_outbound::vless::contract::is_xtls_rprx_vision_flow;
use serde_json::Value;
use sha2::{Digest, Sha256};

mod executable_graph;
mod model;
mod tls_policy;
mod udp_chain;

pub use executable_graph::{ResidentGraphIdentity, resident_graph_identity};
pub use model::*;
pub use tls_policy::*;
pub use udp_chain::*;

pub fn link_hash(link: &str) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(link.as_bytes())))
}

pub fn execution_link_hash(link: &str) -> String {
    link_hash(&canonical_link_without_display_name(link))
}

pub fn graph_id_from_link_hash(link_hash: &str) -> String {
    let graph_hash = link_hash.trim_start_matches("sha256:");
    format!("resident-graph:{}", &graph_hash[..16.min(graph_hash.len())])
}

pub fn redacted_link_source(link: &str) -> String {
    let Ok(url) = url::Url::parse(link) else {
        return "link:<redacted>".to_owned();
    };
    let mut value = format!("{}:<redacted>", url.scheme());
    if let Some(fragment) = url.fragment().filter(|fragment| !fragment.is_empty()) {
        value.push('#');
        value.push_str(fragment);
    }
    value
}

pub fn display_name_from_link(link: &str) -> String {
    url::Url::parse(link)
        .ok()
        .and_then(|url| url.fragment().map(str::to_owned))
        .filter(|fragment| !fragment.is_empty())
        .unwrap_or_else(|| "<redacted>".to_owned())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
