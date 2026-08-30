use sha2::{Digest, Sha256};

use super::link::{Hysteria2ServerContract, normalize_pin_sha256, server_contract};

pub const HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2UnderlayContract {
    pub input_network: String,
    pub server: Hysteria2ServerContract,
    pub underlay_network: &'static str,
    pub input_mark: u32,
    pub underlay_mark: u32,
    pub input_mptcp: bool,
    pub underlay_mptcp_field: bool,
    pub udp_mptcp_effective: bool,
    pub route_cache_key_network: &'static str,
    pub udp_hop_interval_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2PinSha256Check {
    pub configured_pin_normal: String,
    pub raw_cert_sha256_hex: String,
    pub matched: bool,
}

pub fn underlay_contract(
    input_network: &str,
    server: &str,
    mark: u32,
    mptcp: bool,
    udp_hop_interval_ms: u64,
) -> Hysteria2UnderlayContract {
    Hysteria2UnderlayContract {
        input_network: input_network.to_owned(),
        server: server_contract(server),
        underlay_network: "udp",
        input_mark: mark,
        underlay_mark: mark,
        input_mptcp: mptcp,
        underlay_mptcp_field: mptcp,
        udp_mptcp_effective: false,
        route_cache_key_network: "udp",
        udp_hop_interval_ms,
    }
}

pub fn raw_cert_sha256_hex(raw_cert_der: &[u8]) -> String {
    let digest = Sha256::digest(raw_cert_der);
    hex_encode(&digest)
}

pub fn pin_sha256_matches_raw_cert(
    configured_pin: &str,
    raw_cert_der: &[u8],
) -> Hysteria2PinSha256Check {
    let configured_pin_normal = normalize_pin_sha256(configured_pin);
    let raw_cert_sha256_hex = raw_cert_sha256_hex(raw_cert_der);
    Hysteria2PinSha256Check {
        matched: configured_pin_normal == raw_cert_sha256_hex,
        configured_pin_normal,
        raw_cert_sha256_hex,
    }
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
