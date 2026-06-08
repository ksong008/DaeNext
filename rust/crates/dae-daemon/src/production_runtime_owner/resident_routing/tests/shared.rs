use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

pub(crate) use dae_config::parser::parse_config;
pub(crate) use dae_config::schema::build_config;
pub(crate) use dae_core_types::OutboundIndex;

use super::*;

pub(crate) static TEST_ASSET_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn test_asset_root(name: &str) -> PathBuf {
    let sequence = TEST_ASSET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "dae-resident-routing-{name}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

pub(crate) fn write_asset(root: &Path, filename: &str, data: Vec<u8>) {
    fs::write(root.join(filename), data).unwrap();
}

pub(crate) fn geoip_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        push_field_bytes(&mut out, 1, entry);
    }
    out
}

pub(crate) fn geoip_entry(code: &str, cidrs: &[(&[u8], u64)], inverse_match: bool) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_string(&mut out, 1, code);
    for (ip, prefix) in cidrs {
        let mut cidr = Vec::new();
        push_field_bytes(&mut cidr, 1, ip);
        push_field_varint(&mut cidr, 2, *prefix);
        push_field_bytes(&mut out, 2, &cidr);
    }
    if inverse_match {
        push_field_varint(&mut out, 3, 1);
    }
    out
}

pub(crate) fn geosite_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        push_field_bytes(&mut out, 1, entry);
    }
    out
}

pub(crate) fn geosite_entry(code: &str, domains: &[(u64, &str, &[&str])]) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_string(&mut out, 1, code);
    for (domain_type, value, attrs) in domains {
        push_field_bytes(&mut out, 2, &domain_entry(*domain_type, value, attrs));
    }
    out
}

pub(crate) fn domain_entry(domain_type: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_varint(&mut out, 1, domain_type);
    push_field_string(&mut out, 2, value);
    for attr in attrs {
        let mut attribute = Vec::new();
        push_field_string(&mut attribute, 1, attr);
        push_field_bytes(&mut out, 3, &attribute);
    }
    out
}

pub(crate) fn push_field_string(out: &mut Vec<u8>, field: u64, value: &str) {
    push_field_bytes(out, field, value.as_bytes());
}

pub(crate) fn push_field_bytes(out: &mut Vec<u8>, field: u64, value: &[u8]) {
    push_varint(out, (field << 3) | 2);
    push_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

pub(crate) fn push_field_varint(out: &mut Vec<u8>, field: u64, value: u64) {
    push_varint(out, field << 3);
    push_varint(out, value);
}

pub(crate) fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
