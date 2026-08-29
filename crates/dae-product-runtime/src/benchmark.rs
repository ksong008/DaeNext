use super::{display_global_config_text, normalize_global_value};
use serde_json::Value;

pub struct ProductGlobalNormalizeBenchmarkFixture {
    simple_global: &'static str,
    complex_global: &'static str,
    legacy_json: &'static str,
}

pub fn product_global_normalize_benchmark_fixture() -> ProductGlobalNormalizeBenchmarkFixture {
    ProductGlobalNormalizeBenchmarkFixture {
        simple_global: r#"
global {
  tproxy_port:'12345'
  tproxy_port_protect:'true'
  so_mark_from_dae:'7'
  log_level:'debug'
  tcp_check_url:'http://localhost/generate_204,127.0.0.1'
  udp_check_dns:'dns.google:53'
  check_interval:'10s'
  check_tolerance:'500ms'
  lan_interface:'br-lan'
  wan_interface:'auto,eth0'
  fallback_resolver:'8.8.8.8:53'
  bandwidth_max_tx:'200 mbps'
}
"#,
        complex_global: r#"
# comment before global should not change section detection
global { log_level:'debug' tproxy_port:'12345' tcp_check_url:'https://example.com/{probe}:443,127.0.0.1' wan_interface:'auto,eth0' }
"#,
        legacy_json: r#"{"tproxyPort":12345,"wanInterface":["auto","eth0"],"dialMode":"domain","tcpCheckUrl":["http://localhost","127.0.0.1"]}"#,
    }
}

impl ProductGlobalNormalizeBenchmarkFixture {
    pub fn normalize_simple_once(&self) -> u64 {
        checksum_global_value(&normalize_global_value(Some(self.simple_global)))
    }

    pub fn normalize_complex_once(&self) -> u64 {
        checksum_global_value(&normalize_global_value(Some(self.complex_global)))
    }

    pub fn normalize_json_once(&self) -> u64 {
        checksum_global_value(&normalize_global_value(Some(self.legacy_json)))
    }

    pub fn display_raw_once(&self) -> u64 {
        display_global_config_text(self.simple_global).len() as u64
    }
}

fn checksum_global_value(value: &Value) -> u64 {
    let mut checksum = 0_u64;
    checksum ^= value["tproxyPort"].as_u64().unwrap_or_default();
    checksum ^= value["soMarkFromDae"].as_u64().unwrap_or_default() << 8;
    checksum ^= (value["tproxyPortProtect"].as_bool().unwrap_or(false) as u64) << 16;
    checksum ^= value["logLevel"].as_str().map(str::len).unwrap_or_default() as u64;
    checksum ^= (value["tcpCheckUrl"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default() as u64)
        << 0x20;
    checksum ^= (value["wanInterface"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default() as u64)
        << 0x28;
    checksum ^= (value["fallbackResolver"]
        .as_str()
        .map(str::len)
        .unwrap_or_default() as u64)
        << 0x30;
    checksum
}
