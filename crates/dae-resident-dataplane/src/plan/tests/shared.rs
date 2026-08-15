use super::*;
mod imports;
pub(super) use self::imports::*;
mod generic_fixtures;
pub(super) use self::generic_fixtures::*;
mod semantic_assertions;
pub(super) use self::semantic_assertions::*;
mod config;
pub(super) use self::config::*;
mod shadowsocks_fixtures;
pub(super) use self::shadowsocks_fixtures::*;
mod vless_fixtures;
pub(super) use self::vless_fixtures::*;
mod trojan_fixtures;
pub(super) use self::trojan_fixtures::*;
mod quic_fixtures;
pub(super) use self::quic_fixtures::*;
mod vmess_fixtures;
pub(super) use self::vmess_fixtures::*;
mod source_fixture_contract;

pub(super) const fn expected_resident_tls_provider() -> &'static str {
    "boringssl"
}

pub(super) const fn expected_resident_reality_provider() -> &'static str {
    "reality-boringssl"
}

pub(super) const fn expected_resident_quic_provider() -> &'static str {
    "quinn-boringssl"
}
