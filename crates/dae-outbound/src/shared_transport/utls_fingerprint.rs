use crate::error::OutboundError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtlsFingerprint {
    pub name: &'static str,
    pub canonical: &'static str,
    pub family: &'static str,
    pub client: &'static str,
    pub auto_alias: bool,
    pub randomized: bool,
    pub alpn_policy: &'static str,
}

pub const U_TLS_WIRE_STACK_DEFERRED: bool = true;
pub const UTLS_ALPN_H2: &str = "h2";
pub const UTLS_ALPN_HTTP_1_1: &str = "http/1.1";
pub const UTLS_BROWSER_DEFAULT_ALPN: &[&str] = &[UTLS_ALPN_H2, UTLS_ALPN_HTTP_1_1];
pub const UTLS_BROWSER_H2_ONLY_ALPN: &[&str] = &[UTLS_ALPN_H2];
pub const UTLS_ALPN_POLICY_AUTO: &str = "auto";
pub const UTLS_ALPN_POLICY_FIXED: &str = "fixed";
pub const UTLS_ALPN_POLICY_RANDOMIZED_ALPN: &str = "randomized-alpn";
pub const UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN: &str = "randomized-no-alpn";
pub const UTLS_FAMILY_360: &str = "360";
pub const UTLS_FAMILY_ANDROID: &str = "android";
pub const UTLS_FAMILY_CHROME: &str = "chrome";
pub const UTLS_FAMILY_EDGE: &str = "edge";
pub const UTLS_FAMILY_FIREFOX: &str = "firefox";
pub const UTLS_FAMILY_IOS: &str = "ios";
pub const UTLS_FAMILY_QQ: &str = "qq";
pub const UTLS_FAMILY_RANDOM: &str = "random";
pub const UTLS_FAMILY_SAFARI: &str = "safari";
pub const UTLS_FIREFOX_102_FINGERPRINT: &str = "firefox_102";
pub const DEFAULT_UTLS_FINGERPRINT: &str = UTLS_FAMILY_CHROME;
pub const UTLS_CONTRACT_LINK_PROBE_FINGERPRINT: &str = DEFAULT_UTLS_FINGERPRINT;
pub const UTLS_CONTRACT_GLOBAL_PROBE_FINGERPRINT: &str = UTLS_FAMILY_SAFARI;
pub const UTLS_CONTRACT_UNKNOWN_PROBE_FINGERPRINT: &str = "Chrome";

pub const SUPPORTED_UTLS_FINGERPRINTS: &[UtlsFingerprint] = &[
    fp(
        "random",
        "random",
        "random",
        "Randomized",
        false,
        true,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "randomized",
        "random",
        "random",
        "Randomized",
        true,
        true,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "randomizedalpn",
        "randomizedalpn",
        "random",
        "RandomizedALPN",
        false,
        true,
        UTLS_ALPN_POLICY_RANDOMIZED_ALPN,
    ),
    fp(
        "randomizednoalpn",
        "randomizednoalpn",
        "random",
        "RandomizedNoALPN",
        false,
        true,
        UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN,
    ),
    fp(
        "firefox",
        "firefox_auto",
        "firefox",
        "Firefox",
        true,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "firefox_auto",
        "firefox_auto",
        "firefox",
        "Firefox",
        false,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "firefox_55",
        "firefox_55",
        "firefox",
        "Firefox",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "firefox_56",
        "firefox_56",
        "firefox",
        "Firefox",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "firefox_63",
        "firefox_63",
        "firefox",
        "Firefox",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "firefox_65",
        "firefox_65",
        "firefox",
        "Firefox",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "firefox_99",
        "firefox_99",
        "firefox",
        "Firefox",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "firefox_102",
        "firefox_102",
        "firefox",
        "Firefox",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "firefox_105",
        "firefox_105",
        "firefox",
        "Firefox",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome",
        "chrome_auto",
        "chrome",
        "Chrome",
        true,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "chrome_auto",
        "chrome_auto",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "chrome_58",
        "chrome_58",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome_62",
        "chrome_62",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome_70",
        "chrome_70",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome_72",
        "chrome_72",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome_83",
        "chrome_83",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome_87",
        "chrome_87",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome_96",
        "chrome_96",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome_100",
        "chrome_100",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "chrome_102",
        "chrome_102",
        "chrome",
        "Chrome",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "ios",
        "ios_auto",
        "ios",
        "iOS",
        true,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "ios_auto",
        "ios_auto",
        "ios",
        "iOS",
        false,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "ios_11_1",
        "ios_11_1",
        "ios",
        "iOS",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "ios_12_1",
        "ios_12_1",
        "ios",
        "iOS",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "ios_13",
        "ios_13",
        "ios",
        "iOS",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "ios_14",
        "ios_14",
        "ios",
        "iOS",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "android_11_okhttp",
        "android_11_okhttp",
        "android",
        "Android",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "edge",
        "edge_auto",
        "edge",
        "Edge",
        true,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "edge_auto",
        "edge_auto",
        "edge",
        "Edge",
        false,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "edge_85",
        "edge_85",
        "edge",
        "Edge",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "edge_106",
        "edge_106",
        "edge",
        "Edge",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "safari",
        "safari_auto",
        "safari",
        "Safari",
        true,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "safari_auto",
        "safari_auto",
        "safari",
        "Safari",
        false,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "safari_16_0",
        "safari_16_0",
        "safari",
        "Safari",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "360",
        "360_auto",
        "360",
        "360",
        true,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "360_auto",
        "360_auto",
        "360",
        "360",
        false,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "360_7_5",
        "360_7_5",
        "360",
        "360",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "360_11_0",
        "360_11_0",
        "360",
        "360",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
    fp(
        "qq",
        "qq_auto",
        "qq",
        "QQ",
        true,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "qq_auto",
        "qq_auto",
        "qq",
        "QQ",
        false,
        false,
        UTLS_ALPN_POLICY_AUTO,
    ),
    fp(
        "qq_11_1",
        "qq_11_1",
        "qq",
        "QQ",
        false,
        false,
        UTLS_ALPN_POLICY_FIXED,
    ),
];

pub fn resolve_utls_client_hello_id(name: &str) -> Result<UtlsFingerprint, OutboundError> {
    SUPPORTED_UTLS_FINGERPRINTS
        .iter()
        .copied()
        .find(|fingerprint| fingerprint.name == name)
        .ok_or_else(|| {
            OutboundError::BadSharedTransport(format!("unknown uTLS Client Hello ID: {name}"))
        })
}

pub fn supported_utls_fingerprint_count() -> usize {
    SUPPORTED_UTLS_FINGERPRINTS.len()
}

pub fn utls_fingerprint_names() -> Vec<&'static str> {
    SUPPORTED_UTLS_FINGERPRINTS
        .iter()
        .map(|fingerprint| fingerprint.name)
        .collect()
}

pub fn utls_fingerprint_default_alpn_protocols(
    fingerprint: &UtlsFingerprint,
) -> &'static [&'static str] {
    match fingerprint.alpn_policy {
        UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN => &[],
        UTLS_ALPN_POLICY_RANDOMIZED_ALPN => UTLS_BROWSER_DEFAULT_ALPN,
        _ if fingerprint.name == UTLS_FIREFOX_102_FINGERPRINT => UTLS_BROWSER_H2_ONLY_ALPN,
        _ if matches!(fingerprint.family, UTLS_FAMILY_ANDROID | UTLS_FAMILY_RANDOM) => &[],
        _ => UTLS_BROWSER_DEFAULT_ALPN,
    }
}

const fn fp(
    name: &'static str,
    canonical: &'static str,
    family: &'static str,
    client: &'static str,
    auto_alias: bool,
    randomized: bool,
    alpn_policy: &'static str,
) -> UtlsFingerprint {
    UtlsFingerprint {
        name,
        canonical,
        family,
        client,
        auto_alias,
        randomized,
        alpn_policy,
    }
}
