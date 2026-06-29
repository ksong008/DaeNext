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
pub const UTLS_FAMILY_360: &str = "360";
pub const UTLS_FAMILY_ANDROID: &str = "android";
pub const UTLS_FAMILY_CHROME: &str = "chrome";
pub const UTLS_FAMILY_EDGE: &str = "edge";
pub const UTLS_FAMILY_FIREFOX: &str = "firefox";
pub const UTLS_FAMILY_IOS: &str = "ios";
pub const UTLS_FAMILY_QQ: &str = "qq";
pub const UTLS_FAMILY_RANDOM: &str = "random";
pub const UTLS_FAMILY_SAFARI: &str = "safari";

pub const SUPPORTED_UTLS_FINGERPRINTS: &[UtlsFingerprint] = &[
    fp(
        "random",
        "random",
        "random",
        "Randomized",
        false,
        true,
        "auto",
    ),
    fp(
        "randomized",
        "random",
        "random",
        "Randomized",
        true,
        true,
        "auto",
    ),
    fp(
        "randomizedalpn",
        "randomizedalpn",
        "random",
        "RandomizedALPN",
        false,
        true,
        "force-alpn",
    ),
    fp(
        "randomizednoalpn",
        "randomizednoalpn",
        "random",
        "RandomizedNoALPN",
        false,
        true,
        "force-no-alpn",
    ),
    fp(
        "firefox",
        "firefox_auto",
        "firefox",
        "Firefox",
        true,
        false,
        "auto",
    ),
    fp(
        "firefox_auto",
        "firefox_auto",
        "firefox",
        "Firefox",
        false,
        false,
        "auto",
    ),
    fp(
        "firefox_55",
        "firefox_55",
        "firefox",
        "Firefox",
        false,
        false,
        "fixed",
    ),
    fp(
        "firefox_56",
        "firefox_56",
        "firefox",
        "Firefox",
        false,
        false,
        "fixed",
    ),
    fp(
        "firefox_63",
        "firefox_63",
        "firefox",
        "Firefox",
        false,
        false,
        "fixed",
    ),
    fp(
        "firefox_65",
        "firefox_65",
        "firefox",
        "Firefox",
        false,
        false,
        "fixed",
    ),
    fp(
        "firefox_99",
        "firefox_99",
        "firefox",
        "Firefox",
        false,
        false,
        "fixed",
    ),
    fp(
        "firefox_102",
        "firefox_102",
        "firefox",
        "Firefox",
        false,
        false,
        "fixed",
    ),
    fp(
        "firefox_105",
        "firefox_105",
        "firefox",
        "Firefox",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome",
        "chrome_auto",
        "chrome",
        "Chrome",
        true,
        false,
        "auto",
    ),
    fp(
        "chrome_auto",
        "chrome_auto",
        "chrome",
        "Chrome",
        false,
        false,
        "auto",
    ),
    fp(
        "chrome_58",
        "chrome_58",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome_62",
        "chrome_62",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome_70",
        "chrome_70",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome_72",
        "chrome_72",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome_83",
        "chrome_83",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome_87",
        "chrome_87",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome_96",
        "chrome_96",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome_100",
        "chrome_100",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp(
        "chrome_102",
        "chrome_102",
        "chrome",
        "Chrome",
        false,
        false,
        "fixed",
    ),
    fp("ios", "ios_auto", "ios", "iOS", true, false, "auto"),
    fp("ios_auto", "ios_auto", "ios", "iOS", false, false, "auto"),
    fp("ios_11_1", "ios_11_1", "ios", "iOS", false, false, "fixed"),
    fp("ios_12_1", "ios_12_1", "ios", "iOS", false, false, "fixed"),
    fp("ios_13", "ios_13", "ios", "iOS", false, false, "fixed"),
    fp("ios_14", "ios_14", "ios", "iOS", false, false, "fixed"),
    fp(
        "android_11_okhttp",
        "android_11_okhttp",
        "android",
        "Android",
        false,
        false,
        "fixed",
    ),
    fp("edge", "edge_auto", "edge", "Edge", true, false, "auto"),
    fp(
        "edge_auto",
        "edge_auto",
        "edge",
        "Edge",
        false,
        false,
        "auto",
    ),
    fp("edge_85", "edge_85", "edge", "Edge", false, false, "fixed"),
    fp(
        "edge_106", "edge_106", "edge", "Edge", false, false, "fixed",
    ),
    fp(
        "safari",
        "safari_auto",
        "safari",
        "Safari",
        true,
        false,
        "auto",
    ),
    fp(
        "safari_auto",
        "safari_auto",
        "safari",
        "Safari",
        false,
        false,
        "auto",
    ),
    fp(
        "safari_16_0",
        "safari_16_0",
        "safari",
        "Safari",
        false,
        false,
        "fixed",
    ),
    fp("360", "360_auto", "360", "360", true, false, "auto"),
    fp("360_auto", "360_auto", "360", "360", false, false, "auto"),
    fp("360_7_5", "360_7_5", "360", "360", false, false, "fixed"),
    fp("360_11_0", "360_11_0", "360", "360", false, false, "fixed"),
    fp("qq", "qq_auto", "qq", "QQ", true, false, "auto"),
    fp("qq_auto", "qq_auto", "qq", "QQ", false, false, "auto"),
    fp("qq_11_1", "qq_11_1", "qq", "QQ", false, false, "fixed"),
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
