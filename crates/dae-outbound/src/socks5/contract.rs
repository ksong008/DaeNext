pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["socks5"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] = &[
    "http",
    "https",
    "shadowsocks",
    "shadowsocks-2022",
    "trojan",
    "vmess",
    "vless",
    "hysteria2",
    "tuic",
    "juicity",
    "anytls",
    "transport-combos",
];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local fake SOCKS5 TCP CONNECT",
    "local fake SOCKS5 username/password auth",
    "local fake SOCKS5 UDP packet wrapper",
];
pub const DEADLINE_CONTRACT: &[&str] = &[
    "DialContextWithDefaultTimeout applies a non-zero deadline around the SOCKS5 handshake",
    "deadline is reset to zero after handshake",
];
