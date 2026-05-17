use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundError {
    NoAliveDialer,
    NoDialerInGroup,
    FixedIndexOutOfRange,
    UnsupportedPolicy(String),
    UnsupportedFilterInput(String),
    UnsupportedFilterKey { input: String, key: String },
    BadRegex(String),
    UnknownAnnotation(String),
    BadDuration(String),
    MissingScheme,
    BadAnyTLS(String),
    BadHttpProxy(String),
    BadHysteria2(String),
    BadJuicity(String),
    BadShadowsocks(String),
    BadSocks5Address(String),
    BadTrojan(String),
    BadTuic(String),
    BadVless(String),
    BadVmess(String),
    BadSocks5Auth(String),
    BadSocks5Packet(String),
    BadSocks5Reply(String),
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAliveDialer => f.write_str("no alive dialer"),
            Self::NoDialerInGroup => f.write_str("no dialer in this group"),
            Self::FixedIndexOutOfRange => f.write_str("selected dialer index is out of range"),
            Self::UnsupportedPolicy(policy) => {
                write!(f, "unsupported DialerSelectionPolicy: {policy}")
            }
            Self::UnsupportedFilterInput(input) => {
                write!(f, "unsupported filter input type: {input:?}")
            }
            Self::UnsupportedFilterKey { input, key } => {
                write!(f, "unsupported filter key {key:?} in \"filter: {input}()\"")
            }
            Self::BadRegex(pattern) => write!(f, "bad regexp in filter: {pattern}"),
            Self::UnknownAnnotation(key) => write!(f, "unknown filter annotation: {key}"),
            Self::BadDuration(value) => write!(f, "incorrect latency format: {value}"),
            Self::MissingScheme => f.write_str("missing scheme"),
            Self::BadAnyTLS(value) => write!(f, "bad anytls: {value}"),
            Self::BadHttpProxy(value) => write!(f, "bad http proxy: {value}"),
            Self::BadHysteria2(value) => write!(f, "bad hysteria2: {value}"),
            Self::BadJuicity(value) => write!(f, "bad juicity: {value}"),
            Self::BadShadowsocks(value) => write!(f, "bad shadowsocks: {value}"),
            Self::BadSocks5Address(value) => write!(f, "bad socks5 address: {value}"),
            Self::BadTrojan(value) => write!(f, "bad trojan: {value}"),
            Self::BadTuic(value) => write!(f, "bad tuic: {value}"),
            Self::BadVless(value) => write!(f, "bad vless: {value}"),
            Self::BadVmess(value) => write!(f, "bad vmess: {value}"),
            Self::BadSocks5Auth(value) => write!(f, "bad socks5 auth: {value}"),
            Self::BadSocks5Packet(value) => write!(f, "bad socks5 packet: {value}"),
            Self::BadSocks5Reply(value) => write!(f, "bad socks5 reply: {value}"),
        }
    }
}

impl std::error::Error for OutboundError {}
