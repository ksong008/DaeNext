use std::borrow::Cow;

use url::Url;

use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicLink {
    pub name: String,
    pub user: String,
    pub password: String,
    pub server: String,
    pub port: u16,
    pub sni: String,
    pub allow_insecure: bool,
    pub disable_sni: bool,
    pub congestion_control: String,
    pub alpn: Vec<String>,
    pub udp_relay_mode: String,
    pub protocol: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuicUdpRelayMode {
    Native,
    Quic,
}

impl TuicUdpRelayMode {
    pub fn from_config(value: &str) -> Result<Self, OutboundError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "native" => Ok(Self::Native),
            "quic" => Ok(Self::Quic),
            _ => Err(OutboundError::BadTuic(
                "unsupported UDP relay mode".to_owned(),
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Quic => "quic",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicUnderlayContract {
    pub input_network: String,
    pub input_mark: u32,
    pub input_mptcp: bool,
    pub input_encoded: Vec<u8>,
    pub underlay_network: String,
    pub underlay_mark: u32,
    pub underlay_mptcp: bool,
    pub underlay_encoded: Vec<u8>,
    pub same_encoded_value: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MagicNetwork {
    network: String,
    mark: u32,
    mptcp: bool,
}

impl TuicLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let url = Url::parse(raw).map_err(|err| OutboundError::BadTuic(err.to_string()))?;
        if url.scheme() != "tuic" {
            return Err(OutboundError::BadTuic(format!(
                "unsupported scheme: {}",
                url.scheme()
            )));
        }
        let query = url.query_pairs().collect::<Vec<_>>();
        let host = url
            .host_str()
            .ok_or_else(|| OutboundError::BadTuic("missing host".to_owned()))?
            .to_owned();
        let port = url
            .port()
            .ok_or_else(|| OutboundError::BadTuic("invalid parameters".to_owned()))?;
        let mut sni = query_value(&query, "peer")
            .filter(|value| !value.is_empty())
            .or_else(|| query_value(&query, "sni").filter(|value| !value.is_empty()))
            .unwrap_or_else(|| host.clone());
        let mut allow_insecure = parse_allow_insecure(&query);
        let disable_sni = query_value(&query, "disable_sni")
            .and_then(|value| parse_bool(&value))
            .unwrap_or(false);
        if disable_sni {
            sni.clear();
            allow_insecure = true;
        }
        let alpn = if query_has(&query, "alpn") {
            split_alpn(&query_value(&query, "alpn").unwrap_or_default())
        } else {
            Vec::new()
        };
        Ok(Self {
            name: percent_decode(url.fragment().unwrap_or_default())?,
            user: percent_decode(url.username())?,
            password: percent_decode(url.password().unwrap_or_default())?,
            server: host,
            port,
            sni,
            allow_insecure,
            disable_sni,
            congestion_control: query_value(&query, "congestion_control").unwrap_or_default(),
            alpn,
            udp_relay_mode: query_value(&query, "udp_relay_mode")
                .unwrap_or_default()
                .to_ascii_lowercase(),
            protocol: "tuic".to_owned(),
        })
    }

    pub fn validate_uuid(&self) -> Result<(), OutboundError> {
        validate_uuid(&self.user)
    }

    pub fn address(&self) -> String {
        format_authority(&self.server, self.port)
    }

    pub fn export_url(&self) -> String {
        let mut query = Vec::<(&str, Cow<'_, str>)>::new();
        if self.allow_insecure {
            query.push(("allow_insecure", Cow::Borrowed("1")));
        }
        push_if_non_empty(&mut query, "sni", &self.sni);
        if self.disable_sni {
            query.push(("disable_sni", Cow::Borrowed("1")));
        }
        push_if_non_empty(&mut query, "congestion_control", &self.congestion_control);
        if !self.alpn.is_empty() {
            query.push(("alpn", Cow::Owned(self.alpn.join(","))));
        }
        push_if_non_empty(&mut query, "udp_relay_mode", &self.udp_relay_mode);
        query.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.as_ref().cmp(b.1.as_ref())));

        let mut out = String::new();
        out.push_str("tuic://");
        out.push_str(&escape_userinfo(&self.user));
        out.push(':');
        out.push_str(&escape_userinfo(&self.password));
        out.push('@');
        push_authority(&mut out, &self.server, self.port);
        if !query.is_empty() {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (key, value) in query {
                serializer.append_pair(key, value.as_ref());
            }
            out.push('?');
            out.push_str(&serializer.finish());
        }
        if !self.name.is_empty() {
            out.push('#');
            out.push_str(&percent_encode_uri_component(&self.name));
        }
        out
    }
}

pub fn validate_uuid(input: &str) -> Result<(), OutboundError> {
    let compact = input.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(OutboundError::BadTuic(format!("parse UUID: {input}")));
    }
    if input.contains('-') {
        let bytes = input.as_bytes();
        let hyphenated = input.len() == 36
            && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
            && bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit());
        if !hyphenated {
            return Err(OutboundError::BadTuic(format!("parse UUID: {input}")));
        }
    }
    Ok(())
}

pub fn split_alpn(input: &str) -> Vec<String> {
    split_alpn_ref(input).map(str::to_owned).collect()
}

pub fn split_alpn_ref(input: &str) -> impl Iterator<Item = &str> {
    input.split(',').map(str::trim)
}

pub fn underlay_contract(network: &str, mark: u32, mptcp: bool) -> TuicUnderlayContract {
    let input = MagicNetwork {
        network: network.to_owned(),
        mark,
        mptcp,
    };
    let input_encoded = input.encode();
    let underlay = if network == "tcp" {
        MagicNetwork {
            network: "udp".to_owned(),
            mark,
            mptcp: false,
        }
    } else {
        input.clone()
    };
    let underlay_encoded = underlay.encode();
    TuicUnderlayContract {
        input_network: input.network,
        input_mark: input.mark,
        input_mptcp: input.mptcp,
        same_encoded_value: input_encoded == underlay_encoded,
        input_encoded,
        underlay_network: underlay.network,
        underlay_mark: underlay.mark,
        underlay_mptcp: underlay.mptcp,
        underlay_encoded,
    }
}

fn query_value(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    key: &str,
) -> Option<String> {
    query
        .iter()
        .find(|(candidate, _)| candidate.as_ref() == key)
        .map(|(_, value)| value.to_string())
}

fn query_has(query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)], key: &str) -> bool {
    query.iter().any(|(candidate, _)| candidate.as_ref() == key)
}

fn parse_allow_insecure(query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)]) -> bool {
    for key in [
        "allowInsecure",
        "allow_insecure",
        "allowinsecure",
        "skipVerify",
    ] {
        if let Some(value) = query_value(query, key)
            && parse_bool(&value).unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn parse_bool(input: &str) -> Option<bool> {
    match input {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn push_if_non_empty<'a>(
    query: &mut Vec<(&'static str, Cow<'a, str>)>,
    key: &'static str,
    value: &'a str,
) {
    if !value.is_empty() {
        query.push((key, Cow::Borrowed(value)));
    }
}

fn format_authority(host: &str, port: u16) -> String {
    let mut out = String::new();
    push_authority(&mut out, host, port);
    out
}

fn push_authority(out: &mut String, host: &str, port: u16) {
    if host.contains(':') && !host.starts_with('[') {
        out.push('[');
        out.push_str(host);
        out.push_str("]:");
    } else {
        out.push_str(host);
        out.push(':');
    }
    out.push_str(&port.to_string());
}

fn escape_userinfo(input: &str) -> String {
    percent_encode_uri_component(input)
}

fn percent_decode(input: &str) -> Result<String, OutboundError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(OutboundError::BadTuic(
                    "truncated percent escape".to_owned(),
                ));
            }
            out.push((hex_nibble(bytes[i + 1])? << 4) | hex_nibble(bytes[i + 2])?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|err| OutboundError::BadTuic(err.to_string()))
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OutboundError::BadTuic(format!(
            "bad percent escape byte: {byte}"
        ))),
    }
}

fn percent_encode_uri_component(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

impl MagicNetwork {
    fn encode(&self) -> Vec<u8> {
        let network = self.network.as_bytes();
        let mut out = Vec::with_capacity(2 + network.len() + 4 + 1);
        out.push(0);
        out.push(network.len() as u8);
        out.extend_from_slice(network);
        out.extend_from_slice(&self.mark.to_be_bytes());
        out.push(u8::from(self.mptcp));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_relay_mode_admits_official_modes_and_normalized_default() {
        assert_eq!(
            TuicUdpRelayMode::from_config("").unwrap(),
            TuicUdpRelayMode::Native
        );
        assert_eq!(
            TuicUdpRelayMode::from_config(" NATIVE ").unwrap(),
            TuicUdpRelayMode::Native
        );
        assert_eq!(TuicUdpRelayMode::Native.as_str(), "native");
        assert_eq!(
            TuicUdpRelayMode::from_config(" QUIC ").unwrap(),
            TuicUdpRelayMode::Quic
        );
        assert_eq!(TuicUdpRelayMode::Quic.as_str(), "quic");
    }

    #[test]
    fn udp_relay_mode_redacts_unknown_values() {
        let unknown = "private-relay-token";
        let unknown_error = TuicUdpRelayMode::from_config(unknown)
            .unwrap_err()
            .to_string();
        assert!(unknown_error.contains("unsupported UDP relay mode"));
        assert!(!unknown_error.contains(unknown));
    }

    #[test]
    fn export_url_roundtrips_special_characters_in_userinfo_and_name() {
        let link = TuicLink {
            name: "node #1 / 100%".to_owned(),
            user: "user".to_owned(),
            password: "p@ss:w%rd&+?=#".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            sni: "sni.example.com".to_owned(),
            allow_insecure: true,
            disable_sni: false,
            congestion_control: "bbr".to_owned(),
            alpn: vec!["h3".to_owned(), "h2".to_owned()],
            udp_relay_mode: "native".to_owned(),
            protocol: "tuic".to_owned(),
        };
        let exported = link.export_url();
        assert!(exported.contains("p%40ss%3Aw%25rd"));
        assert!(exported.contains("%23")); // name 中的 '#' 必须百分号编码
        let parsed = TuicLink::parse(&exported).unwrap();
        assert_eq!(parsed, link);
    }
}
