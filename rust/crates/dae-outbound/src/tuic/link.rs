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
            name: url.fragment().unwrap_or_default().to_owned(),
            user: url.username().to_owned(),
            password: url.password().unwrap_or_default().to_owned(),
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
            out.push_str(&self.name);
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
        if let Some(value) = query_value(query, key) {
            if parse_bool(&value).unwrap_or(false) {
                return true;
            }
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
    input.to_owned()
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
