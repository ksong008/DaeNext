use base64::{Engine as _, engine::general_purpose};
use url::Url;

use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityLink {
    pub name: String,
    pub user: String,
    pub password: String,
    pub server: String,
    pub port: u16,
    pub sni: String,
    pub allow_insecure: bool,
    pub congestion_control: String,
    pub pinned_certchain_sha256: String,
    pub protocol: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityPinDecode {
    pub ok: bool,
    pub format: String,
    pub decoded: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityUnderlayContract {
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

impl JuicityLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let url = Url::parse(raw).map_err(|err| OutboundError::BadJuicity(err.to_string()))?;
        if url.scheme() != "juicity" {
            return Err(OutboundError::BadJuicity(format!(
                "unsupported scheme: {}",
                url.scheme()
            )));
        }
        let query = url.query_pairs().collect::<Vec<_>>();
        let host = url
            .host_str()
            .ok_or_else(|| OutboundError::BadJuicity("missing host".to_owned()))?
            .to_owned();
        let port = url
            .port()
            .ok_or_else(|| OutboundError::BadJuicity("invalid parameters".to_owned()))?;
        let sni = query_value(&query, "peer")
            .filter(|value| !value.is_empty())
            .or_else(|| query_value(&query, "sni").filter(|value| !value.is_empty()))
            .unwrap_or_else(|| host.clone());
        Ok(Self {
            name: url.fragment().unwrap_or_default().to_owned(),
            user: url.username().to_owned(),
            password: url.password().unwrap_or_default().to_owned(),
            server: host,
            port,
            sni,
            allow_insecure: parse_allow_insecure(&query),
            congestion_control: query_value(&query, "congestion_control").unwrap_or_default(),
            pinned_certchain_sha256: query_value(&query, "pinned_certchain_sha256")
                .unwrap_or_default(),
            protocol: "juicity".to_owned(),
        })
    }

    pub fn validate_uuid(&self) -> Result<(), OutboundError> {
        validate_uuid(&self.user)
    }

    pub fn address(&self) -> String {
        format_authority(&self.server, self.port)
    }

    pub fn pin_forces_insecure_verify(&self) -> bool {
        !self.pinned_certchain_sha256.is_empty()
    }

    pub fn export_url(&self) -> String {
        let mut query = Vec::<(String, String)>::new();
        if self.allow_insecure {
            query.push(("allow_insecure".to_owned(), "1".to_owned()));
        }
        push_if_non_empty(&mut query, "sni", &self.sni);
        push_if_non_empty(&mut query, "congestion_control", &self.congestion_control);
        push_if_non_empty(
            &mut query,
            "pinned_certchain_sha256",
            &self.pinned_certchain_sha256,
        );
        query.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let mut out = String::new();
        out.push_str("juicity://");
        out.push_str(&escape_userinfo(&self.user));
        out.push(':');
        out.push_str(&escape_userinfo(&self.password));
        out.push('@');
        out.push_str(&self.address());
        if !query.is_empty() {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (key, value) in query {
                serializer.append_pair(&key, &value);
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

pub fn decode_pinned_certchain(input: &str) -> Result<JuicityPinDecode, OutboundError> {
    if input.is_empty() {
        return Ok(JuicityPinDecode {
            ok: true,
            format: String::new(),
            decoded: Vec::new(),
        });
    }
    if let Ok(decoded) = general_purpose::URL_SAFE.decode(input) {
        return Ok(JuicityPinDecode {
            ok: true,
            format: "url-base64".to_owned(),
            decoded,
        });
    }
    if let Ok(decoded) = general_purpose::STANDARD.decode(input) {
        return Ok(JuicityPinDecode {
            ok: true,
            format: "std-base64".to_owned(),
            decoded,
        });
    }
    if let Ok(decoded) = hex_decode(input) {
        return Ok(JuicityPinDecode {
            ok: true,
            format: "hex".to_owned(),
            decoded,
        });
    }
    Err(OutboundError::BadJuicity(
        "failed to decode PinnedCertchainSha256".to_owned(),
    ))
}

pub fn validate_uuid(input: &str) -> Result<(), OutboundError> {
    let compact = input.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(OutboundError::BadJuicity(format!("parse UUID: {input}")));
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
            return Err(OutboundError::BadJuicity(format!("parse UUID: {input}")));
        }
    }
    Ok(())
}

pub fn underlay_contract(network: &str, mark: u32, mptcp: bool) -> JuicityUnderlayContract {
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
    JuicityUnderlayContract {
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

fn push_if_non_empty(query: &mut Vec<(String, String)>, key: &str, value: &str) {
    if !value.is_empty() {
        query.push((key.to_owned(), value.to_owned()));
    }
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn escape_userinfo(input: &str) -> String {
    input.to_owned()
}

fn hex_decode(input: &str) -> Result<Vec<u8>, OutboundError> {
    if !input.len().is_multiple_of(2) {
        return Err(OutboundError::BadJuicity("odd hex length".to_owned()));
    }
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| Ok((hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OutboundError::BadJuicity(format!("bad hex byte: {byte}"))),
    }
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
