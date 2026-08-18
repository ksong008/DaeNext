use base64::{Engine as _, engine::general_purpose};
use dae_netutil::{MagicNetworkEncoding, encode_magic_network_with_encoding};
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
            name: percent_decode(url.fragment().unwrap_or_default())?,
            user: percent_decode(url.username())?,
            password: percent_decode(url.password().unwrap_or_default())?,
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
            out.push_str(&percent_encode_uri_component(&self.name));
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

pub fn underlay_contract(
    network: &str,
    mark: u32,
    mptcp: bool,
) -> Result<JuicityUnderlayContract, OutboundError> {
    let input = MagicNetwork {
        network: network.to_owned(),
        mark,
        mptcp,
    };
    let input_encoded = input.encode()?;
    let underlay = if network == "tcp" {
        MagicNetwork {
            network: "udp".to_owned(),
            mark,
            mptcp: false,
        }
    } else {
        input.clone()
    };
    let underlay_encoded = underlay.encode()?;
    Ok(JuicityUnderlayContract {
        input_network: input.network,
        input_mark: input.mark,
        input_mptcp: input.mptcp,
        same_encoded_value: input_encoded == underlay_encoded,
        input_encoded,
        underlay_network: underlay.network,
        underlay_mark: underlay.mark,
        underlay_mptcp: underlay.mptcp,
        underlay_encoded,
    })
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
    percent_encode_uri_component(input)
}

fn percent_decode(input: &str) -> Result<String, OutboundError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(OutboundError::BadJuicity(
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
    String::from_utf8(out).map_err(|err| OutboundError::BadJuicity(err.to_string()))
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
    fn encode(&self) -> Result<Vec<u8>, OutboundError> {
        encode_magic_network_with_encoding(
            &self.network,
            self.mark,
            self.mptcp,
            MagicNetworkEncoding::Framed,
        )
        .map_err(|error| OutboundError::BadJuicity(format!("magic-network: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn underlay_contract_rejects_oversized_magic_network() {
        let network = "x".repeat(u8::MAX as usize + 1);
        assert!(matches!(
            underlay_contract(&network, 0, false),
            Err(OutboundError::BadJuicity(message)) if message.contains("network too long")
        ));
    }

    #[test]
    fn export_url_roundtrips_special_characters_in_userinfo_and_name() {
        let link = JuicityLink {
            name: "node #1 / 100%".to_owned(),
            user: "user".to_owned(),
            password: "p@ss:w%rd&+?".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            sni: "sni.example.com".to_owned(),
            allow_insecure: true,
            congestion_control: "bbr".to_owned(),
            pinned_certchain_sha256: String::new(),
            protocol: "juicity".to_owned(),
        };
        let exported = link.export_url();
        assert!(exported.contains("p%40ss%3Aw%25rd"));
        assert!(exported.contains("%23"));
        let parsed = JuicityLink::parse(&exported).unwrap();
        assert_eq!(parsed, link);
    }
}
