use base64::Engine;

use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksRLink {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub proto: String,
    pub proto_param: String,
    pub obfs: String,
    pub obfs_param: String,
    pub protocol: String,
}

impl ShadowsocksRLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let Some(content) = raw.strip_prefix("ssr://") else {
            return Err(OutboundError::BadShadowsocks(
                "unrecognized ssr address".to_owned(),
            ));
        };
        parse_ssr_content(content).or_else(|_| {
            let decoded = decode_base64_std(content)
                .or_else(|_| decode_base64_url(content))
                .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
            parse_ssr_content(&decoded)
        })
    }

    pub fn address(&self) -> String {
        format_authority(&self.server, self.port)
    }
}

fn parse_ssr_content(content: &str) -> Result<ShadowsocksRLink, OutboundError> {
    let content = if content.contains(':') && !content.contains("/?") {
        format!("{content}/?remarks=&protoparam=&obfsparam=")
    } else {
        content.to_owned()
    };
    let Some((pre, query)) = content.split_once("/?") else {
        return Err(OutboundError::BadShadowsocks(
            "unrecognized ssr address".to_owned(),
        ));
    };
    let mut parts = pre.split(':').map(str::to_owned).collect::<Vec<_>>();
    if parts.len() > 6 {
        let host = parts[..parts.len() - 5].join(":");
        let mut merged = vec![host];
        merged.extend_from_slice(&parts[parts.len() - 5..]);
        parts = merged;
    } else if parts.len() < 6 {
        return Err(OutboundError::BadShadowsocks(
            "unrecognized ssr address".to_owned(),
        ));
    }
    let port = parts[1]
        .parse::<u16>()
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let query_pairs = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<Vec<_>>();
    let query_value = |name: &str| {
        query_pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_default()
    };

    Ok(ShadowsocksRLink {
        name: decode_base64_url_lossy(query_value("remarks"))?,
        server: decode_base64_url_lossy(&parts[0])?,
        port,
        password: decode_base64_url_lossy(&parts[5])?,
        cipher: parts[3].to_ascii_lowercase(),
        proto: parts[2].to_ascii_lowercase(),
        proto_param: decode_base64_url_lossy(query_value("protoparam"))?,
        obfs: parts[4].to_ascii_lowercase(),
        obfs_param: decode_base64_url_lossy(query_value("obfsparam"))?,
        protocol: "shadowsocksr".to_owned(),
    })
}

fn decode_base64_url_lossy(input: &str) -> Result<String, OutboundError> {
    decode_base64_url(input).or_else(|_| Ok(input.to_owned()))
}

fn decode_base64_url(input: &str) -> Result<String, OutboundError> {
    decode_base64_with_padding(input, &base64::engine::general_purpose::URL_SAFE).or_else(|_| {
        decode_base64_with_padding(input, &base64::engine::general_purpose::URL_SAFE_NO_PAD)
    })
}

fn decode_base64_std(input: &str) -> Result<String, OutboundError> {
    decode_base64_with_padding(input, &base64::engine::general_purpose::STANDARD).or_else(|_| {
        decode_base64_with_padding(input, &base64::engine::general_purpose::STANDARD_NO_PAD)
    })
}

fn decode_base64_with_padding(
    input: &str,
    engine: &base64::engine::GeneralPurpose,
) -> Result<String, OutboundError> {
    let mut padded = input.trim().to_owned();
    let rem = padded.len() % 4;
    if rem > 0 {
        padded.extend(std::iter::repeat_n('=', 4 - rem));
    }
    let bytes = engine
        .decode(padded)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    String::from_utf8(bytes).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
