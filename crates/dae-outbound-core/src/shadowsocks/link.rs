use base64::Engine;
use url::Url;

use crate::error::OutboundError;

use super::cipher::{CipherFamily, classify_cipher};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksLink {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub plugin: Sip003,
    pub udp: bool,
    pub protocol: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Sip003 {
    pub name: String,
    pub opts: Sip003Opts,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Sip003Opts {
    pub tls: String,
    pub obfs: String,
    pub host: String,
    pub path: String,
}

impl ShadowsocksLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        parse_direct(raw).or_else(|_| parse_base64_wrapped(raw))
    }

    pub fn address(&self) -> String {
        format_authority(&self.server, self.port)
    }

    pub fn capability_label(&self) -> Result<&'static str, OutboundError> {
        Ok(classify_cipher(&self.cipher)?.rust_capability_label)
    }

    pub fn export_url(&self) -> String {
        let mut out = String::new();
        out.push_str("ss://");
        if classify_cipher(&self.cipher)
            .map(|info| info.family == CipherFamily::Aead2022)
            .unwrap_or(false)
        {
            out.push_str(&escape_userinfo(&self.cipher));
            out.push(':');
            out.push_str(&escape_userinfo_password(&self.password));
        } else {
            out.push_str(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(format!("{}:{}", self.cipher, self.password)),
            );
        }
        out.push('@');
        out.push_str(&format_authority(&self.server, self.port));
        if !self.plugin.name.is_empty() {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("plugin", &self.plugin.to_plugin_string());
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

impl Sip003 {
    pub fn parse(plugin: &str) -> Self {
        let (name, opts) = plugin.split_once(';').unwrap_or((plugin, ""));
        let name = match name {
            "obfs-local" | "simpleobfs" => "simple-obfs",
            value => value,
        };
        Self {
            name: name.to_owned(),
            opts: Sip003Opts::parse(opts),
        }
    }

    pub fn to_plugin_string(&self) -> String {
        let mut list = vec![self.name.clone()];
        if !self.opts.tls.is_empty() {
            list.push(self.opts.tls.clone());
        }
        if !self.opts.obfs.is_empty() {
            list.push(format!("obfs={}", self.opts.obfs));
        }
        if !self.opts.host.is_empty() {
            list.push(format!("obfs-host={}", self.opts.host));
        }
        if !self.opts.path.is_empty() {
            list.push(format!("obfs-uri={}", self.opts.path));
        }
        list.join(";")
    }
}

impl Sip003Opts {
    pub fn parse(opts: &str) -> Self {
        let mut parsed = Self::default();
        for field in opts.split(';') {
            if field.is_empty() {
                continue;
            }
            let (key, value) = field.split_once('=').unwrap_or((field, ""));
            match key {
                "tls" => parsed.tls = "tls".to_owned(),
                "obfs" | "mode" => parsed.obfs = value.to_owned(),
                "obfs-path" | "obfs-uri" | "path" => {
                    parsed.path = if value.starts_with('/') {
                        value.to_owned()
                    } else {
                        format!("{value}/")
                    };
                }
                "obfs-host" | "host" => parsed.host = value.to_owned(),
                _ => {}
            }
        }
        parsed
    }
}

fn parse_direct(raw: &str) -> Result<ShadowsocksLink, OutboundError> {
    if let Ok(parsed) = parse_direct_fast(raw) {
        return Ok(parsed);
    }

    let url = Url::parse(raw).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    match url.scheme() {
        "ss" | "shadowsocks" => {}
        scheme => {
            return Err(OutboundError::BadShadowsocks(format!(
                "unsupported scheme: {scheme}"
            )));
        }
    }
    let userinfo = parse_userinfo(&url)?;
    let cipher = userinfo.0.to_ascii_lowercase();
    let password = userinfo.1;
    let plugin = url
        .query_pairs()
        .find(|(key, _)| key.as_ref() == "plugin")
        .map(|(_, value)| Sip003::parse(&value))
        .unwrap_or_default();
    Ok(ShadowsocksLink {
        name: url.fragment().unwrap_or_default().to_owned(),
        server: url
            .host_str()
            .ok_or_else(|| OutboundError::BadShadowsocks("missing host".to_owned()))?
            .to_owned(),
        port: url
            .port()
            .ok_or_else(|| OutboundError::BadShadowsocks("missing port".to_owned()))?,
        password,
        cipher,
        udp: plugin.name.is_empty(),
        plugin,
        protocol: "shadowsocks".to_owned(),
    })
}

fn parse_direct_fast(raw: &str) -> Result<ShadowsocksLink, OutboundError> {
    let content = raw
        .strip_prefix("ss://")
        .or_else(|| raw.strip_prefix("shadowsocks://"))
        .ok_or_else(|| OutboundError::BadShadowsocks("missing scheme".to_owned()))?;
    let (without_fragment, name) = content.split_once('#').unwrap_or((content, ""));
    let (authority, query) = without_fragment
        .split_once('?')
        .unwrap_or((without_fragment, ""));
    if !query.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "query requires full parser".to_owned(),
        ));
    }
    let (userinfo, server_port) = authority
        .rsplit_once('@')
        .ok_or_else(|| OutboundError::BadShadowsocks("missing userinfo".to_owned()))?;
    let (cipher, password) = userinfo.split_once(':').ok_or_else(|| {
        OutboundError::BadShadowsocks("missing cipher/password separator".to_owned())
    })?;
    let (server, port) = split_host_port(server_port)?;
    Ok(ShadowsocksLink {
        name: name.to_owned(),
        server: server.to_owned(),
        port,
        password: percent_decode(password)?,
        cipher: percent_decode(cipher)?.to_ascii_lowercase(),
        udp: true,
        plugin: Sip003::default(),
        protocol: "shadowsocks".to_owned(),
    })
}

fn parse_userinfo(url: &Url) -> Result<(String, String), OutboundError> {
    if let Some(password) = url.password() {
        return Ok((percent_decode(url.username())?, percent_decode(password)?));
    }
    let username = url.username();
    if username.is_empty() {
        return Err(OutboundError::BadShadowsocks("missing userinfo".to_owned()));
    }
    let decoded = decode_base64_url(&percent_decode(username)?)?;
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let Some((cipher, password)) = decoded.split_once(':') else {
        return Err(OutboundError::BadShadowsocks(
            "missing cipher/password separator".to_owned(),
        ));
    };
    Ok((cipher.to_owned(), password.to_owned()))
}

fn parse_base64_wrapped(raw: &str) -> Result<ShadowsocksLink, OutboundError> {
    let Some(content) = raw.strip_prefix("ss://") else {
        return Err(OutboundError::BadShadowsocks(
            "unrecognized ss address".to_owned(),
        ));
    };
    let (left, fragment) = content.split_once('#').unwrap_or((content, ""));
    let decoded = decode_base64_std(left).or_else(|_| decode_base64_url(left))?;
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut rebuilt = format!("ss://{decoded}");
    if !fragment.is_empty() {
        rebuilt.push('#');
        rebuilt.push_str(fragment);
    }
    parse_direct(&rebuilt)
}

fn split_host_port(input: &str) -> Result<(&str, u16), OutboundError> {
    let (host, port) = if input.starts_with('[') {
        let (host, rest) = input.split_once(']').ok_or_else(|| {
            OutboundError::BadShadowsocks("missing IPv6 closing bracket".to_owned())
        })?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| OutboundError::BadShadowsocks("missing port".to_owned()))?;
        (&host[1..], port)
    } else {
        input
            .rsplit_once(':')
            .ok_or_else(|| OutboundError::BadShadowsocks("missing port".to_owned()))?
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| OutboundError::BadShadowsocks(format!("invalid port: {port}")))?;
    Ok((host, port))
}

fn decode_base64_url(input: &str) -> Result<Vec<u8>, OutboundError> {
    decode_base64_with_padding(input, &base64::engine::general_purpose::URL_SAFE_NO_PAD)
        .or_else(|_| decode_base64_with_padding(input, &base64::engine::general_purpose::URL_SAFE))
}

fn decode_base64_std(input: &str) -> Result<Vec<u8>, OutboundError> {
    decode_base64_with_padding(input, &base64::engine::general_purpose::STANDARD).or_else(|_| {
        decode_base64_with_padding(input, &base64::engine::general_purpose::STANDARD_NO_PAD)
    })
}

fn decode_base64_with_padding(
    input: &str,
    engine: &base64::engine::GeneralPurpose,
) -> Result<Vec<u8>, OutboundError> {
    engine
        .decode(input)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))
}

fn percent_decode(input: &str) -> Result<String, OutboundError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(OutboundError::BadShadowsocks(
                    "truncated percent escape".to_owned(),
                ));
            }
            let high = hex_nibble(bytes[i + 1])?;
            let low = hex_nibble(bytes[i + 2])?;
            out.push((high << 4) | low);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OutboundError::BadShadowsocks(format!(
            "bad percent escape byte: {byte}"
        ))),
    }
}

fn escape_userinfo(input: &str) -> String {
    input.to_owned()
}

fn escape_userinfo_password(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b':' => out.push_str("%3A"),
            _ => out.push(byte as char),
        }
    }
    out
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
