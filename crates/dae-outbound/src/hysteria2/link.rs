use std::borrow::Cow;

use crate::error::OutboundError;

use super::port_hopping::parse_port_union;

const UNSUPPORTED_TLS_QUERY_FIELDS: [&str; 4] = ["ca", "clientCertificate", "clientKey", "ech"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2Link {
    pub name: String,
    pub user: String,
    pub password: String,
    pub server: String,
    pub insecure: bool,
    pub sni: String,
    pub pin_sha256: String,
    pub obfs: String,
    pub obfs_password: String,
    pub max_tx: u64,
    pub max_rx: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2ServerContract {
    pub server: String,
    pub host: String,
    pub port: String,
    pub host_port: String,
    pub port_hopping: bool,
}

impl Hysteria2Link {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| OutboundError::BadHysteria2("missing scheme".to_owned()))?;
        if !matches!(scheme, "hysteria2" | "hy2") {
            return Err(OutboundError::BadHysteria2(format!(
                "unsupported scheme: {scheme}"
            )));
        }
        let (without_fragment, name) = split_once(rest, '#');
        let (authority_path, query_raw) = split_once(without_fragment, '?');
        let authority = authority_path.trim_end_matches('/');
        let (userinfo, server) = authority.rsplit_once('@').unwrap_or(("", authority));
        let (user, password) = parse_userinfo(userinfo)?;
        let query = url::form_urlencoded::parse(query_raw.as_bytes()).collect::<Vec<_>>();
        reject_unsupported_tls_fields(&query)?;
        let insecure = match query_value(&query, "insecure") {
            Some(value) if !value.is_empty() => parse_bool(&value)
                .ok_or_else(|| OutboundError::BadHysteria2("invalid insecure".to_owned()))?,
            _ => false,
        };
        let mut max_tx = 0;
        let mut max_rx = 0;
        if query_value(&query, "maxTx").is_some() && query_value(&query, "maxRx").is_some() {
            max_tx = parse_u64(query_value(&query, "maxTx").as_deref().unwrap_or(""))?;
            max_rx = parse_u64(query_value(&query, "maxRx").as_deref().unwrap_or(""))?;
        }
        let server = normalize_server_with_mport(server, query_value(&query, "mport").as_deref())?;
        Ok(Self {
            name: percent_decode(name)?,
            user,
            password,
            server,
            insecure,
            sni: query_value(&query, "sni").unwrap_or_default(),
            pin_sha256: query_value(&query, "pinSHA256").unwrap_or_default(),
            obfs: query_value(&query, "obfs").unwrap_or_default(),
            obfs_password: query_value(&query, "obfs-password")
                .or_else(|| query_value(&query, "obfsPassword"))
                .or_else(|| query_value(&query, "obfs_password"))
                .unwrap_or_default(),
            max_tx,
            max_rx,
        })
    }

    pub fn export_url(&self) -> String {
        let mut out = String::new();
        out.push_str("hysteria2://");
        out.push_str(&escape_userinfo(&self.user));
        if !self.password.is_empty() {
            out.push(':');
            out.push_str(&escape_userinfo(&self.password));
        }
        out.push('@');
        out.push_str(&self.server);
        let mut query = Vec::<(&str, Cow<'_, str>)>::new();
        if self.insecure {
            query.push(("insecure", Cow::Borrowed("1")));
        }
        if !self.sni.is_empty() {
            query.push(("sni", Cow::Borrowed(&self.sni)));
        }
        if !self.pin_sha256.is_empty() {
            query.push(("pinSHA256", Cow::Borrowed(&self.pin_sha256)));
        }
        if !self.obfs.is_empty() {
            query.push(("obfs", Cow::Borrowed(&self.obfs)));
        }
        if !self.obfs_password.is_empty() {
            query.push(("obfs-password", Cow::Borrowed(&self.obfs_password)));
        }
        if self.max_tx > 0 && self.max_rx > 0 {
            query.push(("maxTx", Cow::Owned(self.max_tx.to_string())));
            query.push(("maxRx", Cow::Owned(self.max_rx.to_string())));
        }
        query.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.as_ref().cmp(b.1.as_ref())));
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

    pub fn property_address(&self) -> String {
        self.server.clone()
    }
}

fn reject_unsupported_tls_fields(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
) -> Result<(), OutboundError> {
    for field in UNSUPPORTED_TLS_QUERY_FIELDS {
        if query
            .iter()
            .any(|(candidate, _)| candidate.as_ref() == field)
        {
            return Err(OutboundError::BadHysteria2(format!(
                "unsupported Hysteria2 TLS field: {field}"
            )));
        }
    }
    Ok(())
}

pub fn normalize_pin_sha256(input: &str) -> String {
    input
        .chars()
        .filter(|ch| *ch != ':' && *ch != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn server_contract(server: &str) -> Hysteria2ServerContract {
    let (host, port, host_port) = if let Some(index) = split_host_port_index(server) {
        (
            server[..index].to_owned(),
            server[index + 1..].to_owned(),
            server.to_owned(),
        )
    } else {
        (server.to_owned(), "443".to_owned(), format!("{server}:443"))
    };
    let port_hopping = is_port_hopping_port(&port);
    Hysteria2ServerContract {
        server: server.to_owned(),
        host,
        port,
        host_port,
        port_hopping,
    }
}

pub fn is_port_hopping_port(port: &str) -> bool {
    port.contains('-') || port.contains(',')
}

fn split_host_port_index(server: &str) -> Option<usize> {
    if server.starts_with('[') {
        let (_, tail) = server.split_once(']')?;
        if tail.starts_with(':') {
            return server.rfind(':');
        }
        return None;
    }
    server.rfind(':')
}

fn normalize_server_with_mport(server: &str, mport: Option<&str>) -> Result<String, OutboundError> {
    let Some(mport) = mport else {
        return Ok(server.to_owned());
    };
    let port_expr = mport.trim();
    if port_expr.is_empty() {
        return Err(OutboundError::BadHysteria2(
            "invalid Hysteria2 mport: empty port expression".to_owned(),
        ));
    }
    parse_port_union(port_expr).map_err(|err| {
        OutboundError::BadHysteria2(format!("invalid Hysteria2 mport {port_expr}: {err}"))
    })?;
    let host = split_host_port_index(server)
        .map(|index| &server[..index])
        .unwrap_or(server);
    Ok(format!("{host}:{port_expr}"))
}

fn split_once(input: &str, delimiter: char) -> (&str, &str) {
    input.split_once(delimiter).unwrap_or((input, ""))
}

fn parse_userinfo(input: &str) -> Result<(String, String), OutboundError> {
    let (user, password) = input.split_once(':').unwrap_or((input, ""));
    Ok((percent_decode(user)?, percent_decode(password)?))
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

fn parse_bool(input: &str) -> Option<bool> {
    match input {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn parse_u64(input: &str) -> Result<u64, OutboundError> {
    input
        .parse::<u64>()
        .map_err(|_| OutboundError::BadHysteria2(format!("invalid u64: {input}")))
}

fn percent_decode(input: &str) -> Result<String, OutboundError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(OutboundError::BadHysteria2(
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
    String::from_utf8(out).map_err(|err| OutboundError::BadHysteria2(err.to_string()))
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OutboundError::BadHysteria2(format!(
            "bad percent escape byte: {byte}"
        ))),
    }
}

fn escape_userinfo(input: &str) -> String {
    input.to_owned()
}
