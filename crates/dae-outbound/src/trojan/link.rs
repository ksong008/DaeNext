use url::Url;

use crate::error::OutboundError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrojanTransportType {
    None,
    Ws,
    Grpc,
    HttpUpgrade,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanLink {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: String,
    pub transport_type: String,
    pub encryption: String,
    pub host: String,
    pub path: String,
    pub service_name: String,
    pub allow_insecure: bool,
    pub protocol: String,
}

impl TrojanLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let url = Url::parse(raw)
            .map_err(|_| OutboundError::BadTrojan("invalid trojan format".to_owned()))?;
        match url.scheme() {
            "trojan" | "trojan-go" => {}
            scheme => {
                return Err(OutboundError::BadTrojan(format!(
                    "unsupported scheme: {scheme}"
                )));
            }
        }
        let query = url.query_pairs().collect::<Vec<_>>();
        let server = url
            .host_str()
            .ok_or_else(|| OutboundError::BadTrojan("missing host".to_owned()))?
            .to_owned();
        let port = url
            .port()
            .ok_or_else(|| OutboundError::BadTrojan("missing port".to_owned()))?;
        let mut sni = query_value(&query, "peer").unwrap_or_default();
        if sni.is_empty() {
            sni = query_value(&query, "sni").unwrap_or_default();
        }
        if sni.is_empty() {
            sni = server.clone();
        }
        let transport_type = query_value(&query, "type").unwrap_or_default();
        let protocol = if url.scheme() == "trojan-go" || !transport_type.is_empty() {
            "trojan-go"
        } else {
            "trojan"
        };
        let mut link = Self {
            name: url.fragment().unwrap_or_default().to_owned(),
            server,
            port,
            password: percent_decode(url.username())?,
            sni,
            transport_type: String::new(),
            encryption: String::new(),
            host: String::new(),
            path: String::new(),
            service_name: String::new(),
            allow_insecure: parse_allow_insecure(&query),
            protocol: protocol.to_owned(),
        };
        if protocol == "trojan-go" {
            link.encryption = query_value(&query, "encryption").unwrap_or_default();
            link.host = query_value(&query, "host").unwrap_or_default();
            link.path = query_value(&query, "path").unwrap_or_default();
            link.transport_type = transport_type;
            link.service_name = query_value(&query, "serviceName").unwrap_or_default();
            if link.transport_type == "grpc" && link.service_name.is_empty() {
                link.service_name = link.path.clone();
            }
        }
        Ok(link)
    }

    pub fn address(&self) -> String {
        format_authority(&self.server, self.port)
    }

    pub fn transport_kind(&self) -> TrojanTransportType {
        match self.transport_type.as_str() {
            "" => TrojanTransportType::None,
            value if value.eq_ignore_ascii_case("tcp") => TrojanTransportType::None,
            "ws" => TrojanTransportType::Ws,
            "grpc" => TrojanTransportType::Grpc,
            "httpupgrade" => TrojanTransportType::HttpUpgrade,
            _ => TrojanTransportType::Other,
        }
    }

    pub fn export_url(&self) -> String {
        let mut out = String::new();
        out.push_str(if self.protocol == "trojan-go" {
            "trojan-go://"
        } else {
            "trojan://"
        });
        out.push_str(&escape_userinfo(&self.password));
        out.push('@');
        out.push_str(&self.address());

        let mut query = Vec::<(String, String)>::new();
        if self.allow_insecure {
            query.push(("allowInsecure".to_owned(), "1".to_owned()));
        }
        if !self.sni.is_empty() {
            query.push(("sni".to_owned(), self.sni.clone()));
        }
        if self.protocol == "trojan-go" {
            push_if_non_empty(&mut query, "host", &self.host);
            push_if_non_empty(&mut query, "encryption", &self.encryption);
            push_if_non_empty(&mut query, "type", &self.transport_type);
            if self.transport_type == "grpc" {
                push_if_non_empty(&mut query, "serviceName", &self.service_name);
            } else {
                push_if_non_empty(&mut query, "path", &self.path);
            }
        }
        query.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
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

fn push_if_non_empty(query: &mut Vec<(String, String)>, key: &str, value: &str) {
    if !value.is_empty() {
        query.push((key.to_owned(), value.to_owned()));
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
    [
        "allowInsecure",
        "allow_insecure",
        "allowinsecure",
        "skipVerify",
    ]
    .iter()
    .any(|key| {
        query_value(query, key)
            .and_then(|value| parse_bool(&value))
            .unwrap_or(false)
    })
}

fn parse_bool(input: &str) -> Option<bool> {
    match input {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn percent_decode(input: &str) -> Result<String, OutboundError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(OutboundError::BadTrojan(
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
    String::from_utf8(out).map_err(|err| OutboundError::BadTrojan(err.to_string()))
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OutboundError::BadTrojan(format!(
            "bad percent escape byte: {byte}"
        ))),
    }
}

fn escape_userinfo(input: &str) -> String {
    input.to_owned()
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
