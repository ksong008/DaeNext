use url::Url;

use crate::error::OutboundError;

use super::contract::{ALLOW_INSECURE_ALIASES, HTTPS_DEFAULT_ALPN_QUERY_VALUE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpProxyLink {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub sni: String,
    pub protocol: HttpScheme,
    pub allow_insecure: bool,
    pub host: String,
    pub path: String,
    pub transport: bool,
    pub tls_implementation: String,
    pub alpn: String,
    pub utls_imitate: String,
}

impl HttpProxyLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let url = Url::parse(raw).map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;
        let protocol = match url.scheme() {
            "http" => HttpScheme::Http,
            "https" => HttpScheme::Https,
            scheme => {
                return Err(OutboundError::BadHttpProxy(format!(
                    "unsupported scheme: {scheme}"
                )));
            }
        };
        let server = url
            .host_str()
            .ok_or_else(|| OutboundError::BadHttpProxy("missing host".to_owned()))?
            .to_owned();
        let port = url.port().unwrap_or_else(|| protocol.default_port());
        let query = url.query_pairs().collect::<Vec<_>>();
        Ok(Self {
            name: url.fragment().unwrap_or_default().to_owned(),
            server,
            port,
            username: url.username().to_owned(),
            password: url.password().unwrap_or_default().to_owned(),
            sni: query_value(&query, "sni").unwrap_or_default(),
            protocol,
            allow_insecure: parse_allow_insecure(&query),
            host: query_value(&query, "host").unwrap_or_default(),
            path: normalize_path(url.path()),
            transport: query_value(&query, "transport")
                .and_then(|value| parse_bool(&value))
                .unwrap_or(false),
            tls_implementation: query_value(&query, "tlsImplementation")
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "tls".to_owned()),
            alpn: query_value(&query, "alpn")
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| HTTPS_DEFAULT_ALPN_QUERY_VALUE.to_owned()),
            utls_imitate: query_value(&query, "utlsImitate").unwrap_or_default(),
        })
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    pub fn export_url(&self) -> String {
        let mut out = String::new();
        out.push_str(self.protocol.as_str());
        out.push_str("://");
        if !self.username.is_empty() {
            out.push_str(&self.username);
            if !self.password.is_empty() {
                out.push(':');
                out.push_str(&self.password);
            }
            out.push('@');
        }
        out.push_str(&self.address());
        let mut query = Vec::new();
        if self.allow_insecure {
            query.push("allowInsecure=1".to_owned());
        }
        if !self.sni.is_empty() {
            query.push(format!("sni={}", self.sni));
        }
        if !query.is_empty() {
            out.push('?');
            out.push_str(&query.join("&"));
        }
        if !self.name.is_empty() {
            out.push('#');
            out.push_str(&self.name);
        }
        out
    }

    pub fn effective_sni(&self) -> String {
        if self.sni.is_empty() {
            self.server.clone()
        } else {
            self.sni.clone()
        }
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
    ALLOW_INSECURE_ALIASES.iter().any(|key| {
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

fn normalize_path(path: &str) -> String {
    if path.is_empty() || !path.starts_with('/') {
        format!("/{path}")
    } else {
        path.to_owned()
    }
}
