use std::collections::BTreeMap;

use percent_encoding::percent_decode_str;
use url::Url;

use crate::error::OutboundError;
use crate::shared_transport::masque::MasqueUriTemplate;

const MASQUE_SCHEME: &str = "masque";
const MASQUE_H2_ALPN: &str = "h2";
const MASQUE_H3_ALPN: &str = "h3";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MasqueTransport {
    H2,
    H3,
}

impl MasqueTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }

    pub fn alpn(self) -> &'static str {
        match self {
            Self::H2 => MASQUE_H2_ALPN,
            Self::H3 => MASQUE_H3_ALPN,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MasqueAuthentication {
    None,
    Basic { username: String, password: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasqueLink {
    pub raw: String,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub transport: MasqueTransport,
    pub target_template: MasqueUriTemplate,
    pub sni: String,
    pub allow_insecure: bool,
    pub authentication: MasqueAuthentication,
}

impl MasqueLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let url = Url::parse(raw).map_err(bad_masque)?;
        if url.scheme() != MASQUE_SCHEME {
            return Err(bad_masque(format!(
                "unsupported scheme {}; CONNECT-UDP requires an explicit {MASQUE_SCHEME} source shape",
                url.scheme()
            )));
        }
        let server = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| bad_masque("missing proxy host"))?
            .to_owned();
        let port = url
            .port()
            .ok_or_else(|| bad_masque("missing explicit proxy port"))?;
        if !matches!(url.path(), "" | "/") {
            return Err(bad_masque(
                "proxy URL path is ambiguous; provide the target URI Template in the template query parameter",
            ));
        }

        let query = unique_query(&url)?;
        reject_unknown_query_keys(&query)?;
        let transport = match required_query(&query, "transport")? {
            "h2" => MasqueTransport::H2,
            "h3" => MasqueTransport::H3,
            value => {
                return Err(bad_masque(format!(
                    "unsupported transport {value:?}; expected h2 or h3"
                )));
            }
        };
        let target_template =
            MasqueUriTemplate::parse(required_query(&query, "template")?).map_err(bad_masque)?;
        let authentication = parse_authentication(&url, &query)?;
        let allow_insecure = match query.get("allowInsecure") {
            Some(value) => parse_bool(value).ok_or_else(|| {
                bad_masque(format!(
                    "invalid allowInsecure value {value:?}; expected a boolean"
                ))
            })?,
            None => false,
        };
        let sni = query
            .get("sni")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| server.clone());

        Ok(Self {
            raw: raw.to_owned(),
            name: url.fragment().unwrap_or_default().to_owned(),
            server,
            port,
            transport,
            target_template,
            sni,
            allow_insecure,
            authentication,
        })
    }

    pub fn address(&self) -> String {
        if self.server.contains(':') && !self.server.starts_with('[') {
            format!("[{}]:{}", self.server, self.port)
        } else {
            format!("{}:{}", self.server, self.port)
        }
    }

    pub fn export_url(&self) -> String {
        self.raw.clone()
    }
}

fn unique_query(url: &Url) -> Result<BTreeMap<String, String>, OutboundError> {
    let mut query = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        let key = key.into_owned();
        if query.insert(key.clone(), value.into_owned()).is_some() {
            return Err(bad_masque(format!("duplicate query parameter {key:?}")));
        }
    }
    Ok(query)
}

fn reject_unknown_query_keys(query: &BTreeMap<String, String>) -> Result<(), OutboundError> {
    const ALLOWED: &[&str] = &["allowInsecure", "auth", "sni", "template", "transport"];
    if let Some(key) = query.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(bad_masque(format!("unsupported query parameter {key:?}")));
    }
    Ok(())
}

fn required_query<'a>(
    query: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, OutboundError> {
    query
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| bad_masque(format!("missing required {key} query parameter")))
}

fn parse_authentication(
    url: &Url,
    query: &BTreeMap<String, String>,
) -> Result<MasqueAuthentication, OutboundError> {
    let username = decode_userinfo(url.username())?;
    let password = url
        .password()
        .map(decode_userinfo)
        .transpose()?
        .unwrap_or_default();
    match required_query(query, "auth")? {
        "none" if username.is_empty() && password.is_empty() => Ok(MasqueAuthentication::None),
        "none" => Err(bad_masque(
            "auth=none cannot be combined with URL user information",
        )),
        "basic" if username.is_empty() => {
            Err(bad_masque("auth=basic requires a non-empty URL username"))
        }
        "basic" => Ok(MasqueAuthentication::Basic { username, password }),
        value => Err(bad_masque(format!(
            "unsupported authentication {value:?}; expected none or basic"
        ))),
    }
}

fn decode_userinfo(value: &str) -> Result<String, OutboundError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|err| bad_masque(format!("invalid UTF-8 in URL user information: {err}")))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" | "True" | "TRUE" => Some(true),
        "0" | "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

fn bad_masque(value: impl ToString) -> OutboundError {
    OutboundError::BadMasque(value.to_string())
}

#[cfg(test)]
mod tests;
