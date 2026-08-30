use serde_json::Value;
use url::Url;

use crate::error::OutboundError;
use crate::shared_transport::{
    EchConfigList, GrpcMode, Mldsa65VerifyKey, parse_optional_ech_config_list,
    parse_optional_mldsa65_verify_key,
};

use super::contract::is_xtls_rprx_vision_flow;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VLESSLink {
    pub ps: String,
    pub add: String,
    pub port: String,
    pub id: String,
    pub net: String,
    pub r#type: String,
    pub host: String,
    pub sni: String,
    pub path: String,
    pub xhttp_mode: String,
    pub xhttp_extra: String,
    pub grpc_mode: GrpcMode,
    pub grpc_authority: String,
    pub tls: String,
    pub flow: String,
    pub alpn: String,
    pub allow_insecure: bool,
    pub fingerprint: String,
    pub public_key: String,
    pub short_id: String,
    pub spider_x: String,
    pub ech: Option<EchConfigList>,
    pub mldsa65_verify: Option<Mldsa65VerifyKey>,
    pub mux: bool,
    /// Xray VLESS Encryption account string.  `none`/empty keeps the
    /// legacy unencrypted VLESS record path; any other value is parsed and
    /// validated by the resident builder before a connection is published.
    pub encryption: String,
    pub protocol: String,
}

impl VLESSLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let url = Url::parse(raw).map_err(|err| OutboundError::BadVless(err.to_string()))?;
        if url.scheme() != "vless" {
            return Err(OutboundError::BadVless(format!(
                "unsupported scheme: {}",
                url.scheme()
            )));
        }
        let query = url.query_pairs().collect::<Vec<_>>();
        let mut parsed = Self {
            ps: url.fragment().unwrap_or_default().to_owned(),
            add: url
                .host_str()
                .ok_or_else(|| OutboundError::BadVless("missing host".to_owned()))?
                .to_owned(),
            port: url.port().map(|port| port.to_string()).unwrap_or_default(),
            id: url.username().to_owned(),
            net: query_value(&query, "type").unwrap_or_default(),
            r#type: query_value(&query, "headerType").unwrap_or_default(),
            host: query_value(&query, "host").unwrap_or_default(),
            sni: query_value(&query, "sni").unwrap_or_default(),
            path: query_value(&query, "path").unwrap_or_default(),
            xhttp_mode: String::new(),
            xhttp_extra: query_value(&query, "extra").unwrap_or_default(),
            grpc_mode: GrpcMode::Gun,
            grpc_authority: String::new(),
            tls: query_value(&query, "security").unwrap_or_default(),
            flow: canonical_flow(&query_value(&query, "flow").unwrap_or_default()),
            alpn: query_value(&query, "alpn").unwrap_or_default(),
            allow_insecure: parse_allow_insecure(&query),
            fingerprint: query_value(&query, "fp").unwrap_or_default(),
            public_key: query_value(&query, "pbk").unwrap_or_default(),
            short_id: query_value(&query, "sid").unwrap_or_default(),
            spider_x: query_value(&query, "spx").unwrap_or_default(),
            ech: parse_optional_ech_config_list(&query_value(&query, "ech").unwrap_or_default())
                .map_err(|err| OutboundError::BadVless(err.to_string()))?,
            mldsa65_verify: parse_optional_mldsa65_verify_key(
                &query_value(&query, "pqv").unwrap_or_default(),
            )
            .map_err(|err| OutboundError::BadVless(err.to_string()))?,
            mux: parse_mux_enabled(&query),
            encryption: query_value(&query, "encryption").unwrap_or_default(),
            protocol: "vless".to_owned(),
        };
        if parsed.net.is_empty() {
            parsed.net = "tcp".to_owned();
        }
        if parsed.net == "grpc" {
            parsed.path = query_value(&query, "serviceName").unwrap_or_default();
            parsed.grpc_mode =
                GrpcMode::parse_link_value(&query_value(&query, "mode").unwrap_or_default())
                    .map_err(|err| OutboundError::BadVless(err.to_string()))?;
            parsed.grpc_authority = query_value(&query, "authority").unwrap_or_default();
        }
        if parsed.net == "xhttp" {
            parsed.xhttp_mode = query_value(&query, "mode").unwrap_or_default();
        }
        if parsed.net == "meek" {
            parsed.path = query_value(&query, "url").unwrap_or_default();
        }
        if parsed.r#type.is_empty() {
            parsed.r#type = "none".to_owned();
        }
        if parsed.tls.is_empty() {
            parsed.tls = "none".to_owned();
        }
        if parsed.r#type == "mkcp" || parsed.r#type == "kcp" {
            parsed.path = query_value(&query, "seed").unwrap_or_default();
        }
        Ok(parsed)
    }

    pub fn validate_flow_client(&self, is_client: bool) -> Result<(), OutboundError> {
        match self.flow.as_str() {
            "" => Ok(()),
            flow if is_xtls_rprx_vision_flow(flow) && is_client => Ok(()),
            flow if is_xtls_rprx_vision_flow(flow) => Err(OutboundError::BadVless(format!(
                "unsupported server mode xtls flow type: {}",
                self.flow
            ))),
            flow => Err(OutboundError::BadVless(format!(
                "unsupported xtls flow type: {flow}"
            ))),
        }
    }

    pub fn validate_transport_contract(&self) -> Result<(), OutboundError> {
        if self.net == "tcp" && self.r#type != "none" && !self.r#type.is_empty() {
            return Err(OutboundError::BadVless(format!(
                "unexpected field: type: {}",
                self.r#type
            )));
        }
        Ok(())
    }

    pub fn address(&self) -> String {
        format_authority(&self.add, &self.port)
    }

    pub fn export_url(&self) -> String {
        let mut query = Vec::<(String, String)>::new();
        push_if_non_empty(&mut query, "type", &self.net);
        push_if_non_empty(&mut query, "security", &self.tls);
        match self.net.as_str() {
            "websocket" | "ws" | "http" | "h2" | "httpupgrade" | "xhttp" => {
                push_if_non_empty(&mut query, "path", &self.path);
                push_if_non_empty(&mut query, "host", &self.host);
                if self.net == "xhttp" {
                    let mode = canonical_xhttp_mode(&self.xhttp_mode);
                    if !mode.is_empty() && mode != "auto" {
                        push_if_non_empty(&mut query, "mode", &mode);
                    }
                    let extra = canonical_xhttp_extra(&self.xhttp_extra);
                    if !extra.is_empty() && extra != "{}" {
                        push_if_non_empty(&mut query, "extra", &extra);
                    }
                }
            }
            "mkcp" | "kcp" => {
                push_if_non_empty(&mut query, "headerType", &self.r#type);
                push_if_non_empty(&mut query, "seed", &self.path);
            }
            "tcp" => {
                push_if_non_empty(&mut query, "headerType", &self.r#type);
                push_if_non_empty(&mut query, "host", &self.host);
                push_if_non_empty(&mut query, "path", &self.path);
            }
            "grpc" => {
                push_if_non_empty(&mut query, "serviceName", &self.path);
                if self.grpc_mode != GrpcMode::Gun {
                    push_if_non_empty(&mut query, "mode", self.grpc_mode.link_value());
                }
                push_if_non_empty(&mut query, "authority", &self.grpc_authority);
            }
            "meek" => push_if_non_empty(&mut query, "url", &self.path),
            _ => {}
        }
        if self.tls != "none" {
            push_if_non_empty(&mut query, "sni", &self.sni);
            push_if_non_empty(&mut query, "alpn", &self.alpn);
            push_if_non_empty(&mut query, "flow", &canonical_flow(&self.flow));
            push_if_non_empty(&mut query, "fp", &self.fingerprint);
            if let Some(ech) = &self.ech {
                push_if_non_empty(&mut query, "ech", ech.canonical_base64());
            }
            query.push((
                "allowInsecure".to_owned(),
                if self.allow_insecure { "1" } else { "0" }.to_owned(),
            ));
            if self.tls == "reality" {
                push_if_non_empty(&mut query, "pbk", &self.public_key);
                push_if_non_empty(&mut query, "sid", &self.short_id);
                push_if_non_empty(&mut query, "spx", &self.spider_x);
                if let Some(mldsa65_verify) = &self.mldsa65_verify {
                    push_if_non_empty(&mut query, "pqv", mldsa65_verify.canonical_base64());
                }
            }
        }
        if self.mux {
            query.push(("mux".to_owned(), "1".to_owned()));
        }
        push_if_non_empty(&mut query, "encryption", &self.encryption);
        query.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let mut out = String::new();
        out.push_str("vless://");
        out.push_str(&self.id);
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
        if !self.ps.is_empty() {
            out.push('#');
            out.push_str(&self.ps);
        }
        out
    }
}

fn parse_mux_enabled(query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)]) -> bool {
    query_value(query, "mux")
        .or_else(|| query_value(query, "muxEnabled"))
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
}

fn canonical_flow(flow: &str) -> String {
    let flow = flow.trim();
    if flow.eq_ignore_ascii_case("none") {
        String::new()
    } else {
        flow.to_owned()
    }
}

fn canonical_xhttp_mode(mode: &str) -> String {
    let mode = mode.trim().to_ascii_lowercase();
    match mode.as_str() {
        "" | "auto" | "stream-up" | "stream-one" | "packet-up" => mode,
        _ => mode,
    }
}

fn canonical_xhttp_extra(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|value| serde_json::to_string(&value).ok())
        .unwrap_or_else(|| raw.to_owned())
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
        "insecure",
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

fn format_authority(host: &str, port: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
