use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessLink {
    pub ps: String,
    pub add: String,
    pub port: String,
    pub id: String,
    pub aid: String,
    pub net: String,
    pub r#type: String,
    pub host: String,
    pub sni: String,
    pub path: String,
    pub tls: String,
    pub allow_insecure: bool,
    pub fingerprint: String,
    pub v: String,
    pub protocol: String,
}

impl VMessLink {
    pub fn parse(raw: &str) -> Result<Self, OutboundError> {
        let Some(payload) = raw.strip_prefix("vmess://") else {
            return Err(OutboundError::BadVmess("unsupported scheme".to_owned()));
        };
        let b64 = payload.split('?').next().unwrap_or_default();
        let decoded = decode_base64(b64)?;
        let mut parsed = if decoded.trim_start().starts_with('{') {
            parse_json(&decoded)?
        } else {
            parse_legacy(raw, &decoded)?
        };
        parsed.normalize();
        Ok(parsed)
    }

    pub fn validate_aead(&self) -> Result<(), OutboundError> {
        if self.aid != "0" && !self.aid.is_empty() {
            return Err(OutboundError::BadVmess(format!(
                "unexpected field: aid: {}, we only support AEAD encryption",
                self.aid
            )));
        }
        Ok(())
    }

    pub fn validate_transport(&self) -> Result<(), OutboundError> {
        if self.tls == "reality" {
            return Err(OutboundError::BadVmess(
                "only VLESS supports reality".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn address(&self) -> String {
        format_authority(&self.add, &self.port)
    }

    pub fn export_url(&self) -> String {
        let json = format!(
            "{{\"ps\":{},\"add\":{},\"port\":{},\"id\":{},\"aid\":{},\"net\":{},\"type\":{},\"host\":{},\"sni\":{},\"path\":{},\"tls\":{},\"allowInsecure\":{},\"Fingerprint\":{},\"v\":{},\"protocol\":{}}}",
            json_string(&self.ps),
            json_string(&self.add),
            json_string(&self.port),
            json_string(&self.id),
            json_string(&self.aid),
            json_string(&self.net),
            json_string(&self.r#type),
            json_string(&self.host),
            json_string(&self.sni),
            json_string(&self.path),
            json_string(&self.tls),
            self.allow_insecure,
            json_string(&self.fingerprint),
            json_string("2"),
            json_string("vmess"),
        );
        let mut encoded = base64::engine::general_purpose::STANDARD.encode(json);
        if encoded.ends_with('=') {
            encoded.pop();
        }
        format!("vmess://{encoded}")
    }

    fn normalize(&mut self) {
        if self.host.starts_with('/') && self.path.is_empty() {
            self.path.clone_from(&self.host);
            self.host.clear();
        }
        if self.aid.is_empty() {
            self.aid = "0".to_owned();
        }
        self.protocol = "vmess".to_owned();
        self.v = "2".to_owned();
    }
}

fn parse_json(raw: &str) -> Result<VMessLink, OutboundError> {
    let fields: VMessJsonFields =
        serde_json::from_str(raw).map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let fingerprint = fields.fingerprint.or_else_empty(fields.fp);
    Ok(VMessLink {
        ps: fields.ps,
        add: fields.add,
        port: fields.port,
        id: fields.id,
        aid: fields.aid,
        net: fields.net,
        r#type: fields.r#type,
        host: fields.host,
        sni: fields.sni,
        path: fields.path,
        tls: fields.tls,
        allow_insecure: fields.allow_insecure,
        fingerprint,
        v: fields.v,
        protocol: fields.protocol,
    })
}

#[derive(Default, Deserialize)]
struct VMessJsonFields {
    #[serde(default)]
    ps: String,
    #[serde(default)]
    add: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    aid: String,
    #[serde(default)]
    net: String,
    #[serde(default, rename = "type")]
    r#type: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    tls: String,
    #[serde(default, rename = "allowInsecure")]
    allow_insecure: bool,
    #[serde(default, rename = "Fingerprint")]
    fingerprint: String,
    #[serde(default)]
    fp: String,
    #[serde(default)]
    v: String,
    #[serde(default)]
    protocol: String,
}

fn parse_legacy(raw_url: &str, decoded: &str) -> Result<VMessLink, OutboundError> {
    let url = Url::parse(raw_url).map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let query = url.query_pairs().collect::<Vec<_>>();
    let Some((_, address)) = decoded.split_once(':') else {
        return Err(OutboundError::BadVmess(
            "unrecognized vmess address".to_owned(),
        ));
    };
    let Some((id, endpoint)) = address.rsplit_once('@') else {
        return Err(OutboundError::BadVmess(
            "unrecognized vmess address".to_owned(),
        ));
    };
    let Some((add, port)) = endpoint.rsplit_once(':') else {
        return Err(OutboundError::BadVmess(
            "unrecognized vmess address".to_owned(),
        ));
    };
    let mut ps = query_value(&query, "remarks").unwrap_or_default();
    if ps.is_empty() {
        ps = query_value(&query, "remark").unwrap_or_default();
    }
    let obfs = query_value(&query, "obfs").unwrap_or_default();
    let obfs_param = query_value(&query, "obfsParam").unwrap_or_default();
    let mut path = query_value(&query, "path").unwrap_or_default();
    let mut host = json_host(&obfs_param);
    let mut net = obfs;
    if net == "websocket" {
        net = "ws".to_owned();
    }
    if matches!(net.as_str(), "kcp" | "mkcp") {
        if let Some(seed) = json_key(&obfs_param, "seed") {
            path = seed;
        }
        host.clear();
    }
    let mut aid = query_value(&query, "alterId").unwrap_or_default();
    if aid.is_empty() {
        aid = query_value(&query, "aid").unwrap_or_default();
    }
    let tls = if query_value(&query, "tls").as_deref() == Some("1") {
        "tls".to_owned()
    } else {
        String::new()
    };
    Ok(VMessLink {
        ps,
        add: add.to_owned(),
        port: port.to_owned(),
        id: id.to_owned(),
        aid,
        net,
        r#type: String::new(),
        host,
        sni: query_value(&query, "peer").unwrap_or_default(),
        path,
        tls,
        allow_insecure: false,
        fingerprint: String::new(),
        v: String::new(),
        protocol: String::new(),
    })
}

fn decode_base64(input: &str) -> Result<String, OutboundError> {
    decode_base64_with(input, &base64::engine::general_purpose::STANDARD)
        .or_else(|_| decode_base64_with(input, &base64::engine::general_purpose::URL_SAFE))
}

fn decode_base64_with(
    input: &str,
    engine: &base64::engine::GeneralPurpose,
) -> Result<String, OutboundError> {
    let mut padded = input.trim().to_owned();
    if !padded.len().is_multiple_of(4) {
        padded.extend(std::iter::repeat_n('=', 4 - padded.len() % 4));
    }
    let decoded = engine
        .decode(padded)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    String::from_utf8(decoded).map_err(|err| OutboundError::BadVmess(err.to_string()))
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

trait OrElseEmpty {
    fn or_else_empty(self, other: String) -> String;
}

impl OrElseEmpty for String {
    fn or_else_empty(self, other: String) -> String {
        if self.is_empty() { other } else { self }
    }
}

fn json_host(input: &str) -> String {
    json_key(input, "host").unwrap_or_default()
}

fn json_key(input: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(input)
        .ok()
        .and_then(|value| value.get(key).and_then(Value::as_str).map(str::to_owned))
}

fn json_string(input: &str) -> String {
    serde_json::to_string(input).unwrap_or_else(|_| "\"\"".to_owned())
}

fn format_authority(host: &str, port: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
