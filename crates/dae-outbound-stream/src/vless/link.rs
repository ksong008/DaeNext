use dae_outbound_core::tls_options::parse_allow_insecure;
use dae_outbound_core::vless::mux::{VlessMuxOptions, VlessUdp443Policy};
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
    pub allow_insecure: Option<bool>,
    pub fingerprint: String,
    pub public_key: String,
    pub short_id: String,
    pub spider_x: String,
    pub ech: Option<EchConfigList>,
    pub mldsa65_verify: Option<Mldsa65VerifyKey>,
    pub mux: bool,
    pub mux_options: VlessMuxOptions,
    pub hysteria_auth: String,
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
            net: canonical_transport(query_value(&query, "type").unwrap_or_default()),
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
            allow_insecure: parse_allow_insecure(&query)
                .map_err(|err| OutboundError::BadVless(err.to_owned()))?,
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
            mux_options: parse_mux_options(&query)?,
            hysteria_auth: query_value(&query, "auth").unwrap_or_default(),
            encryption: query_value(&query, "encryption").unwrap_or_default(),
            protocol: "vless".to_owned(),
        };
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
        if matches!(parsed.net.as_str(), "mkcp" | "kcp") {
            parsed.path = query_value(&query, "seed").unwrap_or_default();
        }
        if parsed.net == "xdrive" {
            match query_value(&query, "service").as_deref() {
                Some("local") => {
                    parsed.path = query_value(&query, "remoteFolder").unwrap_or_default()
                }
                None => parsed.path.clear(),
                Some(_) => {
                    return Err(OutboundError::BadVless(
                        "unsupported VLESS XDrive service".to_owned(),
                    ));
                }
            }
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
            "hysteria" => push_if_non_empty(&mut query, "auth", &self.hysteria_auth),
            "xdrive" if !self.path.is_empty() => {
                query.push(("service".to_owned(), "local".to_owned()));
                push_if_non_empty(&mut query, "remoteFolder", &self.path);
            }
            _ => {}
        }
        push_if_non_empty(&mut query, "flow", &canonical_flow(&self.flow));
        if self.tls != "none" {
            push_if_non_empty(&mut query, "sni", &self.sni);
            push_if_non_empty(&mut query, "alpn", &self.alpn);
            push_if_non_empty(&mut query, "fp", &self.fingerprint);
            if let Some(ech) = &self.ech {
                push_if_non_empty(&mut query, "ech", ech.canonical_base64());
            }
            if let Some(insecure) = self.allow_insecure {
                query.push(("allowInsecure".to_owned(), u8::from(insecure).to_string()));
            }
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
        if let Some(value) = self.mux_options.concurrency {
            query.push(("concurrency".to_owned(), value.to_string()));
        }
        if let Some(value) = self.mux_options.xudp_concurrency {
            query.push(("xudpConcurrency".to_owned(), value.to_string()));
        }
        if let Some(value) = self.mux_options.udp443 {
            query.push(("xudpProxyUDP443".to_owned(), value.as_str().to_owned()));
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

fn canonical_transport(net: String) -> String {
    match net.as_str() {
        "" | "raw" => "tcp".to_owned(),
        "splithttp" => "xhttp".to_owned(),
        "kcp" => "mkcp".to_owned(),
        _ => net,
    }
}

fn parse_mux_enabled(query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)]) -> bool {
    query_value(query, "mux")
        .or_else(|| query_value(query, "muxEnabled"))
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
}

fn parse_mux_options(
    query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
) -> Result<VlessMuxOptions, OutboundError> {
    let concurrency = |field| {
        query_value(query, field)
            .map(|value| {
                value.parse::<i16>().map_err(|_| {
                    OutboundError::BadVless(format!(
                        "invalid VLESS mux {field}: expected a signed 16-bit integer"
                    ))
                })
            })
            .transpose()
    };
    let udp443 = query_value(query, "xudpProxyUDP443")
        .map(|value| {
            VlessUdp443Policy::parse(&value).ok_or_else(|| {
                OutboundError::BadVless(
                    "invalid VLESS mux xudpProxyUDP443: expected reject, allow, or skip".to_owned(),
                )
            })
        })
        .transpose()?;
    Ok(VlessMuxOptions {
        concurrency: concurrency("concurrency")?,
        xudp_concurrency: concurrency("xudpConcurrency")?,
        udp443,
    })
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
        .and_then(|mut value| {
            canonical_xhttp_reality_password(&mut value);
            serde_json::to_string(&value).ok()
        })
        .unwrap_or_else(|| raw.to_owned())
}

fn canonical_xhttp_reality_password(extra: &mut Value) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let Some(download) = extra.get_mut("downloadSettings") else {
        return;
    };
    if download.get("security").and_then(Value::as_str) != Some("reality") {
        return;
    }
    let Some(reality) = download
        .get_mut("realitySettings")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    // Export must not turn a type error or invalid effective password into a
    // valid node. Keep such input intact for the resident admission checks.
    if ["password", "publicKey"].iter().any(|key| {
        reality
            .get(*key)
            .is_some_and(|v| !v.is_null() && !v.is_string())
    }) {
        return;
    }
    let effective = reality
        .get("password")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .or_else(|| {
            reality
                .get("publicKey")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
        });
    let Some(key) = effective
        .and_then(|value| crate::ir::reality_pbk_decode(value).ok())
        .filter(|key| key.len() == 32)
    else {
        return;
    };
    // Keep the established publicKey spelling for stable identities of older
    // links. The effective key is shared by export, node dedup and XMUX keys.
    reality.remove("password");
    reality.insert(
        "publicKey".into(),
        Value::String(URL_SAFE_NO_PAD.encode(key)),
    );
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

fn format_authority(host: &str, port: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod transport_alias_tests {
    use super::VLESSLink;

    #[test]
    fn vless_mux_options_preserve_signed_values_and_udp443_on_export() {
        use dae_outbound_core::vless::mux::VlessUdp443Policy;

        let base = "vless://test@example.invalid:443?security=tls&mux=1";
        let link = VLESSLink::parse(&format!(
            "{base}&concurrency=-1&xudpConcurrency=0&xudpProxyUDP443=skip"
        ))
        .unwrap();
        assert_eq!(link.mux_options.concurrency, Some(-1));
        assert_eq!(link.mux_options.xudp_concurrency, Some(0));
        assert_eq!(link.mux_options.udp443, Some(VlessUdp443Policy::Skip));
        assert_eq!(VLESSLink::parse(&link.export_url()).unwrap(), link);
        for invalid in [
            "concurrency=32768",
            "xudpConcurrency=1.5",
            "xudpProxyUDP443=direct",
        ] {
            assert!(VLESSLink::parse(&format!("{base}&{invalid}")).is_err());
        }
    }

    #[test]
    fn xray_aliases_keep_vless_transport_fields() {
        let link = "vless://test@example.invalid:443?security=tls&mode=stream-up&path=%2Froute&extra=%7B%22noSSEHeader%22%3Atrue%7D&encryption=mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let parsed = VLESSLink::parse(&format!("{link}&type=splithttp")).unwrap();
        assert_eq!(
            parsed,
            VLESSLink::parse(&format!("{link}&type=xhttp")).unwrap()
        );
        assert_eq!(parsed.xhttp_mode, "stream-up");
        assert_eq!(parsed.path, "/route");
        assert_eq!(VLESSLink::parse(&parsed.export_url()).unwrap(), parsed);
        assert_eq!(
            VLESSLink::parse(&format!("{link}&type=raw")).unwrap().net,
            "tcp"
        );
        assert_eq!(
            VLESSLink::parse(&format!("{link}&type=xdrive"))
                .unwrap()
                .net,
            "xdrive"
        );
    }
}
