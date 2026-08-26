use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::fetch_error::SubscriptionFetchFailure;
use crate::{
    ParsedNodeLink, PreparedSubscriptionNode, PreparedSubscriptionNodes,
    PreparedSubscriptionRefresh, RejectedSubscriptionNode, StableNodeKey, SubscriptionContentKind,
    SubscriptionSourceIdentity,
};

pub const SUBSCRIPTION_HELPER_SCHEMA_VERSION: u64 = 1;
pub const SUBSCRIPTION_HELPER_MAX_REQUEST_BYTES: usize = 128 * 1024;
pub const SUBSCRIPTION_HELPER_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct SubscriptionHelperRequest {
    pub state: PathBuf,
    pub config_dir: PathBuf,
    pub response: PathBuf,
    pub persist_staging: PathBuf,
    pub source: SubscriptionSourceIdentity,
}

#[derive(Clone, Debug)]
pub enum DecodedSubscriptionHelperOutcome {
    Prepared(PreparedSubscriptionRefresh),
    FetchFailed(SubscriptionFetchFailure),
}

pub fn encode_subscription_helper_request(
    request: &SubscriptionHelperRequest,
) -> io::Result<Vec<u8>> {
    serde_json::to_vec(&json!({
        "schemaVersion": SUBSCRIPTION_HELPER_SCHEMA_VERSION,
        "statePath": utf8_path(&request.state, "state")?,
        "configDirPath": utf8_path(&request.config_dir, "config directory")?,
        "responsePath": utf8_path(&request.response, "response")?,
        "persistStagingPath": utf8_path(&request.persist_staging, "persist staging")?,
        "source": {
            "id": request.source.id.to_string(),
            "link": request.source.link,
            "tag": request.source.tag,
            "useProxy": request.source.use_proxy,
        },
    }))
    .map_err(|error| io::Error::other(format!("encode subscription helper request: {error}")))
}

pub fn decode_subscription_helper_request(input: &[u8]) -> io::Result<SubscriptionHelperRequest> {
    if input.len() > SUBSCRIPTION_HELPER_MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "subscription helper request exceeds {SUBSCRIPTION_HELPER_MAX_REQUEST_BYTES} bytes"
            ),
        ));
    }
    let value: Value = serde_json::from_slice(input).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode subscription helper request: {error}"),
        )
    })?;
    require_schema(&value)?;
    let source = value.get("source").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription helper request is missing source",
        )
    })?;
    Ok(SubscriptionHelperRequest {
        state: PathBuf::from(required_string(&value, "statePath")?),
        config_dir: PathBuf::from(required_string(&value, "configDirPath")?),
        response: PathBuf::from(required_string(&value, "responsePath")?),
        persist_staging: PathBuf::from(required_string(&value, "persistStagingPath")?),
        source: SubscriptionSourceIdentity {
            id: parse_i64_string(source, "id")?,
            link: required_string(source, "link")?.to_owned(),
            tag: optional_string(source, "tag")?.map(str::to_owned),
            use_proxy: required_bool(source, "useProxy")?,
        },
    })
}

pub fn encode_subscription_helper_success(
    source: &SubscriptionSourceIdentity,
    prepared: &PreparedSubscriptionRefresh,
) -> Value {
    json!({
        "schemaVersion": SUBSCRIPTION_HELPER_SCHEMA_VERSION,
        "status": "pass",
        "subscriptionId": source.id.to_string(),
        "sourceKind": prepared.content_kind.as_str(),
        "sourceNodeCount": prepared.source_node_count.to_string(),
        "invalidSourceCount": prepared.invalid_source_count.to_string(),
        "empty": prepared.empty,
        "persistContent": prepared.persist_content,
        "admitted": prepared.nodes.admitted.iter().map(|node| json!({
            "storedLink": node.stored_link,
            "displayName": node.parsed.display_name,
            "address": node.parsed.address,
            "protocol": node.parsed.protocol,
            "stableKey": node.parsed.stable_key.as_str(),
        })).collect::<Vec<_>>(),
        "invalid": prepared.nodes.invalid.iter().map(encode_rejected_node).collect::<Vec<_>>(),
        "notAdmitted": prepared.nodes.not_admitted.iter().map(encode_rejected_node).collect::<Vec<_>>(),
    })
}

pub fn encode_subscription_helper_failure(
    source: &SubscriptionSourceIdentity,
    failure: &SubscriptionFetchFailure,
) -> Value {
    json!({
        "schemaVersion": SUBSCRIPTION_HELPER_SCHEMA_VERSION,
        "status": "fail",
        "subscriptionId": source.id.to_string(),
        "errorCode": failure.code(),
    })
}

pub fn decode_subscription_helper_response(
    reader: impl Read,
    expected_source: &SubscriptionSourceIdentity,
) -> io::Result<DecodedSubscriptionHelperOutcome> {
    let value: Value = serde_json::from_reader(reader).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode subscription helper response: {error}"),
        )
    })?;
    require_schema(&value)?;
    if parse_i64_string(&value, "subscriptionId")? != expected_source.id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription helper response does not match requested subscription",
        ));
    }
    match required_string(&value, "status")? {
        "fail" => {
            let code = required_string(&value, "errorCode")?;
            let failure = SubscriptionFetchFailure::from_code(code).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported subscription helper error code: {code}"),
                )
            })?;
            Ok(DecodedSubscriptionHelperOutcome::FetchFailed(failure))
        }
        "pass" => decode_prepared(&value).map(DecodedSubscriptionHelperOutcome::Prepared),
        status => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported subscription helper response status: {status}"),
        )),
    }
}

fn decode_prepared(value: &Value) -> io::Result<PreparedSubscriptionRefresh> {
    let admitted = required_array(value, "admitted")?
        .iter()
        .map(decode_admitted_node)
        .collect::<io::Result<Vec<_>>>()?;
    let invalid = required_array(value, "invalid")?
        .iter()
        .map(decode_rejected_node)
        .collect::<io::Result<Vec<_>>>()?;
    let not_admitted = required_array(value, "notAdmitted")?
        .iter()
        .map(decode_rejected_node)
        .collect::<io::Result<Vec<_>>>()?;
    Ok(PreparedSubscriptionRefresh {
        content_kind: decode_content_kind(required_string(value, "sourceKind")?)?,
        source_node_count: parse_usize_string(value, "sourceNodeCount")?,
        invalid_source_count: parse_usize_string(value, "invalidSourceCount")?,
        empty: required_bool(value, "empty")?,
        nodes: PreparedSubscriptionNodes {
            admitted,
            invalid,
            not_admitted,
        },
        persist_content: required_bool(value, "persistContent")?,
    })
}

fn decode_admitted_node(value: &Value) -> io::Result<PreparedSubscriptionNode> {
    let stored_link = required_string(value, "storedLink")?.to_owned();
    let display_name = required_string(value, "displayName")?.to_owned();
    let address = required_string(value, "address")?.to_owned();
    let protocol = required_string(value, "protocol")?.to_owned();
    let stable_key = required_string(value, "stableKey")?.to_owned();
    if stored_link.is_empty() || address.is_empty() || protocol.is_empty() || stable_key.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription helper returned an incomplete admitted node",
        ));
    }
    Ok(PreparedSubscriptionNode {
        stored_link,
        parsed: ParsedNodeLink {
            display_name,
            address,
            protocol,
            stable_key: StableNodeKey::from_canonical(stable_key),
            normalized_link: None,
        },
    })
}

fn encode_rejected_node(node: &RejectedSubscriptionNode) -> Value {
    json!({"link": node.link, "reason": node.reason})
}

fn decode_rejected_node(value: &Value) -> io::Result<RejectedSubscriptionNode> {
    let reason = required_string(value, "reason")?;
    if reason.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription helper rejection reason exceeds 4096 bytes",
        ));
    }
    Ok(RejectedSubscriptionNode {
        link: required_string(value, "link")?.to_owned(),
        reason: reason.to_owned(),
    })
}

fn decode_content_kind(value: &str) -> io::Result<SubscriptionContentKind> {
    match value {
        "empty" => Ok(SubscriptionContentKind::Empty),
        "sip008" => Ok(SubscriptionContentKind::Sip008),
        "plain-text" => Ok(SubscriptionContentKind::PlainText),
        "base64" => Ok(SubscriptionContentKind::Base64),
        "unrecognized" => Ok(SubscriptionContentKind::Unrecognized),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported subscription helper content kind: {value}"),
        )),
    }
}

fn require_schema(value: &Value) -> io::Result<()> {
    if value.get("schemaVersion").and_then(Value::as_u64)
        != Some(SUBSCRIPTION_HELPER_SCHEMA_VERSION)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported subscription helper schema version",
        ));
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subscription helper JSON is missing {key}"),
        )
    })
}

fn optional_string<'a>(value: &'a Value, key: &str) -> io::Result<Option<&'a str>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subscription helper JSON {key} is not a string"),
            )
        }),
    }
}

fn required_bool(value: &Value, key: &str) -> io::Result<bool> {
    value.get(key).and_then(Value::as_bool).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subscription helper JSON is missing {key}"),
        )
    })
}

fn required_array<'a>(value: &'a Value, key: &str) -> io::Result<&'a [Value]> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subscription helper JSON is missing {key}"),
            )
        })
}

fn parse_i64_string(value: &Value, key: &str) -> io::Result<i64> {
    required_string(value, key)?.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse subscription helper {key}: {error}"),
        )
    })
}

fn parse_usize_string(value: &Value, key: &str) -> io::Result<usize> {
    required_string(value, key)?.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse subscription helper {key}: {error}"),
        )
    })
}

fn utf8_path<'a>(path: &'a Path, name: &str) -> io::Result<&'a str> {
    path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("subscription helper {name} path is not UTF-8"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SubscriptionSourceIdentity {
        SubscriptionSourceIdentity {
            id: 41,
            link: "https://example.test/subscription".to_owned(),
            tag: Some("fixture".to_owned()),
            use_proxy: false,
        }
    }

    #[test]
    fn helper_protocol_round_trips_prepared_nodes_without_reparsing_links() {
        let parsed = crate::parse_node_link("socks://127.0.0.1:1080#fixture", None);
        let prepared = PreparedSubscriptionRefresh {
            content_kind: SubscriptionContentKind::PlainText,
            source_node_count: 1,
            invalid_source_count: 0,
            empty: false,
            nodes: PreparedSubscriptionNodes {
                admitted: vec![PreparedSubscriptionNode {
                    stored_link: "socks://127.0.0.1:1080#fixture".to_owned(),
                    parsed,
                }],
                invalid: Vec::new(),
                not_admitted: Vec::new(),
            },
            persist_content: false,
        };
        let encoded =
            serde_json::to_vec(&encode_subscription_helper_success(&source(), &prepared)).unwrap();
        let DecodedSubscriptionHelperOutcome::Prepared(decoded) =
            decode_subscription_helper_response(encoded.as_slice(), &source()).unwrap()
        else {
            panic!("expected prepared helper result")
        };
        assert_eq!(decoded.source_node_count, 1);
        assert_eq!(decoded.nodes.admitted.len(), 1);
        assert_eq!(
            decoded.nodes.admitted[0].parsed.stable_key,
            prepared.nodes.admitted[0].parsed.stable_key
        );
    }

    #[test]
    fn helper_protocol_round_trips_safe_fetch_failure_codes() {
        let failure = SubscriptionFetchFailure::from_io_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "fixture timeout",
        ));
        let encoded =
            serde_json::to_vec(&encode_subscription_helper_failure(&source(), &failure)).unwrap();
        let DecodedSubscriptionHelperOutcome::FetchFailed(decoded) =
            decode_subscription_helper_response(encoded.as_slice(), &source()).unwrap()
        else {
            panic!("expected failed helper result")
        };
        assert_eq!(decoded.response_value(), failure.response_value());
    }
}
