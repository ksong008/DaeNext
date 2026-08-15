use super::*;

pub(super) fn resident_xhttp_extra_overlay_object(
    value: Option<&Value>,
    context: &str,
    node_tag: &str,
) -> Result<Option<Value>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) if raw.trim().is_empty() => Ok(None),
        Some(Value::String(raw)) => {
            let parsed = serde_json::from_str::<Value>(raw)
                .map_err(|err| format!("{context} must be JSON for node {node_tag}: {err}"))?;
            if parsed.is_object() {
                Ok(Some(parsed))
            } else {
                Err(format!(
                    "{context} must be a JSON object for node {node_tag}"
                ))
            }
        }
        Some(Value::Object(_)) => Ok(value.cloned()),
        Some(_) => Err(format!(
            "{context} must be a JSON object or JSON string for node {node_tag}"
        )),
    }
}

pub(super) fn reject_unknown_object_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
    node_tag: &str,
) -> Result<(), String> {
    let unsupported = object
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{context} contains unsupported fields for node {node_tag}: {}",
        unsupported.join(",")
    ))
}

pub(super) fn optional_object<'a>(
    value: Option<&'a Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be a JSON object for node {node_tag}"
        )),
    }
}

pub(super) fn required_string(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<String, String> {
    optional_string(value, field, node_tag)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("resident dataplane vless xHTTP {field} is required for node {node_tag}")
        })
}

pub(super) fn optional_string(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.trim().to_owned())),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be a string for node {node_tag}"
        )),
    }
}

pub(super) fn required_u16(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<u16, String> {
    let Some(value) = value else {
        return Err(format!(
            "resident dataplane vless xHTTP {field} is required for node {node_tag}"
        ));
    };
    let port = value.as_u64().ok_or_else(|| {
        format!("resident dataplane vless xHTTP {field} must be an integer for node {node_tag}")
    })?;
    if port == 0 || port > u16::MAX as u64 {
        return Err(format!(
            "resident dataplane vless xHTTP {field} must be in 1..=65535 for node {node_tag}; got {port}"
        ));
    }
    Ok(port as u16)
}

pub(super) fn optional_bool(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<bool>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be a boolean for node {node_tag}"
        )),
    }
}

pub(super) fn optional_xhttp_range(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<(i32, i32)>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let range = match value {
        Value::Number(number) => {
            let value = number.as_i64().ok_or_else(|| {
                format!(
                    "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
                )
            })?;
            let value = i32::try_from(value).map_err(|_| {
                format!(
                    "resident dataplane vless xHTTP {field} is too large for node {node_tag}: {value}"
                )
            })?;
            (value, value)
        }
        Value::String(raw) => parse_xhttp_range_string(raw, field, node_tag)?,
        Value::Object(object) => {
            reject_unknown_object_fields(
                object,
                &["from", "to"],
                &format!("resident dataplane vless xHTTP {field}"),
                node_tag,
            )?;
            let from =
                optional_i32(object.get("from"), &format!("{field}.from"), node_tag)?.unwrap_or(0);
            let to = optional_i32(object.get("to"), &format!("{field}.to"), node_tag)?.unwrap_or(0);
            (from, to)
        }
        _ => {
            return Err(format!(
                "resident dataplane vless xHTTP {field} must be an integer, string range, or {{from,to}} object for node {node_tag}"
            ));
        }
    };
    Ok(Some(if range.0 <= range.1 {
        range
    } else {
        (range.1, range.0)
    }))
}

fn parse_xhttp_range_string(raw: &str, field: &str, node_tag: &str) -> Result<(i32, i32), String> {
    let raw = raw.trim();
    if let Ok(value) = raw.parse::<i32>() {
        return Ok((value, value));
    }
    if raw.is_empty() {
        return Ok((0, 0));
    }
    let (from, to) = if raw.starts_with('-') {
        let split_at = raw
            .match_indices('-')
            .nth(1)
            .map(|(index, _)| index)
            .ok_or_else(|| {
                format!(
                    "resident dataplane vless xHTTP {field} must be an integer range for node {node_tag}"
                )
            })?;
        (&raw[..split_at], &raw[split_at + 1..])
    } else {
        raw.split_once('-').ok_or_else(|| {
            format!(
                "resident dataplane vless xHTTP {field} must be an integer range for node {node_tag}"
            )
        })?
    };
    Ok((
        parse_xhttp_i32_str(from.trim(), &format!("{field}.from"), node_tag)?,
        parse_xhttp_i32_str(to.trim(), &format!("{field}.to"), node_tag)?,
    ))
}

pub(super) fn optional_i32(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<i32>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => {
            let value = number.as_i64().ok_or_else(|| {
                format!(
                    "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
                )
            })?;
            i32::try_from(value).map(Some).map_err(|_| {
                format!(
                    "resident dataplane vless xHTTP {field} is too large for node {node_tag}: {value}"
                )
            })
        }
        Some(Value::String(raw)) => parse_xhttp_i32_str(raw, field, node_tag).map(Some),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
        )),
    }
}

pub(super) fn optional_i64(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<i64>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number.as_i64().map(Some).ok_or_else(|| {
            format!(
                "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
            )
        }),
        Some(Value::String(raw)) => raw.trim().parse::<i64>().map(Some).map_err(|err| {
            format!(
                "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}: {err}"
            )
        }),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}"
        )),
    }
}

fn parse_xhttp_i32_str(raw: &str, field: &str, node_tag: &str) -> Result<i32, String> {
    raw.trim().parse::<i32>().map_err(|err| {
        format!(
            "resident dataplane vless xHTTP {field} must be an integer for node {node_tag}: {err}"
        )
    })
}

pub(super) fn optional_alpn(
    value: Option<&Value>,
    field: &str,
    node_tag: &str,
) -> Result<Option<Vec<String>>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(split_alpn(value))),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().map(|value| value.trim().to_owned()).ok_or_else(|| {
                    format!(
                        "resident dataplane vless xHTTP {field} entries must be strings for node {node_tag}"
                    )
                })
            })
            .filter(|result| result.as_ref().map_or(true, |value| !value.is_empty()))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(format!(
            "resident dataplane vless xHTTP {field} must be a string or string array for node {node_tag}"
        )),
    }
}
