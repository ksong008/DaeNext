use super::*;
use dae_config::{Item, Section};

pub(crate) fn parse_global_directives(raw: &str) -> HashMap<String, String> {
    let body = global_block_body(raw).unwrap_or(raw);
    let mut directives = HashMap::new();
    for line in body.lines() {
        let line = strip_line_comment(line).trim();
        if line.is_empty() || line == "{" || line == "}" {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches(',').to_owned();
        if key.is_empty() {
            continue;
        }
        directives.insert(key, clean_global_scalar(value));
    }
    directives
}

pub(crate) fn parse_global_directives_with_config_parser(
    raw: &str,
) -> Result<HashMap<String, String>, String> {
    let sections = parse_config(raw).or_else(|raw_err| {
        let wrapped = format!("global {{\n{raw}\n}}");
        parse_config(&wrapped)
            .map_err(|wrapped_err| format!("{raw_err}; wrapped global body: {wrapped_err}"))
    })?;
    let global = sections
        .iter()
        .find(|section| section.name == "global")
        .ok_or_else(|| "global section not found".to_owned())?;
    global_directives_from_section(global)
}

pub(crate) fn global_text_needs_config_parser(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.starts_with('#') {
        return true;
    }
    if trimmed.contains('\n') {
        return false;
    }
    let body = global_block_body(trimmed).unwrap_or(trimmed);
    if contains_quoted_global_block_delimiter(body) {
        return true;
    }
    global_body_contains_inline_directive(body)
}

fn global_directives_from_section(section: &Section) -> Result<HashMap<String, String>, String> {
    let mut directives = HashMap::new();
    for item in &section.items {
        let Item::Param(param) = item else {
            return Err(format!(
                "unexpected global item kind {:?}; expected parameter",
                item.kind()
            ));
        };
        if param.key.trim().is_empty() {
            return Err("unexpected naked global parameter".to_owned());
        }
        if !param.and_functions.is_empty() {
            return Err(format!(
                "unexpected function value for global.{}",
                param.key
            ));
        }
        directives.insert(param.key.clone(), param.val.clone());
    }
    Ok(directives)
}

fn contains_quoted_global_block_delimiter(raw: &str) -> bool {
    let mut quote = None;
    for ch in raw.chars() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            '{' | '}' if quote.is_some() => return true,
            _ => {}
        }
    }
    false
}

fn global_body_contains_inline_directive(body: &str) -> bool {
    body.lines().any(|line| {
        let line = strip_line_comment(line);
        let Some((_, value)) = line.split_once(':') else {
            return false;
        };
        contains_global_directive_key_after_whitespace(value)
    })
}

fn contains_global_directive_key_after_whitespace(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0_usize;
    let mut quote = None;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'\'' | b'"' if quote == Some(byte) => {
                quote = None;
                index += 1;
            }
            b'\'' | b'"' if quote.is_none() => {
                quote = Some(byte);
                index += 1;
            }
            byte if quote.is_none() && byte.is_ascii_whitespace() => {
                let mut ident_start = index + 1;
                while ident_start < bytes.len() && bytes[ident_start].is_ascii_whitespace() {
                    ident_start += 1;
                }
                let mut ident_end = ident_start;
                while ident_end < bytes.len()
                    && (bytes[ident_end].is_ascii_alphanumeric() || bytes[ident_end] == b'_')
                {
                    ident_end += 1;
                }
                let mut colon = ident_end;
                while colon < bytes.len() && bytes[colon].is_ascii_whitespace() {
                    colon += 1;
                }
                if colon < bytes.len()
                    && bytes[colon] == b':'
                    && ident_start < ident_end
                    && is_identifier_start(bytes[ident_start])
                {
                    return true;
                }
                index = ident_end.max(index + 1);
            }
            _ => index += 1,
        }
    }
    false
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

pub(crate) fn global_block_body(raw: &str) -> Option<&str> {
    let start = raw.find("global")?;
    let open = raw[start..].find('{')? + start;
    let bytes = raw.as_bytes();
    let mut depth = 0_i32;
    let mut close = None;
    for (idx, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(idx);
                    break;
                }
            }
            _ => {}
        }
    }
    close.and_then(|close| raw.get(open + 1..close))
}

pub(crate) fn strip_line_comment(line: &str) -> &str {
    let mut quote = None;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            '#' if quote.is_none() => return &line[..idx],
            _ => {}
        }
    }
    line
}

pub(crate) fn clean_global_scalar(value: &str) -> String {
    let value = value.trim().trim_end_matches(',').trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value);
    value.trim().to_owned()
}

pub(crate) fn directive_string(directives: &HashMap<String, String>, key: &str) -> Option<String> {
    directives
        .get(key)
        .cloned()
        .filter(|value| !value.is_empty())
}

pub(crate) fn directive_bool(directives: &HashMap<String, String>, key: &str) -> Option<bool> {
    directives.get(key).and_then(|value| parse_boolish(value))
}

pub(crate) fn directive_u64(directives: &HashMap<String, String>, key: &str) -> Option<u64> {
    directives
        .get(key)
        .and_then(|value| value.trim().parse::<u64>().ok())
}

pub(crate) fn directive_array(
    directives: &HashMap<String, String>,
    key: &str,
) -> Option<Vec<String>> {
    directives
        .get(key)
        .map(|value| split_global_list(value))
        .filter(|values| !values.is_empty())
}

pub(crate) fn split_global_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(crate) fn json_value_by_keys<'a>(source: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| source.get(*key))
}

pub(crate) fn json_string(source: &Value, keys: &[&str]) -> Option<String> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

pub(crate) fn json_bool(source: &Value, keys: &[&str]) -> Option<bool> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => parse_boolish(value),
        _ => None,
    })
}

pub(crate) fn json_u64(source: &Value, keys: &[&str]) -> Option<u64> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    })
}

pub(crate) fn json_array_or_split_string(source: &Value, keys: &[&str]) -> Option<Vec<String>> {
    json_value_by_keys(source, keys).and_then(|value| match value {
        Value::Array(values) => {
            let out = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            (!out.is_empty()).then_some(out)
        }
        Value::String(value) => {
            let out = split_global_list(value);
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    })
}

pub(crate) fn parse_boolish(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

pub(crate) fn set_global_string(target: &mut Value, key: &str, value: Option<String>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

pub(crate) fn set_global_bool(target: &mut Value, key: &str, value: Option<bool>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

pub(crate) fn set_global_u64(target: &mut Value, key: &str, value: Option<u64>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}

pub(crate) fn set_global_array(target: &mut Value, key: &str, value: Option<Vec<String>>) {
    if let (Some(map), Some(value)) = (target.as_object_mut(), value) {
        map.insert(key.to_owned(), json!(value));
    }
}
