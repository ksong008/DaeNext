use super::*;
pub(crate) fn list_nodes(state: &Path, subscription_id: Option<i64>) -> HttpResponse {
    match list_nodes_value(state, subscription_id) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn list_nodes_for_request(state: &Path, request: &HttpRequest) -> HttpResponse {
    let subscription_id = request
        .query
        .get("subscriptionId")
        .or_else(|| request.query.get("subscriptionID"))
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<i64>().ok());
    let scope = if let Some(subscription_id) = subscription_id {
        NodeListScope::Subscription(subscription_id)
    } else {
        match request
            .query
            .get("independent")
            .and_then(|values| values.first())
            .and_then(|value| parse_boolish(value))
        {
            Some(false) => NodeListScope::SubscriptionBacked,
            _ => NodeListScope::Independent,
        }
    };
    match list_nodes_by_scope(state, scope) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum NodeListScope {
    Independent,
    SubscriptionBacked,
    Subscription(i64),
    All,
}

pub(crate) fn list_nodes_value(state: &Path, subscription_id: Option<i64>) -> io::Result<Value> {
    let scope = subscription_id
        .map(NodeListScope::Subscription)
        .unwrap_or(NodeListScope::Independent);
    list_nodes_by_scope(state, scope)
}

pub(crate) fn list_all_nodes_value(state: &Path) -> io::Result<Value> {
    list_nodes_by_scope(state, NodeListScope::All)
}

pub(crate) fn list_nodes_by_scope(state: &Path, scope: NodeListScope) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut items = Vec::new();
    match scope {
        NodeListScope::Independent => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, link, name, address, protocol, tag, subscription_id
                     FROM nodes
                     WHERE subscription_id IS NULL
                     ORDER BY id",
                )
                .map_err(sqlite_io_error)?;
            let rows = stmt
                .query_map([], node_row_value)
                .map_err(sqlite_io_error)?;
            for row in rows {
                items.push(row.map_err(sqlite_io_error)?);
            }
        }
        NodeListScope::SubscriptionBacked => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, link, name, address, protocol, tag, subscription_id
                     FROM nodes
                     WHERE subscription_id IS NOT NULL
                     ORDER BY id",
                )
                .map_err(sqlite_io_error)?;
            let rows = stmt
                .query_map([], node_row_value)
                .map_err(sqlite_io_error)?;
            for row in rows {
                items.push(row.map_err(sqlite_io_error)?);
            }
        }
        NodeListScope::Subscription(subscription_id) => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, link, name, address, protocol, tag, subscription_id
                     FROM nodes
                     WHERE subscription_id = ?1
                     ORDER BY id",
                )
                .map_err(sqlite_io_error)?;
            let rows = stmt
                .query_map(params![subscription_id], node_row_value)
                .map_err(sqlite_io_error)?;
            for row in rows {
                items.push(row.map_err(sqlite_io_error)?);
            }
        }
        NodeListScope::All => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, link, name, address, protocol, tag, subscription_id
                     FROM nodes
                     ORDER BY id",
                )
                .map_err(sqlite_io_error)?;
            let rows = stmt
                .query_map([], node_row_value)
                .map_err(sqlite_io_error)?;
            for row in rows {
                items.push(row.map_err(sqlite_io_error)?);
            }
        }
    }
    Ok(json!({
        "items": items,
        "totalCount": items.len(),
        "nextAfterId": Value::Null,
    }))
}

pub(crate) fn get_node(state: &Path, id: i64) -> HttpResponse {
    match get_node_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "node not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn get_node_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes WHERE id = ?1",
        params![id],
        node_row_value,
    )
    .optional()
    .map_err(sqlite_io_error)
}

pub(crate) fn import_nodes(
    state: &Path,
    request: &HttpRequest,
    subscription_id: Option<i64>,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let args = body
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![body.clone()]);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let mut items = Vec::new();
    for item in args {
        let link = item.get("link").and_then(Value::as_str).unwrap_or("");
        let tag = item.get("tag").and_then(Value::as_str);
        if link.is_empty() {
            items.push(json!({"link": link, "error": "link is required", "node": Value::Null}));
            continue;
        }
        let parsed = parse_node_link(link, tag);
        let stored_link = parsed.normalized_link.as_deref().unwrap_or(link);
        let result = conn.execute(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                stored_link,
                parsed.name,
                parsed.address,
                parsed.protocol,
                tag,
                subscription_id
            ],
        );
        match result {
            Ok(_) => {
                let id = conn.last_insert_rowid();
                let node = get_node_value(state, id).unwrap_or(None);
                items.push(json!({"link": stored_link, "error": Value::Null, "node": node}));
            }
            Err(err) => {
                items.push(json!({"link": link, "error": err.to_string(), "node": Value::Null}))
            }
        }
    }
    HttpResponse::json(200, json!({"items": items}))
}

pub(crate) fn update_node(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let mut conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let tag_present = body.get("tag").is_some();
    let tag = body.get("tag").and_then(Value::as_str);
    if let Some(link) = body.get("link").and_then(Value::as_str) {
        let parsed = parse_node_link(link, tag);
        let stored_link = parsed
            .normalized_link
            .clone()
            .unwrap_or_else(|| link.to_owned());
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
        };
        let previous_identity = match node_latency_identity(&tx, id) {
            Ok(value) => value,
            Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
        };
        let latency_identity_changed = previous_identity
            .as_ref()
            .map(|current| node_latency_identity_changed(current, &stored_link, &parsed))
            .unwrap_or(false);
        let updated = tx.execute(
            "UPDATE nodes
             SET link = ?1,
                 name = ?2,
                 address = ?3,
                 protocol = ?4,
                 tag = CASE WHEN ?5 THEN ?6 ELSE tag END
             WHERE id = ?7",
            params![
                stored_link,
                parsed.name,
                parsed.address,
                parsed.protocol,
                tag_present,
                tag,
                id
            ],
        );
        match updated {
            Ok(0) => HttpResponse::json(404, json!({"error": "node not found"})),
            Ok(_) => {
                if latency_identity_changed
                    && let Err(err) = tx.execute(
                        "DELETE FROM node_latency_results WHERE node_id = ?1",
                        params![id],
                    )
                {
                    return HttpResponse::json(500, json!({"error": err.to_string()}));
                }
                if let Err(err) = tx.commit() {
                    return HttpResponse::json(500, json!({"error": err.to_string()}));
                }
                get_node(state, id)
            }
            Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
        }
    } else if tag_present {
        let updated = conn.execute("UPDATE nodes SET tag = ?1 WHERE id = ?2", params![tag, id]);
        match updated {
            Ok(0) => HttpResponse::json(404, json!({"error": "node not found"})),
            Ok(_) => get_node(state, id),
            Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
        }
    } else {
        HttpResponse::json(400, json!({"error": "link or tag is required"}))
    }
}

#[derive(Clone, Debug)]
struct NodeLatencyIdentity {
    link: String,
    address: String,
    protocol: String,
}

fn node_latency_identity(conn: &Connection, id: i64) -> io::Result<Option<NodeLatencyIdentity>> {
    conn.query_row(
        "SELECT link, address, protocol FROM nodes WHERE id = ?1",
        params![id],
        |row| {
            Ok(NodeLatencyIdentity {
                link: row.get(0)?,
                address: row.get(1)?,
                protocol: row.get(2)?,
            })
        },
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn node_latency_identity_changed(
    current: &NodeLatencyIdentity,
    next_link: &str,
    next: &ParsedNodeLink,
) -> bool {
    current.link != next_link
        || current.address != next.address
        || current.protocol != next.protocol
}

pub(crate) fn delete_nodes(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    let mut removed = 0_usize;
    for id in ids {
        if let Ok(value) = delete_node(state, id) {
            removed += value;
        }
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

pub(crate) fn delete_node_by_id(state: &Path, id: i64) -> HttpResponse {
    match delete_node(state, id) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn delete_node(state: &Path, id: i64) -> io::Result<usize> {
    let conn = open_state_connection(state)?;
    conn.execute("DELETE FROM group_nodes WHERE node_id = ?1", params![id])
        .map_err(sqlite_io_error)?;
    conn.execute(
        "DELETE FROM node_latency_results WHERE node_id = ?1",
        params![id],
    )
    .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM nodes WHERE id = ?1", params![id])
        .map_err(sqlite_io_error)
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedNodeLink {
    pub(in crate::daed_product) name: String,
    pub(in crate::daed_product) address: String,
    pub(in crate::daed_product) protocol: String,
    pub(in crate::daed_product) display_identity: String,
    pub(in crate::daed_product) normalized_link: Option<String>,
}

pub(crate) fn parse_node_link(link: &str, tag: Option<&str>) -> ParsedNodeLink {
    if let Some(parsed) = parse_node_link_with_outbound_parser(link, tag) {
        return parsed;
    }
    let protocol = link
        .split_once("://")
        .map(|(value, _)| value)
        .unwrap_or("unknown");
    let parsed_url = url::Url::parse(link).ok();
    let address = parsed_url
        .as_ref()
        .and_then(url::Url::host_str)
        .map(str::to_owned)
        .or_else(|| {
            link.split_once("://").map(|(_, rest)| {
                rest.split(['@', '/', '?', '#'])
                    .next_back()
                    .unwrap_or(rest)
                    .split(':')
                    .next()
                    .unwrap_or("unknown")
                    .to_owned()
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let name = tag
        .map(decode_node_label)
        .or_else(|| parsed_url.and_then(|url| url.fragment().map(decode_node_label)))
        .unwrap_or_else(|| format!("{protocol}-{address}"));
    ParsedNodeLink {
        name,
        address,
        protocol: protocol.to_owned(),
        display_identity: node_link_display_identity(link),
        normalized_link: None,
    }
}

fn parse_node_link_with_outbound_parser(link: &str, tag: Option<&str>) -> Option<ParsedNodeLink> {
    let tag = tag.map(decode_node_label);
    if let Ok(parsed) = dae_outbound::VMessLink::parse(link) {
        let address = parsed.address();
        return Some(ParsedNodeLink {
            name: tag
                .clone()
                .or_else(|| non_empty(decoded_node_label(&parsed.ps)))
                .unwrap_or_else(|| format!("vmess-{address}")),
            address,
            protocol: parsed.protocol,
            display_identity: node_link_display_identity(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::VLESSLink::parse(link) {
        let address = parsed.add.clone();
        return Some(ParsedNodeLink {
            name: tag
                .clone()
                .or_else(|| non_empty(decoded_node_label(&parsed.ps)))
                .unwrap_or_else(|| format!("vless-{address}")),
            address,
            protocol: parsed.protocol,
            display_identity: node_link_display_identity(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::ShadowsocksLink::parse(link) {
        let address = parsed.address();
        return Some(ParsedNodeLink {
            name: tag
                .clone()
                .or_else(|| non_empty(decoded_node_label(&parsed.name)))
                .unwrap_or_else(|| format!("{}-{address}", parsed.protocol)),
            address: parsed.server,
            protocol: parsed.protocol,
            display_identity: node_link_display_identity(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::Hysteria2Link::parse(link) {
        let address = parsed.property_address();
        let normalized_link = hysteria2_mport_query_present(link).then(|| parsed.export_url());
        return Some(ParsedNodeLink {
            name: tag
                .or_else(|| non_empty(parsed.name))
                .unwrap_or_else(|| format!("hysteria2-{address}")),
            address,
            protocol: "hysteria2".to_owned(),
            display_identity: node_link_display_identity(link),
            normalized_link,
        });
    }
    None
}

pub(crate) fn node_link_display_identity(link: &str) -> String {
    if let Ok(mut parsed) = dae_outbound::VMessLink::parse(link) {
        parsed.ps.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::VLESSLink::parse(link) {
        parsed.ps.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::TrojanLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::ShadowsocksLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::Hysteria2Link::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::TuicLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    if let Ok(mut parsed) = dae_outbound::JuicityLink::parse(link) {
        parsed.name.clear();
        return parsed.export_url();
    }
    url_without_fragment(link)
}

fn url_without_fragment(link: &str) -> String {
    if let Ok(mut url) = url::Url::parse(link) {
        url.set_fragment(None);
        return url.to_string();
    }
    link.split_once('#')
        .map(|(without_fragment, _)| without_fragment.to_owned())
        .unwrap_or_else(|| link.to_owned())
}

fn hysteria2_mport_query_present(link: &str) -> bool {
    let Some((_, rest)) = link.split_once('?') else {
        return false;
    };
    let query = rest.split('#').next().unwrap_or(rest);
    url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key.as_ref() == "mport")
}

fn decoded_node_label(value: &str) -> String {
    decode_node_label(value)
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

pub(crate) fn decode_node_label(value: &str) -> String {
    decode_percent_escapes(value.trim())
}

pub(crate) fn decode_percent_escapes(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push((high << 4) | low);
            changed = true;
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    if changed {
        String::from_utf8_lossy(&out).into_owned()
    } else {
        value.to_owned()
    }
}

pub(crate) fn node_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let subscription_id: Option<i64> = row.get(6)?;
    let name = row.get::<_, String>(2)?;
    let tag = row.get::<_, Option<String>>(5)?;
    let runtime_tag = tag
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(name.as_str())
        .to_owned();
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "link": row.get::<_, String>(1)?,
        "name": decode_node_label(&name),
        "address": row.get::<_, String>(3)?,
        "protocol": row.get::<_, String>(4)?,
        "transport": Value::Null,
        "tag": tag.as_deref().map(decode_node_label),
        "runtimeTag": runtime_tag,
        "subscriptionId": subscription_id,
        "subscriptionID": subscription_id.map(|value| value.to_string()),
    }))
}
