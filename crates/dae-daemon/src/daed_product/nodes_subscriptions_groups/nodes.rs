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
    #[cfg(test)]
    All,
}

pub(crate) fn list_nodes_value(state: &Path, subscription_id: Option<i64>) -> io::Result<Value> {
    let scope = subscription_id
        .map(NodeListScope::Subscription)
        .unwrap_or(NodeListScope::Independent);
    list_nodes_by_scope(state, scope)
}

#[cfg(test)]
pub(crate) fn list_all_nodes_value(state: &Path) -> io::Result<Value> {
    list_nodes_by_scope(state, NodeListScope::All)
}

pub(crate) fn list_nodes_by_scope(state: &Path, scope: NodeListScope) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    list_nodes_by_scope_with_connection(&conn, scope)
}

fn list_nodes_by_scope_with_connection(
    conn: &Connection,
    scope: NodeListScope,
) -> io::Result<Value> {
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
        #[cfg(test)]
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
    let prepared = args
        .into_iter()
        .map(|item| {
            let link = item
                .get("link")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let tag = item.get("tag").and_then(Value::as_str).map(str::to_owned);
            if link.is_empty() {
                return PreparedNodeImport::Rejected(json!({
                    "link": link,
                    "error": "link is required",
                    "node": Value::Null
                }));
            }
            let parsed = parse_node_link(&link, tag.as_deref());
            let stored_link = parsed
                .normalized_link
                .clone()
                .unwrap_or_else(|| link.clone());
            PreparedNodeImport::Ready {
                link,
                stored_link,
                parsed,
                tag,
            }
        })
        .collect::<Vec<_>>();
    let mut conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let mut pending_items = Vec::with_capacity(prepared.len());
    let mut inserted = 0_usize;
    for item in prepared {
        let PreparedNodeImport::Ready {
            link,
            stored_link,
            parsed,
            tag,
        } = item
        else {
            if let PreparedNodeImport::Rejected(response) = item {
                pending_items.push(PendingNodeImport::Complete(response));
            }
            continue;
        };
        let result = tx.execute(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &stored_link,
                parsed.display_name,
                parsed.address,
                parsed.protocol,
                tag.as_deref(),
                subscription_id
            ],
        );
        match result {
            Ok(_) => {
                inserted += 1;
                pending_items.push(PendingNodeImport::Inserted {
                    link: stored_link,
                    id: tx.last_insert_rowid(),
                });
            }
            Err(err) => {
                pending_items.push(PendingNodeImport::Complete(json!({
                    "link": link,
                    "error": err.to_string(),
                    "node": Value::Null
                })));
            }
        }
    }
    if inserted > 0
        && let Err(err) = bump_runtime_external_input_version_with_connection(&tx)
    {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    if let Err(err) = tx.commit() {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    let items = pending_items
        .into_iter()
        .map(|item| match item {
            PendingNodeImport::Complete(response) => response,
            PendingNodeImport::Inserted { link, id } => {
                let node = get_node_value(state, id).unwrap_or(None);
                json!({"link": link, "error": Value::Null, "node": node})
            }
        })
        .collect::<Vec<_>>();
    HttpResponse::json(200, json!({"items": items}))
}

enum PreparedNodeImport {
    Rejected(Value),
    Ready {
        link: String,
        stored_link: String,
        parsed: ParsedNodeLink,
        tag: Option<String>,
    },
}

enum PendingNodeImport {
    Complete(Value),
    Inserted { link: String, id: i64 },
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
            .map(|current| node_latency_identity_changed(current, &parsed))
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
                parsed.display_name,
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
                if previous_identity
                    .as_ref()
                    .is_some_and(|current| current.link != stored_link)
                    && let Err(err) = bump_runtime_external_input_version_with_connection(&tx)
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
    stable_key: StableNodeKey,
    address: String,
    protocol: String,
}

fn node_latency_identity(conn: &Connection, id: i64) -> io::Result<Option<NodeLatencyIdentity>> {
    conn.query_row(
        "SELECT link, address, protocol FROM nodes WHERE id = ?1",
        params![id],
        |row| {
            let link = row.get::<_, String>(0)?;
            Ok(NodeLatencyIdentity {
                link: link.clone(),
                stable_key: StableNodeKey::from_link(&link),
                address: row.get(1)?,
                protocol: row.get(2)?,
            })
        },
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn node_latency_identity_changed(current: &NodeLatencyIdentity, next: &ParsedNodeLink) -> bool {
    current.stable_key != next.stable_key
        || current.address != next.address
        || current.protocol != next.protocol
}

pub(crate) fn delete_nodes(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    match delete_nodes_transaction(state, ids) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn delete_node_by_id(state: &Path, id: i64) -> HttpResponse {
    match delete_node(state, id) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn delete_node(state: &Path, id: i64) -> io::Result<usize> {
    delete_nodes_transaction(state, [id])
}

fn delete_nodes_transaction(state: &Path, ids: impl IntoIterator<Item = i64>) -> io::Result<usize> {
    let ids = ids.into_iter().collect::<BTreeSet<_>>();
    if ids.is_empty() {
        return Ok(0);
    }
    let mut conn = open_state_connection(state)?;
    let tx = conn.transaction().map_err(sqlite_io_error)?;
    let mut removed = 0_usize;
    for id in ids {
        tx.execute("DELETE FROM group_nodes WHERE node_id = ?1", params![id])
            .map_err(sqlite_io_error)?;
        tx.execute(
            "DELETE FROM node_latency_results WHERE node_id = ?1",
            params![id],
        )
        .map_err(sqlite_io_error)?;
        removed += tx
            .execute("DELETE FROM nodes WHERE id = ?1", params![id])
            .map_err(sqlite_io_error)?;
    }
    if removed > 0 {
        bump_runtime_external_input_version_with_connection(&tx)?;
    }
    tx.commit().map_err(sqlite_io_error)?;
    Ok(removed)
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedNodeLink {
    pub(in crate::daed_product) display_name: String,
    pub(in crate::daed_product) address: String,
    pub(in crate::daed_product) protocol: String,
    pub(in crate::daed_product) stable_key: StableNodeKey,
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
    let display_name = tag
        .map(decode_node_label)
        .or_else(|| parsed_url.and_then(|url| url.fragment().map(decode_node_label)))
        .unwrap_or_else(|| format!("{protocol}-{address}"));
    ParsedNodeLink {
        display_name,
        address,
        protocol: protocol.to_owned(),
        stable_key: StableNodeKey::from_link(link),
        normalized_link: None,
    }
}

fn parse_node_link_with_outbound_parser(link: &str, tag: Option<&str>) -> Option<ParsedNodeLink> {
    let tag = tag.map(decode_node_label);
    if let Ok(parsed) = dae_outbound::VMessLink::parse(link) {
        let address = parsed.address();
        return Some(ParsedNodeLink {
            display_name: tag
                .clone()
                .or_else(|| non_empty(decoded_node_label(&parsed.ps)))
                .unwrap_or_else(|| format!("vmess-{address}")),
            address,
            protocol: parsed.protocol,
            stable_key: StableNodeKey::from_link(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::VLESSLink::parse(link) {
        let address = parsed.add.clone();
        return Some(ParsedNodeLink {
            display_name: tag
                .clone()
                .or_else(|| non_empty(decoded_node_label(&parsed.ps)))
                .unwrap_or_else(|| format!("vless-{address}")),
            address,
            protocol: parsed.protocol,
            stable_key: StableNodeKey::from_link(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::ShadowsocksLink::parse(link) {
        let address = parsed.address();
        return Some(ParsedNodeLink {
            display_name: tag
                .clone()
                .or_else(|| non_empty(decoded_node_label(&parsed.name)))
                .unwrap_or_else(|| format!("{}-{address}", parsed.protocol)),
            address: parsed.server,
            protocol: parsed.protocol,
            stable_key: StableNodeKey::from_link(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::Hysteria2Link::parse(link) {
        let address = parsed.property_address();
        let normalized_link = hysteria2_mport_query_present(link).then(|| parsed.export_url());
        return Some(ParsedNodeLink {
            display_name: tag
                .or_else(|| non_empty(parsed.name))
                .unwrap_or_else(|| format!("hysteria2-{address}")),
            address,
            protocol: "hysteria2".to_owned(),
            stable_key: StableNodeKey::from_link(link),
            normalized_link,
        });
    }
    None
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
    let id = row.get::<_, i64>(0)?;
    let subscription_id: Option<i64> = row.get(6)?;
    let name = row.get::<_, String>(2)?;
    let tag = row.get::<_, Option<String>>(5)?;
    let runtime_tag = RuntimeNodeTag::from_node_id(id).into_string();
    Ok(json!({
        "id": id,
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
