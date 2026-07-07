use super::*;

const GROUP_SUMMARY_MATCHED_NODE_SAMPLE_LIMIT: usize = 5;

pub(crate) fn list_groups(state: &Path, request: &HttpRequest) -> HttpResponse {
    let result = if request_summary_enabled(request) {
        list_group_summaries_value(state)
    } else {
        list_groups_value(state)
    };
    match result {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn list_group_summaries_value(state: &Path) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id, name, policy, version FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        let (id, name, policy, version) = row.map_err(sqlite_io_error)?;
        items.push(group_summary_value(&conn, id, name, policy, version)?);
    }
    Ok(json!({"items": items}))
}

fn group_summary_value(
    conn: &Connection,
    group_id: i64,
    name: String,
    policy: String,
    version: i64,
) -> io::Result<Value> {
    Ok(json!({
        "id": group_id,
        "name": name,
        "policy": policy,
        "policyParams": group_policy_params_value(conn, group_id)?,
        "version": version,
        "nodeCount": count_group_nodes(conn, group_id)?,
        "subscriptionCount": count_group_subscriptions(conn, group_id)?,
        "firstNode": first_group_node_value(conn, group_id)?,
        "sampleNodes": group_node_sample_value(conn, group_id, GROUP_SUMMARY_MATCHED_NODE_SAMPLE_LIMIT)?,
        "subscriptions": group_subscription_summaries_value(conn, group_id)?,
    }))
}

pub(crate) fn list_groups_value(state: &Path) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    let mut items = Vec::new();
    for id in ids {
        if let Some(group) = get_group_value_with_conn(&conn, id)? {
            items.push(group);
        }
    }
    Ok(json!({"items": items}))
}

fn count_group_nodes(conn: &Connection, group_id: i64) -> io::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*)
         FROM group_nodes gn
         JOIN nodes n ON n.id = gn.node_id
         WHERE gn.group_id = ?1",
        params![group_id],
        |row| row.get(0),
    )
    .map_err(sqlite_io_error)
}

fn count_group_subscriptions(conn: &Connection, group_id: i64) -> io::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM group_subscriptions WHERE group_id = ?1",
        params![group_id],
        |row| row.get(0),
    )
    .map_err(sqlite_io_error)
}

fn first_group_node_value(conn: &Connection, group_id: i64) -> io::Result<Value> {
    conn.query_row(
        "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id
         FROM nodes n
         JOIN group_nodes gn ON gn.node_id = n.id
         WHERE gn.group_id = ?1
         ORDER BY n.id
         LIMIT 1",
        params![group_id],
        node_row_value,
    )
    .optional()
    .map(|value| value.unwrap_or(Value::Null))
    .map_err(sqlite_io_error)
}

fn group_node_sample_value(
    conn: &Connection,
    group_id: i64,
    limit: usize,
) -> io::Result<Vec<Value>> {
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id
             FROM nodes n
             JOIN group_nodes gn ON gn.node_id = n.id
             WHERE gn.group_id = ?1
             ORDER BY n.id
             LIMIT ?2",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id, limit], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn group_subscription_summaries_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.id, s.updated_at, s.link, s.status, s.info, s.tag, gs.name_filter_regex
             FROM subscriptions s
             JOIN group_subscriptions gs ON gs.subscription_id = s.id
             WHERE gs.group_id = ?1
             ORDER BY s.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, updated_at, link, status, info, tag, name_filter_regex) =
            row.map_err(sqlite_io_error)?;
        out.push(group_subscription_summary_value(
            conn,
            id,
            updated_at,
            link,
            status,
            info,
            tag,
            name_filter_regex,
        )?);
    }
    Ok(out)
}

fn group_subscription_summary_value(
    conn: &Connection,
    id: i64,
    updated_at: String,
    link: String,
    status: String,
    info: String,
    tag: Option<String>,
    name_filter_regex: Option<String>,
) -> io::Result<Value> {
    let matched_count =
        count_nodes_for_subscription_filtered(conn, id, name_filter_regex.as_deref())?;
    let sample_matched_nodes = nodes_for_subscription_filtered_sample_value(
        conn,
        id,
        name_filter_regex.as_deref(),
        GROUP_SUMMARY_MATCHED_NODE_SAMPLE_LIMIT,
    )?;
    Ok(json!({
        "subscriptionId": id,
        "nameFilterRegex": name_filter_regex,
        "matchedCount": matched_count,
        "sampleMatchedNodes": sample_matched_nodes,
        "updatedAt": updated_at,
        "status": status,
        "info": info,
        "link": link,
        "tag": tag,
    }))
}

pub(crate) fn create_group(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_GROUP_NAME);
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_GROUP_POLICY);
    let policy = match validate_group_policy(policy) {
        Ok(policy) => policy,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let node_ids = integer_array(&body, "nodeIds");
    let subscription_ids = integer_array(&body, "subscriptionIds");
    let mut conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = tx.execute(
        "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
        params![name, policy],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = tx.last_insert_rowid();
    if let Err(err) = replace_group_policy_params(&tx, id, body.get("policyParams")) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_node_ids(&tx, id, &node_ids, true) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_subscription_ids(&tx, id, &subscription_ids, None, true) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = tx.commit() {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    get_group(state, id).with_status(201)
}

pub(crate) fn get_group(state: &Path, id: i64) -> HttpResponse {
    match get_group_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "group not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn get_group_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    get_group_value_with_conn(&conn, id)
}

pub(crate) fn get_group_value_with_conn(conn: &Connection, id: i64) -> io::Result<Option<Value>> {
    let Some((group_id, name, policy, version)) = conn
        .query_row(
            "SELECT id, name, policy, version FROM groups WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_io_error)?
    else {
        return Ok(None);
    };
    let nodes = group_nodes_value(conn, group_id)?;
    let subscriptions = group_subscriptions_value(conn, group_id)?;
    let policy_params = group_policy_params_value(conn, group_id)?;
    Ok(Some(json!({
        "id": group_id,
        "name": name,
        "policy": policy,
        "policyParams": policy_params,
        "nodes": nodes,
        "subscriptions": subscriptions,
        "version": version,
    })))
}

pub(crate) fn update_group(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let policy = match body.get("policy").and_then(Value::as_str) {
        Some(policy) => match validate_group_policy(policy) {
            Ok(policy) => Some(policy),
            Err(err) => return HttpResponse::json(400, json!({"error": err})),
        },
        None => None,
    };
    let mut conn = conn;
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(name) = body.get("name").and_then(Value::as_str)
        && let Err(err) = tx.execute(
            "UPDATE groups SET name = ?1, version = version + 1 WHERE id = ?2",
            params![name, id],
        )
    {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Some(policy) = policy {
        if group_policy_is_fixed(policy) {
            let tags = match fixed_group_runtime_node_tags(&tx, id) {
                Ok(tags) => tags,
                Err(err) => return HttpResponse::json(400, json!({"error": err.to_string()})),
            };
            if let Err(err) = validate_fixed_group_runtime_node_tags(&tags) {
                return HttpResponse::json(400, json!({"error": err.to_string()}));
            }
        }
        if let Err(err) = tx.execute(
            "UPDATE groups SET policy = ?1, version = version + 1 WHERE id = ?2",
            params![policy, id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if body.get("policyParams").is_some()
        && let Err(err) = replace_group_policy_params(&tx, id, body.get("policyParams"))
    {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = tx.commit() {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    get_group(state, id)
}

pub(crate) fn delete_group(state: &Path, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    match running_group_references_id(&conn, id) {
        Ok(true) => {
            return HttpResponse::json(400, json!({"error": "running group cannot be deleted"}));
        }
        Ok(false) => {}
        Err(err) => return HttpResponse::json(400, json!({"error": err.to_string()})),
    }
    if let Err(err) = conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = conn.execute("DELETE FROM group_nodes WHERE group_id = ?1", params![id]) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = conn.execute(
        "DELETE FROM group_subscriptions WHERE group_id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    match conn.execute("DELETE FROM groups WHERE id = ?1", params![id]) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(crate) fn update_group_nodes(
    state: &Path,
    request: &HttpRequest,
    id: i64,
    add: bool,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "nodeIds");
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if add && let Err(err) = ensure_fixed_group_runtime_node_limit(&conn, id, &ids, &[], None) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_node_ids(&conn, id, &ids, add) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let _ = conn.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    );
    get_group(state, id)
}

pub(crate) fn update_group_subscriptions(
    state: &Path,
    request: &HttpRequest,
    id: i64,
    add: bool,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "subscriptionIds");
    let name_filter_regex = body.get("nameFilterRegex").and_then(Value::as_str);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if add
        && let Err(err) =
            ensure_fixed_group_runtime_node_limit(&conn, id, &[], &ids, name_filter_regex)
    {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_subscription_ids(&conn, id, &ids, name_filter_regex, add) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let _ = conn.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    );
    get_group(state, id)
}

pub(crate) fn group_nodes_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id
             FROM nodes n
             JOIN group_nodes gn ON gn.node_id = n.id
             WHERE gn.group_id = ?1
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn validate_group_policy(policy: &str) -> Result<&str, String> {
    let policy = policy.trim();
    if SUPPORTED_GROUP_POLICIES.contains(&policy) {
        return Ok(policy);
    }
    Err(format!(
        "unsupported group policy {policy:?}; allowed values: {}",
        SUPPORTED_GROUP_POLICIES.join(", ")
    ))
}

fn group_policy_is_fixed(policy: &str) -> bool {
    policy.trim() == GROUP_POLICY_FIXED
}

fn group_has_fixed_policy(conn: &Connection, group_id: i64) -> io::Result<bool> {
    let policy = conn
        .query_row(
            "SELECT policy FROM groups WHERE id = ?1",
            params![group_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?;
    Ok(policy
        .as_deref()
        .map(group_policy_is_fixed)
        .unwrap_or(false))
}

fn ensure_fixed_group_runtime_node_limit(
    conn: &Connection,
    group_id: i64,
    extra_node_ids: &[i64],
    extra_subscription_ids: &[i64],
    name_filter_regex: Option<&str>,
) -> io::Result<()> {
    if !group_has_fixed_policy(conn, group_id)? {
        return Ok(());
    }
    let mut tags = fixed_group_runtime_node_tags(conn, group_id)?;
    for node in nodes_by_ids_value(conn, extra_node_ids)? {
        push_unique(&mut tags, runtime_node_tag(&node));
    }
    for subscription_id in extra_subscription_ids {
        for node in
            nodes_for_subscription_filtered_value(conn, *subscription_id, name_filter_regex)?
        {
            push_unique(&mut tags, runtime_node_tag(&node));
        }
    }
    validate_fixed_group_runtime_node_tags(&tags)
}

fn validate_fixed_group_runtime_node_tags(tags: &[String]) -> io::Result<()> {
    if tags.len() <= 1 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "fixed group can match only one node; current selection would match {} nodes",
            tags.len()
        ),
    ))
}

fn fixed_group_runtime_node_tags(conn: &Connection, group_id: i64) -> io::Result<Vec<String>> {
    let mut tags = Vec::new();
    for node in group_nodes_value(conn, group_id)? {
        push_unique(&mut tags, runtime_node_tag(&node));
    }
    for subscription in group_subscriptions_value(conn, group_id)? {
        for node in subscription["matchedNodes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            push_unique(&mut tags, runtime_node_tag(node));
        }
    }
    Ok(tags)
}

fn nodes_by_ids_value(conn: &Connection, ids: &[i64]) -> io::Result<Vec<Value>> {
    let mut items = Vec::new();
    for id in ids {
        if let Some(node) = conn
            .query_row(
                "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes WHERE id = ?1",
                params![id],
                node_row_value,
            )
            .optional()
            .map_err(sqlite_io_error)?
        {
            items.push(node);
        }
    }
    Ok(items)
}

pub(crate) fn group_subscriptions_value(
    conn: &Connection,
    group_id: i64,
) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.id, s.updated_at, s.link, s.cron_exp, s.cron_enable, s.status, s.info, s.tag, gs.name_filter_regex
             FROM subscriptions s
             JOIN group_subscriptions gs ON gs.subscription_id = s.id
             WHERE gs.group_id = ?1
             ORDER BY s.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?
                    .unwrap_or_else(|| DEFAULT_SUBSCRIPTION_CRON_EXP.to_owned()),
                row.get::<_, i64>(4)? != 0,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, updated_at, link, _cron_exp, _cron_enable, status, info, tag, name_filter_regex) =
            row.map_err(sqlite_io_error)?;
        let matched_nodes =
            nodes_for_subscription_filtered_value(conn, id, name_filter_regex.as_deref())?;
        out.push(json!({
            "subscriptionId": id,
            "nameFilterRegex": name_filter_regex,
            "matchedCount": matched_nodes.len(),
            "matchedNodes": matched_nodes,
            "updatedAt": updated_at,
            "status": status,
            "info": info,
            "link": link,
            "tag": tag,
        }));
    }
    Ok(out)
}

pub(crate) fn nodes_for_subscription_filtered_value(
    conn: &Connection,
    subscription_id: i64,
    name_filter_regex: Option<&str>,
) -> io::Result<Vec<Value>> {
    let filter = compile_name_filter(name_filter_regex)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes WHERE subscription_id = ?1 ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        let node = row.map_err(sqlite_io_error)?;
        if node_matches_name_filter(&node, filter.as_ref()) {
            items.push(node);
        }
    }
    Ok(items)
}

pub(crate) fn count_nodes_for_subscription_filtered(
    conn: &Connection,
    subscription_id: i64,
    name_filter_regex: Option<&str>,
) -> io::Result<usize> {
    let filter = compile_name_filter(name_filter_regex)?;
    let mut stmt = conn
        .prepare("SELECT name FROM nodes WHERE subscription_id = ?1")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], |row| row.get::<_, String>(0))
        .map_err(sqlite_io_error)?;
    let mut count = 0_usize;
    for row in rows {
        let name = row.map_err(sqlite_io_error)?;
        if filter
            .as_ref()
            .map(|filter| filter.is_match(&name))
            .unwrap_or(true)
        {
            count += 1;
        }
    }
    Ok(count)
}

pub(crate) fn nodes_for_subscription_filtered_sample_value(
    conn: &Connection,
    subscription_id: i64,
    name_filter_regex: Option<&str>,
    limit: usize,
) -> io::Result<Vec<Value>> {
    let filter = compile_name_filter(name_filter_regex)?;
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
    let mut items = Vec::new();
    for row in rows {
        let node = row.map_err(sqlite_io_error)?;
        if node_matches_name_filter(&node, filter.as_ref()) {
            items.push(node);
            if items.len() >= limit {
                break;
            }
        }
    }
    Ok(items)
}

pub(crate) fn compile_name_filter(name_filter_regex: Option<&str>) -> io::Result<Option<Regex>> {
    let Some(raw) = name_filter_regex
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    Regex::new(raw)
        .map(Some)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}

pub(crate) fn node_matches_name_filter(node: &Value, filter: Option<&Regex>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    node.get("name")
        .and_then(Value::as_str)
        .map(|name| filter.is_match(name))
        .unwrap_or(false)
}

pub(crate) fn group_policy_params_value(
    conn: &Connection,
    group_id: i64,
) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM group_policy_params WHERE group_id = ?1 ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok(json!({
                "key": row.get::<_, String>(0)?,
                "val": row.get::<_, String>(1)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

pub(crate) fn replace_group_policy_params(
    conn: &Connection,
    group_id: i64,
    params_value: Option<&Value>,
) -> io::Result<()> {
    conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    if let Some(values) = params_value.and_then(Value::as_array) {
        for item in values {
            let key = item
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let value = item
                .get("val")
                .or_else(|| item.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            conn.execute(
                "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
                params![key, value, group_id],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

pub(crate) fn apply_group_node_ids(
    conn: &Connection,
    group_id: i64,
    ids: &[i64],
    add: bool,
) -> io::Result<()> {
    if add {
        ensure_fixed_group_runtime_node_limit(conn, group_id, ids, &[], None)?;
    }
    for id in ids {
        if add {
            conn.execute(
                "INSERT OR IGNORE INTO group_nodes(group_id, node_id) VALUES(?1, ?2)",
                params![group_id, id],
            )
        } else {
            conn.execute(
                "DELETE FROM group_nodes WHERE group_id = ?1 AND node_id = ?2",
                params![group_id, id],
            )
        }
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

pub(crate) fn apply_group_subscription_ids(
    conn: &Connection,
    group_id: i64,
    ids: &[i64],
    name_filter_regex: Option<&str>,
    add: bool,
) -> io::Result<()> {
    let name_filter_regex = name_filter_regex
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if add {
        let _ = compile_name_filter(name_filter_regex)?;
        ensure_fixed_group_runtime_node_limit(conn, group_id, &[], ids, name_filter_regex)?;
    }
    for id in ids {
        if add {
            conn.execute(
                "INSERT OR REPLACE INTO group_subscriptions(group_id, subscription_id, name_filter_regex) VALUES(?1, ?2, ?3)",
                params![group_id, id, name_filter_regex],
            )
        } else {
            conn.execute(
                "DELETE FROM group_subscriptions WHERE group_id = ?1 AND subscription_id = ?2",
                params![group_id, id],
            )
        }
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}
