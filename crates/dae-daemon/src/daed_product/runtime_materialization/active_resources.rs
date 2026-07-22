use super::*;

#[derive(Debug)]
pub(in crate::daed_product) struct ActiveRuntimeResources {
    pub(in crate::daed_product) groups: Value,
    pub(in crate::daed_product) nodes: Value,
    pub(in crate::daed_product) group_ids: Vec<i64>,
    pub(in crate::daed_product) group_version_sum: i64,
}

#[derive(Debug)]
struct ActiveGroupRow {
    id: i64,
    name: String,
    policy: String,
    version: i64,
}

#[derive(Debug)]
struct ActiveSubscriptionBinding {
    subscription_id: i64,
    updated_at: String,
    link: String,
    status: String,
    info: String,
    tag: Option<String>,
    name_filter_regex: Option<String>,
}

pub(in crate::daed_product) fn load_active_runtime_resources(
    conn: &Connection,
    routing_raw: &str,
) -> io::Result<ActiveRuntimeResources> {
    let routing_text =
        render_routing_section((!routing_raw.trim().is_empty()).then_some(routing_raw));
    let referenced_groups =
        referenced_group_names_from_routing(&routing_text).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "selected routing could not be parsed while resolving runtime groups",
            )
        })?;
    if referenced_groups.is_empty() {
        return Ok(ActiveRuntimeResources {
            groups: json!({"items": []}),
            nodes: json!({"items": [], "totalCount": 0, "nextAfterId": Value::Null}),
            group_ids: Vec::new(),
            group_version_sum: 0,
        });
    }

    let groups = load_groups(conn, &referenced_groups)?;
    let group_ids = groups.iter().map(|group| group.id).collect::<Vec<_>>();
    let group_version_sum = groups
        .iter()
        .map(|group| group.version)
        .fold(0_i64, i64::saturating_add);
    let policy_params = load_policy_params(conn, &group_ids)?;
    let direct_nodes = load_direct_nodes(conn, &group_ids)?;
    let bindings = load_subscription_bindings(conn, &group_ids)?;
    let subscription_ids = bindings
        .values()
        .flatten()
        .map(|binding| binding.subscription_id)
        .collect::<BTreeSet<_>>();
    let subscription_nodes = load_subscription_nodes(conn, &subscription_ids)?;

    let mut active_nodes = BTreeMap::<i64, Value>::new();
    let mut group_values = Vec::with_capacity(groups.len());
    for group in &groups {
        let direct = direct_nodes.get(&group.id).cloned().unwrap_or_default();
        for node in &direct {
            insert_active_node(&mut active_nodes, node);
        }
        let mut subscription_values = Vec::new();
        for binding in bindings.get(&group.id).into_iter().flatten() {
            let filter = compile_name_filter(binding.name_filter_regex.as_deref())?;
            let matched_nodes = subscription_nodes
                .get(&binding.subscription_id)
                .into_iter()
                .flatten()
                .filter(|node| node_matches_name_filter(node, filter.as_ref()))
                .cloned()
                .collect::<Vec<_>>();
            for node in &matched_nodes {
                insert_active_node(&mut active_nodes, node);
            }
            subscription_values.push(json!({
                "subscriptionId": binding.subscription_id,
                "nameFilterRegex": binding.name_filter_regex,
                "matchedCount": matched_nodes.len(),
                "matchedNodes": matched_nodes,
                "updatedAt": binding.updated_at,
                "status": binding.status,
                "info": binding.info,
                "link": binding.link,
                "tag": binding.tag,
            }));
        }
        group_values.push(json!({
            "id": group.id,
            "name": group.name,
            "policy": group.policy,
            "policyParams": policy_params.get(&group.id).cloned().unwrap_or_default(),
            "nodes": direct,
            "subscriptions": subscription_values,
            "version": group.version,
        }));
    }
    let node_values = active_nodes.into_values().collect::<Vec<_>>();
    Ok(ActiveRuntimeResources {
        groups: json!({"items": group_values}),
        nodes: json!({
            "totalCount": node_values.len(),
            "items": node_values,
            "nextAfterId": Value::Null,
        }),
        group_ids,
        group_version_sum,
    })
}

fn load_groups(conn: &Connection, names: &BTreeSet<String>) -> io::Result<Vec<ActiveGroupRow>> {
    let sql = format!(
        "SELECT id, name, policy, version FROM groups WHERE name IN ({}) ORDER BY id",
        sql_placeholders(names.len())
    );
    let mut statement = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(names.iter()), |row| {
            Ok(ActiveGroupRow {
                id: row.get(0)?,
                name: row.get(1)?,
                policy: row.get(2)?,
                version: row.get(3)?,
            })
        })
        .map_err(sqlite_io_error)?;
    collect_rows(rows)
}

fn load_policy_params(
    conn: &Connection,
    group_ids: &[i64],
) -> io::Result<HashMap<i64, Vec<Value>>> {
    if group_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT group_id, key, value FROM group_policy_params WHERE group_id IN ({}) ORDER BY group_id, id",
        sql_placeholders(group_ids.len())
    );
    let mut statement = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(group_ids), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                json!({
                    "key": row.get::<_, String>(1)?,
                    "val": row.get::<_, String>(2)?,
                }),
            ))
        })
        .map_err(sqlite_io_error)?;
    collect_grouped_rows(rows)
}

fn load_direct_nodes(conn: &Connection, group_ids: &[i64]) -> io::Result<HashMap<i64, Vec<Value>>> {
    if group_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT gn.group_id, n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id
         FROM group_nodes gn
         JOIN nodes n ON n.id = gn.node_id
         WHERE gn.group_id IN ({})
         ORDER BY gn.group_id, n.id",
        sql_placeholders(group_ids.len())
    );
    let mut statement = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(group_ids), |row| {
            Ok((row.get::<_, i64>(0)?, active_node_value(row, 1)?))
        })
        .map_err(sqlite_io_error)?;
    collect_grouped_rows(rows)
}

fn load_subscription_bindings(
    conn: &Connection,
    group_ids: &[i64],
) -> io::Result<HashMap<i64, Vec<ActiveSubscriptionBinding>>> {
    if group_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT gs.group_id, s.id, s.updated_at, s.link, s.status, s.info, s.tag,
                gs.name_filter_regex
         FROM group_subscriptions gs
         JOIN subscriptions s ON s.id = gs.subscription_id
         WHERE gs.group_id IN ({})
         ORDER BY gs.group_id, s.id",
        sql_placeholders(group_ids.len())
    );
    let mut statement = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(group_ids), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                ActiveSubscriptionBinding {
                    subscription_id: row.get(1)?,
                    updated_at: row.get(2)?,
                    link: row.get(3)?,
                    status: row.get(4)?,
                    info: row.get(5)?,
                    tag: row.get(6)?,
                    name_filter_regex: row.get(7)?,
                },
            ))
        })
        .map_err(sqlite_io_error)?;
    collect_grouped_rows(rows)
}

fn load_subscription_nodes(
    conn: &Connection,
    subscription_ids: &BTreeSet<i64>,
) -> io::Result<HashMap<i64, Vec<Value>>> {
    if subscription_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!(
        "SELECT subscription_id, id, link, name, address, protocol, tag, subscription_id
         FROM nodes
         WHERE subscription_id IN ({})
         ORDER BY subscription_id, id",
        sql_placeholders(subscription_ids.len())
    );
    let mut statement = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(subscription_ids.iter()), |row| {
            Ok((row.get::<_, i64>(0)?, active_node_value(row, 1)?))
        })
        .map_err(sqlite_io_error)?;
    collect_grouped_rows(rows)
}

fn active_node_value(row: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<Value> {
    let id = row.get::<_, i64>(offset)?;
    let subscription_id = row.get::<_, Option<i64>>(offset + 6)?;
    let name = row.get::<_, String>(offset + 2)?;
    let tag = row.get::<_, Option<String>>(offset + 5)?;
    Ok(json!({
        "id": id,
        "link": row.get::<_, String>(offset + 1)?,
        "name": decode_node_label(&name),
        "address": row.get::<_, String>(offset + 3)?,
        "protocol": row.get::<_, String>(offset + 4)?,
        "transport": Value::Null,
        "tag": tag.as_deref().map(decode_node_label),
        "runtimeTag": RuntimeNodeTag::from_node_id(id).into_string(),
        "subscriptionId": subscription_id,
        "subscriptionID": subscription_id.map(|value| value.to_string()),
    }))
}

fn insert_active_node(nodes: &mut BTreeMap<i64, Value>, node: &Value) {
    if let Some(id) = node.get("id").and_then(Value::as_i64) {
        nodes.entry(id).or_insert_with(|| node.clone());
    }
}

fn sql_placeholders(len: usize) -> String {
    std::iter::repeat_n("?", len).collect::<Vec<_>>().join(",")
}

fn collect_rows<T>(rows: impl Iterator<Item = rusqlite::Result<T>>) -> io::Result<Vec<T>> {
    let mut values = Vec::new();
    for row in rows {
        values.push(row.map_err(sqlite_io_error)?);
    }
    Ok(values)
}

fn collect_grouped_rows<T>(
    rows: impl Iterator<Item = rusqlite::Result<(i64, T)>>,
) -> io::Result<HashMap<i64, Vec<T>>> {
    let mut values = HashMap::<i64, Vec<T>>::new();
    for row in rows {
        let (key, value) = row.map_err(sqlite_io_error)?;
        values.entry(key).or_default().push(value);
    }
    Ok(values)
}
