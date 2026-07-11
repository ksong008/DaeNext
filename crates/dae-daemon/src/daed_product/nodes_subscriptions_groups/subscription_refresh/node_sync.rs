use super::*;

#[cfg(test)]
pub(crate) fn replace_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
    links: &[String],
) -> io::Result<Vec<Value>> {
    let prepared = super::node_stage::prepare_subscription_nodes(links);
    replace_prepared_subscription_nodes(conn, subscription_id, &prepared).map(|result| result.items)
}

pub(super) struct SubscriptionNodeSyncResult {
    pub(super) runtime_input_changed: bool,
    pub(super) items: Vec<Value>,
}

pub(super) fn replace_prepared_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
    candidates: &[super::node_stage::PreparedSubscriptionNode],
) -> io::Result<SubscriptionNodeSyncResult> {
    let existing_nodes = existing_subscription_nodes(conn, subscription_id)?;
    let mut existing_name_counts = HashMap::<String, usize>::new();
    let mut existing_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    let mut existing_key_counts = HashMap::<StableNodeKey, usize>::new();
    let mut existing_by_key = HashMap::<StableNodeKey, ExistingSubscriptionNode>::new();
    for node in &existing_nodes {
        *existing_name_counts
            .entry(node.display_name.clone())
            .or_default() += 1;
        existing_by_name.insert(node.display_name.clone(), node.clone());
        *existing_key_counts
            .entry(node.stable_key.clone())
            .or_default() += 1;
        existing_by_key.insert(node.stable_key.clone(), node.clone());
    }
    let mut incoming_name_counts = HashMap::<String, usize>::new();
    let mut incoming_key_counts = HashMap::<StableNodeKey, usize>::new();
    for candidate in candidates {
        let parsed = &candidate.parsed;
        *incoming_name_counts
            .entry(parsed.display_name.clone())
            .or_default() += 1;
        *incoming_key_counts
            .entry(parsed.stable_key.clone())
            .or_default() += 1;
    }

    let mut reusable_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    for (name, incoming_count) in &incoming_name_counts {
        if *incoming_count != 1 {
            continue;
        }
        if existing_name_counts.get(name).copied().unwrap_or(0) == 1
            && let Some(node) = existing_by_name.get(name)
        {
            reusable_by_name.insert(name.clone(), node.clone());
        }
    }
    let mut reusable_by_key = HashMap::<StableNodeKey, ExistingSubscriptionNode>::new();
    for (stable_key, incoming_count) in &incoming_key_counts {
        if *incoming_count != 1 {
            continue;
        }
        if existing_key_counts.get(stable_key).copied().unwrap_or(0) == 1
            && let Some(node) = existing_by_key.get(stable_key)
        {
            reusable_by_key.insert(stable_key.clone(), node.clone());
        }
    }
    let reusable_ids = reusable_by_name
        .values()
        .chain(reusable_by_key.values())
        .map(|node| node.id)
        .collect::<HashSet<_>>();
    let mut live_links = existing_nodes
        .iter()
        .map(|node| node.link.clone())
        .collect::<HashSet<_>>();
    let mut runtime_input_changed = false;

    for node in existing_nodes
        .iter()
        .filter(|node| !reusable_ids.contains(&node.id))
    {
        bump_group_versions_for_node(conn, node.id)?;
        conn.prepare_cached("DELETE FROM group_nodes WHERE node_id = ?1")
            .map_err(sqlite_io_error)?
            .execute(params![node.id])
            .map_err(sqlite_io_error)?;
        conn.prepare_cached("DELETE FROM node_latency_results WHERE node_id = ?1")
            .map_err(sqlite_io_error)?
            .execute(params![node.id])
            .map_err(sqlite_io_error)?;
        conn.prepare_cached("DELETE FROM nodes WHERE id = ?1")
            .map_err(sqlite_io_error)?
            .execute(params![node.id])
            .map_err(sqlite_io_error)?;
        live_links.remove(&node.link);
        runtime_input_changed = true;
    }

    let mut out = Vec::new();
    let mut reused_nodes = HashSet::<i64>::new();
    for candidate in candidates {
        let link = &candidate.stored_link;
        let parsed = &candidate.parsed;
        if let Some(preserved) = reusable_by_key
            .get(&parsed.stable_key)
            .or_else(|| reusable_by_name.get(&parsed.display_name))
            && reused_nodes.insert(preserved.id)
        {
            if !subscription_node_changed(preserved, link, parsed) {
                out.push(json!({
                    "link": link,
                    "error": Value::Null,
                    "node": {"id": preserved.id}
                }));
                continue;
            }
            match conn.prepare_cached(
                "UPDATE nodes
                         SET link = ?1,
                             name = ?2,
                             address = ?3,
                             protocol = ?4,
                             tag = NULL,
                             subscription_id = ?5
                         WHERE id = ?6",
            ) {
                Ok(mut statement) => match statement.execute(params![
                    link,
                    parsed.display_name,
                    parsed.address,
                    parsed.protocol,
                    subscription_id,
                    preserved.id
                ]) {
                    Ok(_) => {
                        if subscription_node_probe_target_changed(preserved, parsed) {
                            conn.prepare_cached(
                                "DELETE FROM node_latency_results WHERE node_id = ?1",
                            )
                            .map_err(sqlite_io_error)?
                            .execute(params![preserved.id])
                            .map_err(sqlite_io_error)?;
                        }
                        bump_group_versions_for_node(conn, preserved.id)?;
                        live_links.remove(&preserved.link);
                        live_links.insert(link.clone());
                        runtime_input_changed = true;
                        out.push(json!({
                            "link": link,
                            "error": Value::Null,
                            "node": {"id": preserved.id}
                        }));
                        continue;
                    }
                    Err(err) => {
                        out.push(json!({
                            "link": link,
                            "error": err.to_string(),
                            "node": Value::Null
                        }));
                        continue;
                    }
                },
                Err(err) => {
                    out.push(json!({
                        "link": link,
                        "error": err.to_string(),
                        "node": Value::Null
                    }));
                    continue;
                }
            }
        }

        if live_links.contains(link) {
            out.push(json!({
                "link": link,
                "error": "node duplicated",
                "node": Value::Null
            }));
            continue;
        }
        match conn.prepare_cached(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, NULL, ?5)",
        ) {
            Ok(mut statement) => match statement.execute(params![
                link,
                parsed.display_name,
                parsed.address,
                parsed.protocol,
                subscription_id
            ]) {
            Ok(_) => {
                let id = conn.last_insert_rowid();
                live_links.insert(link.clone());
                runtime_input_changed = true;
                out.push(json!({
                    "link": link,
                    "error": Value::Null,
                    "node": {"id": id}
                }));
            }
            Err(err) => out.push(json!({
                "link": link,
                "error": err.to_string(),
                "node": Value::Null
            })),
        },
            Err(err) => out.push(json!({
                "link": link,
                "error": err.to_string(),
                "node": Value::Null
            })),
        }
    }
    if runtime_input_changed {
        bump_group_versions_for_subscription(conn, subscription_id)?;
    }
    Ok(SubscriptionNodeSyncResult {
        runtime_input_changed,
        items: out,
    })
}

#[derive(Clone)]
pub(crate) struct ExistingSubscriptionNode {
    pub(super) id: i64,
    pub(super) link: String,
    pub(super) display_name: String,
    pub(super) address: String,
    pub(super) protocol: String,
    pub(super) stable_key: StableNodeKey,
}

pub(crate) fn subscription_node_changed(
    current: &ExistingSubscriptionNode,
    next_link: &str,
    next: &ParsedNodeLink,
) -> bool {
    current.link != next_link
        || current.display_name != next.display_name
        || current.address != next.address
        || current.protocol != next.protocol
}

pub(crate) fn subscription_node_probe_target_changed(
    current: &ExistingSubscriptionNode,
    next: &ParsedNodeLink,
) -> bool {
    current.address != next.address
        || current.protocol != next.protocol
        || current.stable_key != next.stable_key
}

pub(crate) fn existing_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<Vec<ExistingSubscriptionNode>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol
             FROM nodes
             WHERE subscription_id = ?1
             ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], |row| {
            let link = row.get::<_, String>(1)?;
            let stable_key = StableNodeKey::from_link(&link);
            Ok(ExistingSubscriptionNode {
                id: row.get(0)?,
                link,
                display_name: row.get(2)?,
                address: row.get(3)?,
                protocol: row.get(4)?,
                stable_key,
            })
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

pub(crate) fn bump_group_versions_for_node(conn: &Connection, node_id: i64) -> io::Result<()> {
    conn.execute(
        "UPDATE groups
         SET version = version + 1
         WHERE id IN (SELECT group_id FROM group_nodes WHERE node_id = ?1)",
        params![node_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

pub(crate) fn bump_group_versions_for_subscription(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<()> {
    conn.execute(
        "UPDATE groups
         SET version = version + 1
         WHERE id IN (
             SELECT group_id FROM group_subscriptions WHERE subscription_id = ?1
         )",
        params![subscription_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}
