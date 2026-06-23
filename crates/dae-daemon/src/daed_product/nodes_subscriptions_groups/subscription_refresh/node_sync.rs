use super::*;

pub(crate) fn replace_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
    links: &[String],
) -> io::Result<Vec<Value>> {
    let existing_nodes = existing_subscription_nodes(conn, subscription_id)?;
    let preserved_ids = preserved_subscription_node_ids(conn, subscription_id)?;
    let mut existing_name_counts = HashMap::<String, usize>::new();
    let mut existing_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    for node in &existing_nodes {
        *existing_name_counts.entry(node.name.clone()).or_default() += 1;
        existing_by_name.insert(node.name.clone(), node.clone());
    }
    let mut preserved_name_counts = HashMap::<String, usize>::new();
    let mut preserved_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    for node in existing_nodes
        .iter()
        .filter(|node| preserved_ids.contains(&node.id))
    {
        *preserved_name_counts.entry(node.name.clone()).or_default() += 1;
        preserved_by_name.insert(node.name.clone(), node.clone());
    }

    let mut candidates = Vec::<(String, ParsedNodeLink)>::new();
    let mut incoming_name_counts = HashMap::<String, usize>::new();
    for link in links {
        let parsed = parse_node_link(link.as_str(), None);
        let stored_link = parsed
            .normalized_link
            .clone()
            .unwrap_or_else(|| link.clone());
        *incoming_name_counts.entry(parsed.name.clone()).or_default() += 1;
        candidates.push((stored_link, parsed));
    }

    let mut reusable_by_name = HashMap::<String, ExistingSubscriptionNode>::new();
    for (name, incoming_count) in &incoming_name_counts {
        if *incoming_count != 1 {
            continue;
        }
        if preserved_name_counts.get(name).copied().unwrap_or(0) == 1 {
            if let Some(node) = preserved_by_name.get(name) {
                reusable_by_name.insert(name.clone(), node.clone());
            }
        } else if existing_name_counts.get(name).copied().unwrap_or(0) == 1
            && let Some(node) = existing_by_name.get(name)
        {
            reusable_by_name.insert(name.clone(), node.clone());
        }
    }
    let reusable_ids = reusable_by_name
        .values()
        .map(|node| node.id)
        .collect::<HashSet<_>>();

    for node in existing_nodes
        .iter()
        .filter(|node| !reusable_ids.contains(&node.id) && !preserved_ids.contains(&node.id))
    {
        conn.execute(
            "DELETE FROM group_nodes WHERE node_id = ?1",
            params![node.id],
        )
        .map_err(sqlite_io_error)?;
        conn.execute(
            "DELETE FROM node_latency_results WHERE node_id = ?1",
            params![node.id],
        )
        .map_err(sqlite_io_error)?;
        conn.execute("DELETE FROM nodes WHERE id = ?1", params![node.id])
            .map_err(sqlite_io_error)?;
    }

    let mut out = Vec::new();
    let mut reused_nodes = HashSet::<i64>::new();
    for (link, parsed) in candidates {
        if let Some(preserved) = reusable_by_name.get(&parsed.name)
            && reused_nodes.insert(preserved.id)
        {
            if !subscription_node_changed(preserved, &link, &parsed) {
                out.push(json!({
                    "link": link,
                    "error": Value::Null,
                    "node": {"id": preserved.id}
                }));
                continue;
            }
            match conn.execute(
                "UPDATE nodes
                         SET link = ?1,
                             name = ?2,
                             address = ?3,
                             protocol = ?4,
                             tag = NULL,
                             subscription_id = ?5
                         WHERE id = ?6",
                params![
                    link,
                    parsed.name,
                    parsed.address,
                    parsed.protocol,
                    subscription_id,
                    preserved.id
                ],
            ) {
                Ok(_) => {
                    conn.execute(
                        "DELETE FROM node_latency_results WHERE node_id = ?1",
                        params![preserved.id],
                    )
                    .map_err(sqlite_io_error)?;
                    bump_group_versions_for_node(conn, preserved.id)?;
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
            }
        }

        if subscription_node_link_exists(conn, subscription_id, &link)? {
            out.push(json!({
                "link": link,
                "error": "node duplicated",
                "node": Value::Null
            }));
            continue;
        }
        match conn.execute(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, NULL, ?5)",
            params![link, parsed.name, parsed.address, parsed.protocol, subscription_id],
        ) {
            Ok(_) => {
                let id = conn.last_insert_rowid();
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
        }
    }
    bump_group_versions_for_subscription(conn, subscription_id)?;
    Ok(out)
}

#[derive(Clone)]
pub(crate) struct ExistingSubscriptionNode {
    pub(super) id: i64,
    pub(super) link: String,
    pub(super) name: String,
    pub(super) address: String,
    pub(super) protocol: String,
}

pub(crate) fn subscription_node_changed(
    current: &ExistingSubscriptionNode,
    next_link: &str,
    next: &ParsedNodeLink,
) -> bool {
    current.link != next_link
        || current.name != next.name
        || current.address != next.address
        || current.protocol != next.protocol
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
            Ok(ExistingSubscriptionNode {
                id: row.get(0)?,
                link: row.get(1)?,
                name: row.get(2)?,
                address: row.get(3)?,
                protocol: row.get(4)?,
            })
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

pub(crate) fn preserved_subscription_node_ids(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<HashSet<i64>> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT n.id
             FROM nodes n
             JOIN group_nodes gn ON gn.node_id = n.id
             WHERE n.subscription_id = ?1",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut out = HashSet::new();
    for row in rows {
        out.insert(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

pub(crate) fn subscription_node_link_exists(
    conn: &Connection,
    subscription_id: i64,
    link: &str,
) -> io::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM nodes WHERE subscription_id = ?1 AND link = ?2",
        params![subscription_id, link],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
    .map_err(sqlite_io_error)
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
