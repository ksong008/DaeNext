use super::*;
use crate::daed_product::dae_file_import::stage::StagedDaeNode;
use rusqlite::Transaction;

pub(super) struct ExistingNode {
    id: i64,
    tag: Option<String>,
    subscription_id: Option<i64>,
    stable_key: StableNodeKey,
}

pub(super) fn load_existing_nodes(tx: &Transaction<'_>) -> io::Result<Vec<ExistingNode>> {
    let mut stmt = tx
        .prepare("SELECT id, link, tag, subscription_id FROM nodes ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            let link = row.get::<_, String>(1)?;
            Ok(ExistingNode {
                id: row.get(0)?,
                stable_key: StableNodeKey::from_link(&link),
                tag: row.get(2)?,
                subscription_id: row.get(3)?,
            })
        })
        .map_err(sqlite_io_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_io_error)
}

pub(super) fn upsert_imported_node(
    tx: &Transaction<'_>,
    existing: &mut Vec<ExistingNode>,
    node: &StagedDaeNode,
) -> io::Result<i64> {
    let parsed = parse_node_link(&node.link, Some(&node.tag));
    let stored_link = parsed
        .normalized_link
        .clone()
        .unwrap_or_else(|| node.link.clone());
    let stable_matches = existing
        .iter()
        .enumerate()
        .filter(|(_, current)| {
            current.subscription_id.is_none() && current.stable_key == parsed.stable_key
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if stable_matches.len() > 1 {
        return Err(invalid_dae_file(format!(
            "node {:?} matches multiple existing independent node identities",
            node.tag
        )));
    }
    let tag_match = existing
        .iter()
        .enumerate()
        .find(|(_, current)| current.tag.as_deref() == Some(node.tag.as_str()))
        .map(|(index, _)| index);
    if let Some(index) = tag_match
        && existing[index].subscription_id.is_some()
    {
        return Err(invalid_dae_file(format!(
            "node tag {:?} belongs to a subscription-managed node",
            node.tag
        )));
    }
    if let (Some(stable_index), Some(tag_index)) = (stable_matches.first().copied(), tag_match)
        && stable_index != tag_index
    {
        return Err(invalid_dae_file(format!(
            "node {:?} has conflicting stable identity and existing tag",
            node.tag
        )));
    }

    let existing_index = stable_matches.first().copied().or(tag_match);
    if let Some(index) = existing_index {
        update_existing_node(tx, existing, index, node, parsed, stored_link)
    } else {
        insert_imported_node(tx, existing, node, parsed, stored_link)
    }
}

fn update_existing_node(
    tx: &Transaction<'_>,
    existing: &mut [ExistingNode],
    index: usize,
    node: &StagedDaeNode,
    parsed: ParsedNodeLink,
    stored_link: String,
) -> io::Result<i64> {
    let identity_changed = existing[index].stable_key != parsed.stable_key;
    let id = existing[index].id;
    tx.execute(
        "UPDATE nodes SET link = ?1, name = ?2, address = ?3, protocol = ?4, tag = ?5, subscription_id = NULL WHERE id = ?6",
        params![
            stored_link,
            parsed.display_name,
            parsed.address,
            parsed.protocol,
            node.tag,
            id,
        ],
    )
    .map_err(sqlite_io_error)?;
    if identity_changed {
        tx.execute(
            "DELETE FROM node_latency_results WHERE node_id = ?1",
            params![id],
        )
        .map_err(sqlite_io_error)?;
    }
    existing[index] = ExistingNode {
        id,
        tag: Some(node.tag.clone()),
        subscription_id: None,
        stable_key: parsed.stable_key,
    };
    Ok(id)
}

fn insert_imported_node(
    tx: &Transaction<'_>,
    existing: &mut Vec<ExistingNode>,
    node: &StagedDaeNode,
    parsed: ParsedNodeLink,
    stored_link: String,
) -> io::Result<i64> {
    tx.execute(
        "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, ?5, NULL)",
        params![
            stored_link,
            parsed.display_name,
            parsed.address,
            parsed.protocol,
            node.tag,
        ],
    )
    .map_err(sqlite_io_error)?;
    let id = tx.last_insert_rowid();
    existing.push(ExistingNode {
        id,
        tag: Some(node.tag.clone()),
        subscription_id: None,
        stable_key: parsed.stable_key,
    });
    Ok(id)
}
