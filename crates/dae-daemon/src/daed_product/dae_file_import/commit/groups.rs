use super::*;
use crate::daed_product::dae_file_import::stage::StagedDaeGroup;
use rusqlite::Transaction;

pub(super) fn upsert_imported_group(
    tx: &Transaction<'_>,
    group: &StagedDaeGroup,
    node_ids_by_tag: &BTreeMap<String, i64>,
) -> io::Result<i64> {
    let existing = tx
        .query_row(
            "SELECT id FROM groups WHERE name = ?1",
            params![group.name],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?;
    let id = if let Some(id) = existing {
        tx.execute(
            "UPDATE groups SET policy = ?1, version = version + 1 WHERE id = ?2",
            params![group.policy, id],
        )
        .map_err(sqlite_io_error)?;
        id
    } else {
        tx.execute(
            "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
            params![group.name, group.policy],
        )
        .map_err(sqlite_io_error)?;
        tx.last_insert_rowid()
    };
    replace_policy_params(tx, id, group)?;
    replace_node_bindings(tx, id, group, node_ids_by_tag)?;
    Ok(id)
}

fn replace_policy_params(
    tx: &Transaction<'_>,
    group_id: i64,
    group: &StagedDaeGroup,
) -> io::Result<()> {
    tx.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    for (key, value) in &group.policy_params {
        tx.execute(
            "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
            params![key, value, group_id],
        )
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn replace_node_bindings(
    tx: &Transaction<'_>,
    group_id: i64,
    group: &StagedDaeGroup,
    node_ids_by_tag: &BTreeMap<String, i64>,
) -> io::Result<()> {
    tx.execute(
        "DELETE FROM group_nodes WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    tx.execute(
        "DELETE FROM group_subscriptions WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    for tag in &group.node_tags {
        let node_id = node_ids_by_tag.get(tag).ok_or_else(|| {
            invalid_dae_file(format!(
                "group {:?} references unresolved node {tag:?}",
                group.name
            ))
        })?;
        tx.execute(
            "INSERT INTO group_nodes(
                group_id, node_id, binding_mode, source_subscription_id
             ) VALUES(?1, ?2, 'manual', NULL)",
            params![group_id, node_id],
        )
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}
