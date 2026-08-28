use super::*;

pub(crate) fn delete_subscription(state: &Path, id: i64) -> io::Result<usize> {
    delete_subscriptions_by_ids(state, &[id])
}

pub(in crate::daed_product) fn delete_subscriptions_by_ids(
    state: &Path,
    ids: &[i64],
) -> io::Result<usize> {
    let ids = ids.iter().copied().collect::<BTreeSet<_>>();
    if ids.is_empty() {
        return Ok(0);
    }

    let _guard = subscription_write_guard()?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    let affected_groups = affected_group_ids(&tx, &ids)?;
    let mut removed = 0_usize;
    for id in ids {
        tx.execute(
            "DELETE FROM group_nodes
             WHERE node_id IN (SELECT id FROM nodes WHERE subscription_id = ?1)",
            params![id],
        )
        .map_err(sqlite_io_error)?;
        tx.execute(
            "DELETE FROM node_latency_results
             WHERE node_id IN (SELECT id FROM nodes WHERE subscription_id = ?1)",
            params![id],
        )
        .map_err(sqlite_io_error)?;
        tx.execute(
            "DELETE FROM group_subscriptions WHERE subscription_id = ?1",
            params![id],
        )
        .map_err(sqlite_io_error)?;
        tx.execute("DELETE FROM nodes WHERE subscription_id = ?1", params![id])
            .map_err(sqlite_io_error)?;
        removed = removed.saturating_add(
            tx.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])
                .map_err(sqlite_io_error)?,
        );
    }
    if removed != 0 {
        for group_id in affected_groups {
            tx.execute(
                "UPDATE groups SET version = version + 1 WHERE id = ?1",
                params![group_id],
            )
            .map_err(sqlite_io_error)?;
        }
        bump_runtime_external_input_version_with_connection(&tx)?;
    }
    tx.commit().map_err(sqlite_io_error)?;
    if removed != 0 {
        notify_subscription_scheduler();
    }
    Ok(removed)
}

fn affected_group_ids(conn: &Connection, ids: &BTreeSet<i64>) -> io::Result<BTreeSet<i64>> {
    let mut groups = BTreeSet::new();
    for id in ids {
        let mut statement = conn
            .prepare_cached(
                "SELECT group_id FROM group_subscriptions WHERE subscription_id = ?1
                 UNION
                 SELECT group_id FROM group_nodes
                 WHERE node_id IN (SELECT id FROM nodes WHERE subscription_id = ?1)",
            )
            .map_err(sqlite_io_error)?;
        let rows = statement
            .query_map(params![id], |row| row.get::<_, i64>(0))
            .map_err(sqlite_io_error)?;
        for row in rows {
            groups.insert(row.map_err(sqlite_io_error)?);
        }
    }
    Ok(groups)
}
