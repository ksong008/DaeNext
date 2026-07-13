use super::*;

pub(super) struct SubscriptionRefreshApplyResult {
    pub(super) runtime_input_changed: bool,
    pub(super) node_import_result: Vec<Value>,
    pub(super) refresh_outcome: &'static str,
    pub(super) source_kind: &'static str,
    pub(super) source_node_count: usize,
    pub(super) admitted_node_count: usize,
    pub(super) invalid_node_count: usize,
    pub(super) not_admitted_node_count: usize,
    pub(super) preserved_existing_nodes: bool,
}

pub(super) fn apply_subscription_refresh_report(
    state: &Path,
    id: i64,
    fetched_at: &str,
    content: &content::SubscriptionContentReport,
) -> io::Result<SubscriptionRefreshApplyResult> {
    let prepared = node_stage::prepare_subscription_nodes(&content.links);
    let admitted_node_count = prepared.admitted.len();
    let invalid_node_count = content
        .invalid_source_count
        .saturating_add(prepared.invalid.len());
    let not_admitted_node_count = prepared.not_admitted.len();
    let mut node_import_result = rejected_node_results(&prepared);

    let _guard = subscription_write_guard()?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    ensure_subscription_exists(&tx, id)?;

    let (runtime_input_changed, preserved_existing_nodes, refresh_outcome) =
        if prepared.admitted.is_empty() {
            (
                false,
                true,
                preserved_refresh_outcome(content, invalid_node_count, not_admitted_node_count),
            )
        } else {
            let sync_result =
                node_sync::replace_prepared_subscription_nodes(&tx, id, &prepared.admitted)?;
            node_import_result.splice(0..0, sync_result.items);
            let outcome = if invalid_node_count != 0 || not_admitted_node_count != 0 {
                "partial"
            } else if sync_result.runtime_input_changed {
                "updated"
            } else {
                "unchanged"
            };
            (sync_result.runtime_input_changed, false, outcome)
        };

    let info = format!(
        "subscription refresh {refresh_outcome}: source={}, sourceNodes={}, admitted={}, invalid={}, notAdmitted={}",
        content.kind.as_str(),
        content.source_node_count,
        admitted_node_count,
        invalid_node_count,
        not_admitted_node_count,
    );
    tx.execute(
        "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
        params![fetched_at, "fetched", info, id],
    )
    .map_err(sqlite_io_error)?;
    if runtime_input_changed {
        bump_runtime_external_input_version_with_connection(&tx)?;
    }
    tx.commit().map_err(sqlite_io_error)?;

    Ok(SubscriptionRefreshApplyResult {
        runtime_input_changed,
        node_import_result,
        refresh_outcome,
        source_kind: content.kind.as_str(),
        source_node_count: content.source_node_count,
        admitted_node_count,
        invalid_node_count,
        not_admitted_node_count,
        preserved_existing_nodes,
    })
}

pub(super) fn record_subscription_fetch_error(
    state: &Path,
    id: i64,
    fetched_at: &str,
    error: &str,
) -> io::Result<()> {
    let _guard = subscription_write_guard()?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    let updated = tx
        .execute(
            "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
            params![fetched_at, "fetch_error", error, id],
        )
        .map_err(sqlite_io_error)?;
    if updated == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "subscription not found",
        ));
    }
    tx.commit().map_err(sqlite_io_error)
}

fn preserved_refresh_outcome(
    content: &content::SubscriptionContentReport,
    invalid_node_count: usize,
    not_admitted_node_count: usize,
) -> &'static str {
    if content.empty {
        "empty-preserved"
    } else if invalid_node_count != 0 && not_admitted_node_count == 0 {
        "all-invalid-preserved"
    } else if invalid_node_count == 0 && not_admitted_node_count != 0 {
        "all-not-admitted-preserved"
    } else {
        "all-rejected-preserved"
    }
}

fn rejected_node_results(prepared: &node_stage::PreparedSubscriptionNodes) -> Vec<Value> {
    prepared
        .invalid
        .iter()
        .map(|node| rejected_node_result(node, "invalid"))
        .chain(
            prepared
                .not_admitted
                .iter()
                .map(|node| rejected_node_result(node, "not-admitted")),
        )
        .collect()
}

fn rejected_node_result(node: &node_stage::RejectedSubscriptionNode, class: &str) -> Value {
    json!({
        "link": node.link,
        "error": node.reason,
        "classification": class,
        "node": Value::Null,
    })
}

fn ensure_subscription_exists(conn: &Connection, id: i64) -> io::Result<()> {
    conn.query_row(
        "SELECT 1 FROM subscriptions WHERE id = ?1",
        params![id],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(sqlite_io_error)?
    .map(|_| ())
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "subscription not found"))
}
