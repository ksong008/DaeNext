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

pub(super) enum SubscriptionCommitResult<T> {
    Applied(T),
    Stale,
}

pub(super) enum PersistedSubscriptionContent<'a> {
    #[cfg(test)]
    Bytes { path: &'a Path, bytes: &'a [u8] },
    #[cfg(not(test))]
    StagedFile { path: &'a Path, staging: &'a Path },
}

#[cfg(test)]
pub(super) fn apply_subscription_refresh_report(
    state: &Path,
    source: &SubscriptionSourceIdentity,
    fetched_at: &str,
    content: &content::SubscriptionContentReport,
    persist: Option<(&Path, &[u8])>,
) -> io::Result<SubscriptionCommitResult<SubscriptionRefreshApplyResult>> {
    let prepared = node_stage::prepare_subscription_refresh(content);
    let persist = persist.map(|(path, bytes)| PersistedSubscriptionContent::Bytes { path, bytes });
    apply_prepared_subscription_refresh_report(state, source, fetched_at, &prepared, persist)
}

pub(super) fn apply_prepared_subscription_refresh_report(
    state: &Path,
    source: &SubscriptionSourceIdentity,
    fetched_at: &str,
    prepared: &node_stage::PreparedSubscriptionRefresh,
    persist: Option<PersistedSubscriptionContent<'_>>,
) -> io::Result<SubscriptionCommitResult<SubscriptionRefreshApplyResult>> {
    let admitted_node_count = prepared.nodes.admitted.len();
    let invalid_node_count = prepared
        .invalid_source_count
        .saturating_add(prepared.nodes.invalid.len());
    let not_admitted_node_count = prepared.nodes.not_admitted.len();
    let mut node_import_result = rejected_node_results(&prepared.nodes);

    let _guard = subscription_write_guard()?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    if !subscription_source_is_current(&tx, source)? {
        return Ok(SubscriptionCommitResult::Stale);
    }
    let mut persisted = persist
        .map(|persist| persistence::PreparedSubscriptionPersist::prepare(source.id, persist))
        .transpose()?;
    if let Some(persisted) = persisted.as_mut() {
        persisted.activate()?;
    }

    let (runtime_input_changed, preserved_existing_nodes, refresh_outcome) =
        if prepared.nodes.admitted.is_empty() {
            (
                false,
                true,
                preserved_refresh_outcome(prepared, invalid_node_count, not_admitted_node_count),
            )
        } else {
            let sync_result = node_sync::replace_prepared_subscription_nodes(
                &tx,
                source.id,
                &prepared.nodes.admitted,
            )?;
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
        prepared.content_kind.as_str(),
        prepared.source_node_count,
        admitted_node_count,
        invalid_node_count,
        not_admitted_node_count,
    );
    tx.execute(
        "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
        params![fetched_at, "fetched", info, source.id],
    )
    .map_err(sqlite_io_error)?;
    if runtime_input_changed {
        bump_runtime_external_input_version_with_connection(&tx)?;
    }
    if let Some(persisted) = persisted.as_ref() {
        persisted.record_generation(&tx)?;
    }
    let commit_result = match persisted.as_mut() {
        Some(persisted) => persisted.commit_database(|| tx.commit().map_err(sqlite_io_error)),
        None => tx.commit().map_err(sqlite_io_error),
    };
    if let Err(error) = commit_result {
        return match persisted {
            Some(persisted) => match persisted.rollback() {
                Ok(()) => Err(error),
                Err(rollback) => Err(io::Error::other(format!(
                    "{error}; persisted subscription rollback failed: {rollback}"
                ))),
            },
            None => Err(error),
        };
    }
    if let Some(persisted) = persisted {
        persisted.finish()?;
    }

    Ok(SubscriptionCommitResult::Applied(
        SubscriptionRefreshApplyResult {
            runtime_input_changed,
            node_import_result,
            refresh_outcome,
            source_kind: prepared.content_kind.as_str(),
            source_node_count: prepared.source_node_count,
            admitted_node_count,
            invalid_node_count,
            not_admitted_node_count,
            preserved_existing_nodes,
        },
    ))
}

pub(super) fn record_subscription_fetch_error(
    state: &Path,
    source: &SubscriptionSourceIdentity,
    fetched_at: &str,
    error: &str,
) -> io::Result<SubscriptionCommitResult<()>> {
    let _guard = subscription_write_guard()?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    if !subscription_source_is_current(&tx, source)? {
        return Ok(SubscriptionCommitResult::Stale);
    }
    tx.execute(
        "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
        params![fetched_at, "fetch_error", error, source.id],
    )
    .map_err(sqlite_io_error)?;
    tx.commit().map_err(sqlite_io_error)?;
    Ok(SubscriptionCommitResult::Applied(()))
}

fn preserved_refresh_outcome(
    prepared: &node_stage::PreparedSubscriptionRefresh,
    invalid_node_count: usize,
    not_admitted_node_count: usize,
) -> &'static str {
    if prepared.empty {
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

fn subscription_source_is_current(
    conn: &Connection,
    expected: &SubscriptionSourceIdentity,
) -> io::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT link, tag, use_proxy FROM subscriptions WHERE id = ?1",
            params![expected.id],
            |row| {
                Ok(SubscriptionSourceIdentity {
                    id: expected.id,
                    link: row.get(0)?,
                    tag: row.get(1)?,
                    use_proxy: row.get::<_, i64>(2)? != 0,
                })
            },
        )
        .optional()
        .map_err(sqlite_io_error)?
        .map(|current| current == *expected)
        .unwrap_or(false))
}
