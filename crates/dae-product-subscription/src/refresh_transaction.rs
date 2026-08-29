use std::io;
use std::path::{Path, PathBuf};

use dae_product_persistence::{
    bump_runtime_external_input_version_with_connection, ensure_state_schema,
    open_state_connection, sqlite_io_error,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};

use crate::{
    PersistedSubscriptionContent, PreparedSubscriptionNodes, PreparedSubscriptionPersist,
    PreparedSubscriptionRefresh, RejectedSubscriptionNode, SubscriptionSourceIdentity,
    replace_prepared_subscription_nodes, subscription_write_guard,
};

pub struct SubscriptionRefreshPersist {
    pub path: PathBuf,
    pub content: SubscriptionRefreshPersistContent,
}

pub enum SubscriptionRefreshPersistContent {
    Bytes(Vec<u8>),
    StagedFile(PathBuf),
}

impl SubscriptionRefreshPersist {
    fn as_persisted(&self) -> PersistedSubscriptionContent<'_> {
        match &self.content {
            SubscriptionRefreshPersistContent::Bytes(bytes) => {
                PersistedSubscriptionContent::Bytes {
                    path: &self.path,
                    bytes,
                }
            }
            SubscriptionRefreshPersistContent::StagedFile(staging) => {
                PersistedSubscriptionContent::StagedFile {
                    path: &self.path,
                    staging,
                }
            }
        }
    }
}

pub enum SubscriptionRefreshFetch {
    Prepared {
        prepared: PreparedSubscriptionRefresh,
        persist: Option<SubscriptionRefreshPersist>,
    },
    FetchFailed(crate::fetch_error::SubscriptionFetchFailure),
}

pub trait SubscriptionRefreshCallbacks {
    fn fetch_subscription(
        &self,
        state: &Path,
        config_dir: &Path,
        source: &SubscriptionSourceIdentity,
    ) -> io::Result<SubscriptionRefreshFetch>;
}

pub fn refresh_subscription_from_remote_with_callbacks<C: SubscriptionRefreshCallbacks>(
    callbacks: &C,
    state: &Path,
    config_dir: &Path,
    id: i64,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let source = subscription_source_by_id(state, id)?;
    let fetched_at = dae_product_core::product_now_text();
    let result = callbacks.fetch_subscription(state, config_dir, &source);
    let fetched = match result {
        Ok(fetched) => fetched,
        Err(error) => {
            return record_subscription_fetch_failure(
                state,
                &source,
                &fetched_at,
                crate::fetch_error::SubscriptionFetchFailure::from_io_error(&error),
            );
        }
    };
    match fetched {
        SubscriptionRefreshFetch::FetchFailed(failure) => {
            record_subscription_fetch_failure(state, &source, &fetched_at, failure)
        }
        SubscriptionRefreshFetch::Prepared { prepared, persist } => {
            match apply_prepared_subscription_refresh_report(
                state,
                &source,
                &fetched_at,
                &prepared,
                persist
                    .as_ref()
                    .map(SubscriptionRefreshPersist::as_persisted),
            )? {
                SubscriptionCommitResult::Applied(applied) => Ok(json!({
                    "link": source.link,
                    "fetched": true,
                    "fetchError": Value::Null,
                    "fetchedAt": fetched_at,
                    "refreshOutcome": applied.refresh_outcome,
                    "sourceKind": applied.source_kind,
                    "sourceNodeCount": applied.source_node_count,
                    "admittedNodeCount": applied.admitted_node_count,
                    "invalidNodeCount": applied.invalid_node_count,
                    "notAdmittedNodeCount": applied.not_admitted_node_count,
                    "preservedExistingNodes": applied.preserved_existing_nodes,
                    "runtimeInputChanged": applied.runtime_input_changed,
                    "nodeImportResult": applied.node_import_result,
                })),
                SubscriptionCommitResult::Stale => {
                    Ok(stale_subscription_refresh_report(&source, &fetched_at))
                }
            }
        }
    }
}

pub fn subscription_source_by_id(state: &Path, id: i64) -> io::Result<SubscriptionSourceIdentity> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT link, tag, use_proxy FROM subscriptions WHERE id = ?1",
        params![id],
        |row| {
            Ok(SubscriptionSourceIdentity {
                id,
                link: row.get(0)?,
                tag: row.get(1)?,
                use_proxy: row.get::<_, i64>(2)? != 0,
            })
        },
    )
    .optional()
    .map_err(sqlite_io_error)?
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "subscription not found"))
}

fn record_subscription_fetch_failure(
    state: &Path,
    source: &SubscriptionSourceIdentity,
    fetched_at: &str,
    failure: crate::fetch_error::SubscriptionFetchFailure,
) -> io::Result<Value> {
    match record_subscription_fetch_error(state, source, fetched_at, failure.message())? {
        SubscriptionCommitResult::Applied(()) => Ok(json!({
            "link": source.link,
            "fetched": false,
            "fetchError": failure.response_value(),
            "fetchedAt": fetched_at,
            "refreshOutcome": "fetch-failed-preserved",
            "preservedExistingNodes": true,
            "runtimeInputChanged": false,
            "nodeImportResult": [],
        })),
        SubscriptionCommitResult::Stale => {
            Ok(stale_subscription_refresh_report(source, fetched_at))
        }
    }
}

fn stale_subscription_refresh_report(
    source: &SubscriptionSourceIdentity,
    fetched_at: &str,
) -> Value {
    json!({
        "link": source.link,
        "fetched": false,
        "fetchError": Value::Null,
        "fetchedAt": fetched_at,
        "refreshOutcome": "stale-source-discarded",
        "preservedExistingNodes": true,
        "runtimeInputChanged": false,
        "nodeImportResult": [],
    })
}

pub struct SubscriptionRefreshApplyResult {
    pub runtime_input_changed: bool,
    pub node_import_result: Vec<Value>,
    pub refresh_outcome: &'static str,
    pub source_kind: &'static str,
    pub source_node_count: usize,
    pub admitted_node_count: usize,
    pub invalid_node_count: usize,
    pub not_admitted_node_count: usize,
    pub preserved_existing_nodes: bool,
}

pub enum SubscriptionCommitResult<T> {
    Applied(T),
    Stale,
}
pub fn apply_prepared_subscription_refresh_report(
    state: &Path,
    source: &SubscriptionSourceIdentity,
    fetched_at: &str,
    prepared: &PreparedSubscriptionRefresh,
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
        .map(|persist| PreparedSubscriptionPersist::prepare(source.id, persist))
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
            let sync_result =
                replace_prepared_subscription_nodes(&tx, source.id, &prepared.nodes.admitted)?;
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

pub fn record_subscription_fetch_error(
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
    prepared: &PreparedSubscriptionRefresh,
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

fn rejected_node_results(prepared: &PreparedSubscriptionNodes) -> Vec<Value> {
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

fn rejected_node_result(node: &RejectedSubscriptionNode, class: &str) -> Value {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PreparedSubscriptionNodes, SubscriptionContentKind};
    use dae_product_persistence::{ensure_state_schema, open_state_connection};
    use rusqlite::params;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct PreparedCallback {
        calls: AtomicUsize,
    }

    impl SubscriptionRefreshCallbacks for PreparedCallback {
        fn fetch_subscription(
            &self,
            _state: &Path,
            _config_dir: &Path,
            _source: &SubscriptionSourceIdentity,
        ) -> io::Result<SubscriptionRefreshFetch> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(SubscriptionRefreshFetch::Prepared {
                prepared: PreparedSubscriptionRefresh {
                    content_kind: SubscriptionContentKind::PlainText,
                    source_node_count: 0,
                    invalid_source_count: 0,
                    empty: true,
                    nodes: PreparedSubscriptionNodes::default(),
                    persist_content: false,
                },
                persist: None,
            })
        }
    }

    #[test]
    fn refresh_callback_owns_fetch_and_product_owns_commit() {
        let directory = std::env::temp_dir().join(format!(
            "dae-product-subscription-refresh-{}",
            fastrand::u64(..)
        ));
        let state = directory.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let connection = open_state_connection(&state).unwrap();
        connection
            .execute(
                "INSERT INTO subscriptions(link, tag, use_proxy) VALUES(?1, ?2, 0)",
                params!["file://source", "source"],
            )
            .unwrap();
        let id = connection.last_insert_rowid();
        drop(connection);

        let callbacks = PreparedCallback {
            calls: AtomicUsize::new(0),
        };
        let report =
            refresh_subscription_from_remote_with_callbacks(&callbacks, &state, &directory, id)
                .unwrap();

        assert_eq!(callbacks.calls.load(Ordering::Relaxed), 1);
        assert_eq!(report["fetched"], true);
        let connection = open_state_connection(&state).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM subscriptions WHERE id = ?1",
                    params![id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "fetched"
        );
        drop(connection);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
