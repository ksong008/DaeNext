use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use crate::{notify_subscription_scheduler, subscription_write_guard};
use dae_product_persistence::{
    bump_runtime_external_input_version_with_connection, open_state_connection, sqlite_io_error,
};
use rusqlite::{Connection, TransactionBehavior, params};

#[derive(Debug)]
pub enum SubscriptionMutationError {
    Io(io::Error),
    Database(rusqlite::Error),
    TagConflict,
}

impl std::fmt::Display for SubscriptionMutationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Database(error) => error.fmt(formatter),
            Self::TagConflict => formatter.write_str("subscription tag already exists"),
        }
    }
}

impl std::error::Error for SubscriptionMutationError {}

impl From<io::Error> for SubscriptionMutationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct SubscriptionTagConflict;

impl SubscriptionTagConflict {
    pub fn matches(error: &rusqlite::Error) -> bool {
        matches!(
            error,
            rusqlite::Error::SqliteFailure(sqlite_error, _)
                if sqlite_error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        )
    }
}

pub fn subscription_tag_exists(conn: &Connection, tag: Option<&str>) -> io::Result<bool> {
    let Some(tag) = tag else {
        return Ok(false);
    };
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE tag = ?1)",
        params![tag],
        |row| row.get::<_, i64>(0),
    )
    .map(|exists| exists != 0)
    .map_err(sqlite_io_error)
}

pub fn create_subscription_record(
    state: &Path,
    link: &str,
    cron_exp: &str,
    cron_enable: bool,
    status: &str,
    tag: Option<&str>,
    use_proxy: bool,
    updated_at: &str,
) -> Result<i64, SubscriptionMutationError> {
    let _guard = subscription_write_guard()?;
    let conn = open_state_connection(state)?;
    if subscription_tag_exists(&conn, tag)? {
        return Err(SubscriptionMutationError::TagConflict);
    }
    let result = conn.execute(
        "INSERT INTO subscriptions(updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            updated_at,
            link,
            cron_exp,
            cron_enable as i64,
            status,
            "",
            tag,
            use_proxy as i64
        ],
    );
    match result {
        Ok(_) => Ok(conn.last_insert_rowid()),
        Err(error) if SubscriptionTagConflict::matches(&error) => {
            Err(SubscriptionMutationError::TagConflict)
        }
        Err(error) => Err(SubscriptionMutationError::Database(error)),
    }
}

pub fn update_subscription_record(
    state: &Path,
    id: i64,
    link: Option<&str>,
    tag_present: bool,
    tag: Option<&str>,
    cron_exp: Option<&str>,
    cron_enable: Option<bool>,
    use_proxy: Option<bool>,
    updated_at: &str,
) -> Result<bool, SubscriptionMutationError> {
    let _guard = subscription_write_guard()?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(SubscriptionMutationError::Database)?;
    let updated = match tx.execute(
        "UPDATE subscriptions
         SET link = COALESCE(?1, link),
             tag = CASE WHEN ?2 THEN ?3 ELSE tag END,
             cron_exp = COALESCE(?4, cron_exp),
             cron_enable = COALESCE(?5, cron_enable),
             use_proxy = COALESCE(?6, use_proxy),
             updated_at = ?7
         WHERE id = ?8",
        params![
            link,
            tag_present,
            tag,
            cron_exp,
            cron_enable.map(i64::from),
            use_proxy.map(i64::from),
            updated_at,
            id
        ],
    ) {
        Ok(updated) => updated,
        Err(error) if SubscriptionTagConflict::matches(&error) => {
            return Err(SubscriptionMutationError::TagConflict);
        }
        Err(error) => return Err(SubscriptionMutationError::Database(error)),
    };
    tx.commit().map_err(SubscriptionMutationError::Database)?;
    Ok(updated != 0)
}

pub fn delete_subscription(state: &Path, id: i64) -> io::Result<usize> {
    delete_subscriptions_by_ids(state, &[id])
}

pub fn delete_subscriptions_by_ids(state: &Path, ids: &[i64]) -> io::Result<usize> {
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
