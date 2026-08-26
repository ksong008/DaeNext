use super::*;

mod content {
    #[cfg(test)]
    pub(crate) use dae_product_subscription::subscription_links_from_content;
    pub(in crate::daed_product) use dae_product_subscription::{
        SubscriptionContentReport, parse_subscription_content,
    };
}
#[cfg(not(test))]
use dae_product_subscription::PersistedSubscriptionContent;
use dae_product_subscription::{SubscriptionSourceIdentity, fetch_error};
mod helper;
mod http;
mod node_stage;
mod node_sync;
mod outcome {
    pub(in crate::daed_product) use dae_product_subscription::SubscriptionRefreshOutcome;
}
mod source;
mod transaction;

pub(super) use outcome::SubscriptionRefreshOutcome;

#[cfg(test)]
pub(crate) use self::content::subscription_links_from_content;
#[cfg(test)]
pub(crate) use self::http::{
    decode_chunked_body, decode_chunked_body_with_limit, http_response_body_with_limit,
    read_subscription_http_response_with_limit, subscription_http_request,
    subscription_tls_alpn_protocols,
};
#[cfg(test)]
pub(crate) use self::node_sync::replace_subscription_nodes;
#[cfg(test)]
pub(crate) use self::source::fetch_subscription_content;

const SUBSCRIPTION_MAX_BYTES: usize = dae_product_subscription::SUBSCRIPTION_MAX_BYTES;

pub(in crate::daed_product) use dae_product_subscription::recover_subscription_persist_transaction;
pub(in crate::daed_product) use helper::run_subscription_prepare_helper_command;

pub(crate) fn refresh_subscription_from_remote(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    config_dir: &Path,
    id: i64,
) -> io::Result<Value> {
    #[cfg(not(test))]
    let _ = control_runtime;
    let result = {
        let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
        #[cfg(not(test))]
        let result = refresh_subscription_from_remote_inner(state, config_dir, id);
        #[cfg(test)]
        let result =
            refresh_subscription_from_remote_inline(control_runtime, state, config_dir, id);
        result
    };
    allocator_request_reclaim(AllocatorReclaimReason::SubscriptionRefresh);
    result
}

#[cfg(test)]
fn refresh_subscription_from_remote_inline(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    config_dir: &Path,
    id: i64,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let source = subscription_source_by_id(state, id)?;
    let fetched_at = now_text();
    let proxy_config = if source.use_proxy && subscription_link_uses_http_transport(&source.link) {
        Some(product_default_proxy_config(state)?)
    } else {
        None
    };
    match source::fetch_subscription_content_with_proxy_config(
        control_runtime,
        config_dir,
        source.tag.as_deref(),
        &source.link,
        proxy_config.as_ref(),
    ) {
        Ok(fetched) => {
            let content = content::parse_subscription_content(&fetched.content);
            let persist = fetched
                .persist_path
                .as_deref()
                .map(|path| (path, fetched.content.as_bytes()));
            match transaction::apply_subscription_refresh_report(
                state,
                &source,
                &fetched_at,
                &content,
                persist,
            )? {
                transaction::SubscriptionCommitResult::Applied(applied) => Ok(json!({
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
                    "preparationMode": "inline-test",
                })),
                transaction::SubscriptionCommitResult::Stale => {
                    Ok(stale_subscription_refresh_report(&source, &fetched_at))
                }
            }
        }
        Err(error) => record_subscription_fetch_failure(
            state,
            &source,
            &fetched_at,
            fetch_error::SubscriptionFetchFailure::from_io_error(&error),
        ),
    }
}

#[cfg(not(test))]
fn refresh_subscription_from_remote_inner(
    state: &Path,
    config_dir: &Path,
    id: i64,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let source = subscription_source_by_id(state, id)?;
    let fetched_at = now_text();
    match helper::prepare_subscription_with_helper(state, config_dir, &source) {
        Ok(helper::SubscriptionHelperOutcome::Prepared(prepared)) => {
            let persist_path = if prepared.persist_staging.is_some() {
                Some(source::persist_subscription_path(
                    config_dir,
                    source.tag.as_deref(),
                )?)
            } else {
                None
            };
            let persist = persist_path
                .as_deref()
                .zip(prepared.persist_staging.as_deref())
                .map(|(path, staging)| PersistedSubscriptionContent::StagedFile { path, staging });
            match transaction::apply_prepared_subscription_refresh_report(
                state,
                &source,
                &fetched_at,
                &prepared.prepared,
                persist,
            )? {
                transaction::SubscriptionCommitResult::Applied(applied) => Ok(json!({
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
                    "preparationMode": "isolated-process",
                })),
                transaction::SubscriptionCommitResult::Stale => {
                    Ok(stale_subscription_refresh_report(&source, &fetched_at))
                }
            }
        }
        Ok(helper::SubscriptionHelperOutcome::FetchFailed(failure)) => {
            record_subscription_fetch_failure(state, &source, &fetched_at, failure)
        }
        Err(error) => {
            let failure = fetch_error::SubscriptionFetchFailure::from_io_error(&error);
            record_subscription_fetch_failure(state, &source, &fetched_at, failure)
        }
    }
}

fn record_subscription_fetch_failure(
    state: &Path,
    source: &SubscriptionSourceIdentity,
    fetched_at: &str,
    failure: fetch_error::SubscriptionFetchFailure,
) -> io::Result<Value> {
    match transaction::record_subscription_fetch_error(
        state,
        source,
        fetched_at,
        failure.message(),
    )? {
        transaction::SubscriptionCommitResult::Applied(()) => Ok(json!({
            "link": source.link,
            "fetched": false,
            "fetchError": failure.response_value(),
            "fetchedAt": fetched_at,
            "refreshOutcome": "fetch-failed-preserved",
            "preservedExistingNodes": true,
            "runtimeInputChanged": false,
            "nodeImportResult": [],
            "preparationMode": "isolated-process",
        })),
        transaction::SubscriptionCommitResult::Stale => {
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

fn subscription_source_by_id(state: &Path, id: i64) -> io::Result<SubscriptionSourceIdentity> {
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

#[cfg(test)]
pub(in crate::daed_product) fn apply_subscription_refresh_result(
    state: &Path,
    id: i64,
    fetched_at: &str,
    links: &[String],
) -> io::Result<(bool, Vec<Value>)> {
    let content = content::SubscriptionContentReport::from_links(links);
    let source = subscription_source_by_id(state, id)?;
    match transaction::apply_subscription_refresh_report(
        state, &source, fetched_at, &content, None,
    )? {
        transaction::SubscriptionCommitResult::Applied(applied) => {
            Ok((applied.runtime_input_changed, applied.node_import_result))
        }
        transaction::SubscriptionCommitResult::Stale => Ok((false, Vec::new())),
    }
}

fn subscription_http_body_limit() -> usize {
    SUBSCRIPTION_MAX_BYTES
}

fn subscription_link_uses_http_transport(link: &str) -> bool {
    url::Url::parse(link)
        .map(|url| matches!(url.scheme(), "http" | "https" | "http-file" | "https-file"))
        .unwrap_or(false)
}
