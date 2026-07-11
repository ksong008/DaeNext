use super::*;

mod content;
mod http;
mod node_stage;
mod node_sync;
mod source;

pub(crate) use self::content::subscription_links_from_content;
#[cfg(test)]
pub(crate) use self::http::{
    decode_chunked_body, decode_chunked_body_with_limit, http_response_body_with_limit,
    read_subscription_http_response_with_limit, subscription_http_request,
};
#[cfg(test)]
pub(crate) use self::node_sync::replace_subscription_nodes;
#[cfg(test)]
pub(crate) use self::source::fetch_subscription_content;
use self::source::fetch_subscription_content_with_proxy_config;

const SUBSCRIPTION_HTTP_HEADER_LIMIT: usize = 128 * 1024;
const SUBSCRIPTION_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
struct SubscriptionSource {
    link: String,
    tag: Option<String>,
    use_proxy: bool,
}

pub(crate) fn refresh_subscription_from_remote(
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
    match fetch_subscription_content_with_proxy_config(
        config_dir,
        source.tag.as_deref(),
        &source.link,
        proxy_config.as_ref(),
    ) {
        Ok(content) => {
            let links = subscription_links_from_content(&content);
            let (runtime_input_changed, node_import_result) =
                apply_subscription_refresh_result(state, id, &fetched_at, &links)?;
            Ok(json!({
                "link": source.link,
                "fetched": true,
                "fetchedAt": fetched_at,
                "runtimeInputChanged": runtime_input_changed,
                "nodeImportResult": node_import_result,
            }))
        }
        Err(err) => {
            let error = err.to_string();
            record_subscription_fetch_error(state, id, &fetched_at, &error)?;
            Ok(json!({
                "link": source.link,
                "fetched": false,
                "fetchedAt": fetched_at,
                "runtimeInputChanged": false,
                "nodeImportResult": [{
                    "link": source.link,
                    "error": error,
                    "node": Value::Null
                }],
            }))
        }
    }
}

fn subscription_source_by_id(state: &Path, id: i64) -> io::Result<SubscriptionSource> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT link, tag, use_proxy FROM subscriptions WHERE id = ?1",
        params![id],
        |row| {
            Ok(SubscriptionSource {
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

pub(in crate::daed_product) fn apply_subscription_refresh_result(
    state: &Path,
    id: i64,
    fetched_at: &str,
    links: &[String],
) -> io::Result<(bool, Vec<Value>)> {
    let prepared_nodes = node_stage::prepare_subscription_nodes(links);
    let _guard = subscription_write_guard()?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    ensure_subscription_exists(&tx, id)?;
    let sync_result = node_sync::replace_prepared_subscription_nodes(&tx, id, &prepared_nodes)?;
    let runtime_input_changed = sync_result.runtime_input_changed;
    let node_import_result = sync_result.items;
    tx.execute(
        "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
        params![
            fetched_at,
            "fetched",
            format!("{} node links fetched by Rust daed", links.len()),
            id
        ],
    )
    .map_err(sqlite_io_error)?;
    if runtime_input_changed {
        bump_runtime_external_input_version_with_connection(&tx)?;
    }
    tx.commit().map_err(sqlite_io_error)?;
    Ok((runtime_input_changed, node_import_result))
}

fn record_subscription_fetch_error(
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
    tx.commit().map_err(sqlite_io_error)?;
    Ok(())
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

fn subscription_http_body_limit() -> usize {
    SUBSCRIPTION_MAX_BYTES
}

fn subscription_link_uses_http_transport(link: &str) -> bool {
    url::Url::parse(link)
        .map(|url| matches!(url.scheme(), "http" | "https" | "http-file" | "https-file"))
        .unwrap_or(false)
}
