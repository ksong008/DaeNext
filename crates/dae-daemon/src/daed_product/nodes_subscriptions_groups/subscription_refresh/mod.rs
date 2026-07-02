use super::*;

mod content;
mod http;
mod node_sync;
mod source;

pub(crate) use self::content::subscription_links_from_content;
#[cfg(test)]
pub(crate) use self::http::{
    decode_chunked_body, decode_chunked_body_with_limit, http_response_body_with_limit,
    read_subscription_http_response_with_limit,
};
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
    let conn = open_state_connection(state)?;
    let Some(source) = conn
        .query_row(
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
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "subscription not found",
        ));
    };
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
            let before_nodes = subscription_runtime_node_fingerprint(&conn, id)?;
            let node_import_result = replace_subscription_nodes(&conn, id, &links)?;
            let after_nodes = subscription_runtime_node_fingerprint(&conn, id)?;
            let runtime_input_changed = before_nodes != after_nodes;
            conn.execute(
                "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
                params![
                    fetched_at,
                    "fetched",
                    format!("{} node links fetched by Rust daed", links.len()),
                    id
                ],
            )
            .map_err(sqlite_io_error)?;
            drop(conn);
            if runtime_input_changed {
                bump_runtime_external_input_version(state)?;
            }
            Ok(json!({
                "link": source.link,
                "fetched": true,
                "fetchedAt": fetched_at,
                "runtimeInputChanged": runtime_input_changed,
                "nodeImportResult": node_import_result,
            }))
        }
        Err(err) => {
            conn.execute(
                "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
                params![fetched_at, "fetch_error", err.to_string(), id],
            )
            .map_err(sqlite_io_error)?;
            Ok(json!({
                "link": source.link,
                "fetched": false,
                "fetchedAt": fetched_at,
                "runtimeInputChanged": false,
                "nodeImportResult": [{
                    "link": source.link,
                    "error": err.to_string(),
                    "node": Value::Null
                }],
            }))
        }
    }
}

fn subscription_runtime_node_fingerprint(
    conn: &Connection,
    subscription_id: i64,
) -> io::Result<Vec<(String, String, String, String)>> {
    let mut stmt = conn
        .prepare(
            "SELECT link, name, address, protocol
             FROM nodes
             WHERE subscription_id = ?1
             ORDER BY name, link, address, protocol",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

fn subscription_http_body_limit() -> usize {
    SUBSCRIPTION_MAX_BYTES
}

fn subscription_link_uses_http_transport(link: &str) -> bool {
    url::Url::parse(link)
        .map(|url| matches!(url.scheme(), "http" | "https" | "http-file" | "https-file"))
        .unwrap_or(false)
}
