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
pub(crate) use self::source::fetch_subscription_content;

const SUBSCRIPTION_HTTP_HEADER_LIMIT: usize = 128 * 1024;
const SUBSCRIPTION_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
struct SubscriptionSource {
    link: String,
    tag: Option<String>,
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
            "SELECT link, tag FROM subscriptions WHERE id = ?1",
            params![id],
            |row| {
                Ok(SubscriptionSource {
                    link: row.get(0)?,
                    tag: row.get(1)?,
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
    match fetch_subscription_content(config_dir, source.tag.as_deref(), &source.link) {
        Ok(content) => {
            let links = subscription_links_from_content(&content);
            let node_import_result = replace_subscription_nodes(&conn, id, &links)?;
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
            Ok(json!({
                "link": source.link,
                "fetched": true,
                "fetchedAt": fetched_at,
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
                "nodeImportResult": [{
                    "link": source.link,
                    "error": err.to_string(),
                    "node": Value::Null
                }],
            }))
        }
    }
}

fn subscription_http_body_limit() -> usize {
    SUBSCRIPTION_MAX_BYTES
}
