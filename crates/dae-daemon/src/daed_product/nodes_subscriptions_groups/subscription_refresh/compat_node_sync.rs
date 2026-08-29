#[cfg(test)]
pub(crate) fn replace_subscription_nodes(
    conn: &rusqlite::Connection,
    subscription_id: i64,
    links: &[String],
) -> std::io::Result<Vec<serde_json::Value>> {
    let prepared = super::node_stage::prepare_subscription_nodes(links);
    dae_product_control::subscription::replace_prepared_subscription_nodes(
        conn,
        subscription_id,
        &prepared.admitted,
    )
    .map(|result| result.items)
}
