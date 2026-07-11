use super::*;
use rusqlite::Transaction;

pub(super) fn update_imported_defaults(
    tx: &Transaction<'_>,
    user: &UserRecord,
    config_id: i64,
    dns_id: i64,
    routing_id: i64,
    group_id: Option<i64>,
) -> io::Result<()> {
    let mut storage =
        serde_json::from_str::<Value>(&user.json_storage).unwrap_or_else(|_| json!({}));
    if !storage.is_object() {
        storage = json!({});
    }
    for (path, id) in [
        ("defaultConfigID", config_id),
        ("defaultDNSID", dns_id),
        ("defaultRoutingID", routing_id),
    ] {
        set_value_at_path(&mut storage, path, Value::String(id.to_string()))
            .map_err(invalid_dae_file)?;
    }
    if let Some(group_id) = group_id {
        set_value_at_path(
            &mut storage,
            "defaultGroupID",
            Value::String(group_id.to_string()),
        )
        .map_err(invalid_dae_file)?;
    }
    let updated = tx
        .execute(
            "UPDATE users SET json_storage = ?1 WHERE id = ?2",
            params![storage.to_string(), user.id],
        )
        .map_err(sqlite_io_error)?;
    if updated != 1 {
        return Err(invalid_dae_file("import user no longer exists"));
    }
    Ok(())
}
