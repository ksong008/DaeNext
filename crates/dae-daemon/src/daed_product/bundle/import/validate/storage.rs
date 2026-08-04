use super::*;

pub(super) fn prepare_user_storage(body: &Value, user: &UserRecord) -> io::Result<String> {
    let mut storage =
        serde_json::from_str::<Value>(&user.json_storage).unwrap_or_else(|_| json!({}));
    if !storage.is_object() {
        storage = json!({});
    }
    if let Some(mode) = body.get("mode").and_then(Value::as_str) {
        set_value_at_path(&mut storage, "mode", Value::String(mode.to_owned()))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }
    if let Some(defaults) = body.get("defaults").and_then(Value::as_object) {
        for (key, path) in [
            ("configId", "defaultConfigID"),
            ("dnsId", "defaultDNSID"),
            ("routingId", "defaultRoutingID"),
            ("groupId", "defaultGroupID"),
        ] {
            let Some(value) = defaults.get(key) else {
                continue;
            };
            let value = value.as_i64().map(|id| id.to_string()).unwrap_or_default();
            set_value_at_path(&mut storage, path, Value::String(value))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        }
    }
    if let Some(group_sort_state) = body.get("groupSortState") {
        if group_sort_state.is_null() {
            delete_value_at_path(&mut storage, "groupSortStateV1")
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        } else {
            set_value_at_path(
                &mut storage,
                "groupSortStateV1",
                Value::String(group_sort_state.to_string()),
            )
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        }
    }
    Ok(storage.to_string())
}
