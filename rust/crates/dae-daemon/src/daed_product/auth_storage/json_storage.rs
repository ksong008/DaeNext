use super::*;
pub(crate) fn query_json_storage(storage: &str, paths: &[String]) -> Vec<String> {
    if paths.is_empty() {
        return vec![storage.to_owned()];
    }
    let root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    paths
        .iter()
        .map(|path| {
            value_at_path(&root, path)
                .map(value_to_storage_string)
                .unwrap_or_default()
        })
        .collect()
}

pub(crate) fn set_json_storage(
    storage: &mut String,
    paths: &[String],
    values: &[String],
) -> Result<i32, String> {
    let mut root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    if !root.is_object() {
        root = json!({});
    }
    for (path, value) in paths.iter().zip(values.iter()) {
        set_value_at_path(&mut root, path, Value::String(value.clone()))?;
    }
    *storage = root.to_string();
    Ok(paths.len() as i32)
}

pub(crate) fn remove_json_storage(storage: &mut String, paths: &[String]) -> Result<i32, String> {
    if paths.is_empty() {
        *storage = "{}".to_owned();
        return Ok(1);
    }
    let mut root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    for path in paths {
        delete_value_at_path(&mut root, path)?;
    }
    *storage = root.to_string();
    Ok(paths.len() as i32)
}

pub(crate) fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        current = current.get(segment)?;
    }
    Some(current)
}

pub(crate) fn set_value_at_path(root: &mut Value, path: &str, value: Value) -> Result<(), String> {
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err("storage path must not be empty".to_owned());
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        if !current.is_object() {
            *current = json!({});
        }
        let object = current.as_object_mut().unwrap();
        current = object
            .entry((*segment).to_owned())
            .or_insert_with(|| json!({}));
    }
    if !current.is_object() {
        *current = json!({});
    }
    current
        .as_object_mut()
        .unwrap()
        .insert(segments[segments.len() - 1].to_owned(), value);
    Ok(())
}

pub(crate) fn delete_value_at_path(root: &mut Value, path: &str) -> Result<(), String> {
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err("storage path must not be empty".to_owned());
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        let Some(next) = current.get_mut(*segment) else {
            return Ok(());
        };
        current = next;
    }
    if let Some(object) = current.as_object_mut() {
        object.remove(segments[segments.len() - 1]);
    }
    Ok(())
}

pub(crate) fn value_to_storage_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

pub(crate) fn save_json_storage(state: &Path, user_id: i64, storage: &str) -> io::Result<()> {
    let conn = open_state_connection(state)?;
    conn.execute(
        "UPDATE users SET json_storage = ?1 WHERE id = ?2",
        params![storage, user_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}
