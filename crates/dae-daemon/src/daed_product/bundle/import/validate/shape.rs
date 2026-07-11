use super::*;

mod references;

pub(super) fn validate_bundle_shape(body: &Value) -> io::Result<()> {
    let root = required_object(body, "bundle")?;
    if let Some(version) = root.get("schemaVersion")
        && version.as_i64() != Some(1)
    {
        return invalid("bundle schemaVersion must be 1");
    }
    if let Some(mode) = root.get("mode") {
        require_string(mode, "bundle mode")?;
    }

    let configs = validate_resource_array(root, "configs", &["name", "global"])?;
    let dnss = validate_resource_array(root, "dnss", &["name", "dns"])?;
    let routings = validate_resource_array(root, "routings", &["name", "routing"])?;
    let subscriptions = validate_resource_array(
        root,
        "subscriptions",
        &["link", "cronExp", "status", "info"],
    )?;
    let nodes = validate_resource_array(root, "nodes", &["link", "name", "address", "protocol"])?;
    let groups = validate_resource_array(root, "groups", &["name", "policy"])?;

    let config_ids = item_ids(configs, "configs")?;
    let dns_ids = item_ids(dnss, "dnss")?;
    let routing_ids = item_ids(routings, "routings")?;
    let subscription_ids = item_ids(subscriptions, "subscriptions")?;
    let node_ids = item_ids(nodes, "nodes")?;
    let _group_ids = item_ids(groups, "groups")?;

    let selected = required_object(
        root.get("selected")
            .ok_or_else(|| invalid_error("bundle selected resources are required"))?,
        "bundle selected",
    )?;
    validate_selected_id(selected, "configId", &config_ids)?;
    validate_selected_id(selected, "dnsId", &dns_ids)?;
    validate_selected_id(selected, "routingId", &routing_ids)?;

    validate_optional_defaults(root.get("defaults"))?;
    references::validate_subscription_fields(subscriptions)?;
    references::validate_node_references(nodes, &subscription_ids)?;
    references::validate_group_references(groups, &node_ids, &subscription_ids)?;
    Ok(())
}

fn validate_resource_array<'a>(
    root: &'a Map<String, Value>,
    key: &str,
    string_fields: &[&str],
) -> io::Result<&'a Vec<Value>> {
    let items = root
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_error(&format!("bundle {key} must be an array")))?;
    for (index, item) in items.iter().enumerate() {
        let object = required_object(item, &format!("bundle {key}[{index}]"))?;
        let id = object
            .get("id")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid_error(&format!("bundle {key}[{index}].id is required")))?;
        if id <= 0 {
            return invalid(&format!("bundle {key}[{index}].id must be positive"));
        }
        for field in string_fields {
            let value = object.get(*field).ok_or_else(|| {
                invalid_error(&format!("bundle {key}[{index}].{field} is required"))
            })?;
            require_string(value, &format!("bundle {key}[{index}].{field}"))?;
        }
    }
    Ok(items)
}

fn item_ids(items: &[Value], scope: &str) -> io::Result<HashSet<i64>> {
    let mut ids = HashSet::new();
    for item in items {
        let id = item["id"].as_i64().expect("validated bundle id");
        if !ids.insert(id) {
            return invalid(&format!("bundle {scope} contains duplicate id {id}"));
        }
    }
    Ok(ids)
}

fn validate_selected_id(
    selected: &Map<String, Value>,
    key: &str,
    existing: &HashSet<i64>,
) -> io::Result<()> {
    let id = selected
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid_error(&format!("bundle selected.{key} is required")))?;
    if existing.contains(&id) {
        Ok(())
    } else {
        invalid(&format!("bundle selected.{key} references missing id {id}"))
    }
}

fn validate_optional_defaults(defaults: Option<&Value>) -> io::Result<()> {
    let Some(defaults) = defaults else {
        return Ok(());
    };
    let defaults = required_object(defaults, "bundle defaults")?;
    for key in ["configId", "dnsId", "routingId", "groupId"] {
        if let Some(value) = defaults.get(key)
            && !value.is_null()
            && value.as_i64().is_none()
        {
            return invalid(&format!("bundle defaults.{key} must be an integer or null"));
        }
    }
    Ok(())
}

pub(super) fn required_object<'a>(
    value: &'a Value,
    scope: &str,
) -> io::Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_error(&format!("{scope} must be an object")))
}

pub(super) fn require_string(value: &Value, scope: &str) -> io::Result<()> {
    if value.as_str().is_some() {
        Ok(())
    } else {
        invalid(&format!("{scope} must be a string"))
    }
}

pub(super) fn invalid<T>(message: &str) -> io::Result<T> {
    Err(invalid_error(message))
}

pub(super) fn invalid_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
