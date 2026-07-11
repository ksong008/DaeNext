use super::*;

pub(super) fn validate_subscription_fields(items: &[Value]) -> io::Result<()> {
    for (index, item) in items.iter().enumerate() {
        for key in ["cronEnable", "useProxy"] {
            if let Some(value) = item.get(key)
                && value.as_bool().is_none()
            {
                return invalid(&format!(
                    "bundle subscriptions[{index}].{key} must be boolean"
                ));
            }
        }
        if let Some(tag) = item.get("tag")
            && !tag.is_null()
        {
            require_string(tag, &format!("bundle subscriptions[{index}].tag"))?;
        }
    }
    Ok(())
}

pub(super) fn validate_node_references(
    items: &[Value],
    subscription_ids: &HashSet<i64>,
) -> io::Result<()> {
    for (index, item) in items.iter().enumerate() {
        if let Some(subscription_id) = item.get("subscriptionId")
            && !subscription_id.is_null()
        {
            let subscription_id = subscription_id.as_i64().ok_or_else(|| {
                invalid_error(&format!(
                    "bundle nodes[{index}].subscriptionId must be an integer or null"
                ))
            })?;
            if !subscription_ids.contains(&subscription_id) {
                return invalid(&format!(
                    "bundle nodes[{index}].subscriptionId references missing id {subscription_id}"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_group_references(
    groups: &[Value],
    node_ids: &HashSet<i64>,
    subscription_ids: &HashSet<i64>,
) -> io::Result<()> {
    for (group_index, group) in groups.iter().enumerate() {
        validate_group_node_ids(group_index, group, node_ids)?;
        validate_policy_params(group_index, group.get("policyParams"))?;
        validate_subscription_bindings(
            group_index,
            group.get("subscriptionBindings"),
            subscription_ids,
        )?;
    }
    Ok(())
}

fn validate_group_node_ids(
    group_index: usize,
    group: &Value,
    node_ids: &HashSet<i64>,
) -> io::Result<()> {
    let values = group
        .get("nodeIds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_error(&format!(
                "bundle groups[{group_index}].nodeIds must be an array"
            ))
        })?;
    let mut seen = HashSet::new();
    for value in values {
        let id = value.as_i64().ok_or_else(|| {
            invalid_error(&format!(
                "bundle groups[{group_index}].nodeIds must contain integers"
            ))
        })?;
        if !node_ids.contains(&id) {
            return invalid(&format!(
                "bundle groups[{group_index}].nodeIds references missing id {id}"
            ));
        }
        if !seen.insert(id) {
            return invalid(&format!(
                "bundle groups[{group_index}].nodeIds contains duplicate id {id}"
            ));
        }
    }
    Ok(())
}

fn validate_policy_params(group_index: usize, value: Option<&Value>) -> io::Result<()> {
    let values = value.and_then(Value::as_array).ok_or_else(|| {
        invalid_error(&format!(
            "bundle groups[{group_index}].policyParams must be an array"
        ))
    })?;
    for (index, item) in values.iter().enumerate() {
        let object = required_object(
            item,
            &format!("bundle groups[{group_index}].policyParams[{index}]"),
        )?;
        require_string(
            object.get("key").ok_or_else(|| {
                invalid_error(&format!(
                    "bundle groups[{group_index}].policyParams[{index}].key is required"
                ))
            })?,
            "bundle group policy parameter key",
        )?;
        let value = object
            .get("val")
            .or_else(|| object.get("value"))
            .ok_or_else(|| {
                invalid_error(&format!(
                    "bundle groups[{group_index}].policyParams[{index}].val is required"
                ))
            })?;
        require_string(value, "bundle group policy parameter value")?;
    }
    Ok(())
}

fn validate_subscription_bindings(
    group_index: usize,
    value: Option<&Value>,
    subscription_ids: &HashSet<i64>,
) -> io::Result<()> {
    let bindings = value.and_then(Value::as_array).ok_or_else(|| {
        invalid_error(&format!(
            "bundle groups[{group_index}].subscriptionBindings must be an array"
        ))
    })?;
    let mut seen = HashSet::new();
    for (index, binding) in bindings.iter().enumerate() {
        let object = required_object(
            binding,
            &format!("bundle groups[{group_index}].subscriptionBindings[{index}]"),
        )?;
        let id = object
            .get("subscriptionId")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                invalid_error(&format!(
                    "bundle groups[{group_index}].subscriptionBindings[{index}].subscriptionId is required"
                ))
            })?;
        if !subscription_ids.contains(&id) {
            return invalid(&format!(
                "bundle groups[{group_index}].subscriptionBindings references missing id {id}"
            ));
        }
        if !seen.insert(id) {
            return invalid(&format!(
                "bundle groups[{group_index}].subscriptionBindings contains duplicate id {id}"
            ));
        }
        if let Some(regex) = object.get("nameFilterRegex")
            && !regex.is_null()
        {
            require_string(regex, "bundle group subscription nameFilterRegex")?;
        }
    }
    Ok(())
}
