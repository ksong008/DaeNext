use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use dae_product_core::{DEFAULT_PRODUCT_GROUP_NAME, DEFAULT_PRODUCT_GROUP_POLICY};
use dae_product_http::{HttpRequest, HttpResponse, integer_array, json_body};
use dae_product_persistence::{
    open_state_connection, running_group_references_id, sqlite_io_error,
};
use dae_product_runtime::parse_boolish;
use dae_product_subscription::*;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};

pub fn list_groups(
    state: &Path,
    request: &HttpRequest,
    runtime_selectors: Option<&BTreeMap<String, Value>>,
) -> HttpResponse {
    let result = if request_summary_enabled(request) {
        list_group_summaries_value_with_runtime_selection(
            state,
            runtime_selectors.unwrap_or(&BTreeMap::new()),
        )
    } else {
        list_groups_value(state)
    };
    match result {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub fn list_group_summaries_value_with_runtime_selection(
    state: &Path,
    runtime_selectors: &BTreeMap<String, Value>,
) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    dae_product_subscription::list_group_summaries_batched(&conn, runtime_selectors)
}

fn request_summary_enabled(request: &HttpRequest) -> bool {
    request
        .query
        .get("summary")
        .and_then(|values| values.first())
        .and_then(|value| parse_boolish(value))
        .unwrap_or(false)
}

pub fn create_group(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_GROUP_NAME);
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_GROUP_POLICY);
    let policy = match validate_group_policy(policy) {
        Ok(policy) => policy,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let node_ids = integer_array(&body, "nodeIds");
    let subscription_ids = integer_array(&body, "subscriptionIds");
    let mut conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = tx.execute(
        "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
        params![name, policy],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = tx.last_insert_rowid();
    if let Err(err) = replace_group_policy_params(&tx, id, body.get("policyParams")) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_node_ids(&tx, id, &node_ids, true) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_subscription_ids(&tx, id, &subscription_ids, None, true) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = tx.commit() {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    get_group(state, id).with_status(201)
}

pub fn get_group(state: &Path, id: i64) -> HttpResponse {
    match get_group_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "group not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub fn update_group(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let policy = match body.get("policy").and_then(Value::as_str) {
        Some(policy) => match validate_group_policy(policy) {
            Ok(policy) => Some(policy),
            Err(err) => return HttpResponse::json(400, json!({"error": err})),
        },
        None => None,
    };
    let mut conn = conn;
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(name) = body.get("name").and_then(Value::as_str)
        && let Err(err) = tx.execute(
            "UPDATE groups SET name = ?1, version = version + 1 WHERE id = ?2",
            params![name, id],
        )
    {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Some(policy) = policy {
        if group_policy_is_fixed(policy) {
            let tags = match fixed_group_runtime_node_tags(&tx, id) {
                Ok(tags) => tags,
                Err(err) => return HttpResponse::json(400, json!({"error": err.to_string()})),
            };
            if let Err(err) = validate_fixed_group_runtime_node_tags(&tags) {
                return HttpResponse::json(400, json!({"error": err.to_string()}));
            }
        }
        if let Err(err) = tx.execute(
            "UPDATE groups SET policy = ?1, version = version + 1 WHERE id = ?2",
            params![policy, id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if body.get("policyParams").is_some()
        && let Err(err) = replace_group_policy_params(&tx, id, body.get("policyParams"))
    {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = tx.commit() {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    get_group(state, id)
}

pub fn delete_group(state: &Path, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    match running_group_references_id(&conn, id) {
        Ok(true) => {
            return HttpResponse::json(400, json!({"error": "running group cannot be deleted"}));
        }
        Ok(false) => {}
        Err(err) => return HttpResponse::json(400, json!({"error": err.to_string()})),
    }
    if let Err(err) = conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = conn.execute("DELETE FROM group_nodes WHERE group_id = ?1", params![id]) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = conn.execute(
        "DELETE FROM group_subscriptions WHERE group_id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    match conn.execute("DELETE FROM groups WHERE id = ?1", params![id]) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub fn update_group_nodes(state: &Path, request: &HttpRequest, id: i64, add: bool) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "nodeIds");
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if add && let Err(err) = ensure_fixed_group_runtime_node_limit(&conn, id, &ids, &[], None) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_node_ids(&conn, id, &ids, add) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let _ = conn.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    );
    get_group(state, id)
}

pub fn replace_group_nodes(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let mut node_ids = integer_array(&body, "nodeIds");
    node_ids.sort_unstable();
    node_ids.dedup();
    let expected_version = body.get("expectedVersion").and_then(Value::as_i64);
    let mut conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let current_version = match tx
        .query_row(
            "SELECT version FROM groups WHERE id = ?1",
            params![id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_io_error)
    {
        Ok(Some(version)) => version,
        Ok(None) => return HttpResponse::json(404, json!({"error": "group not found"})),
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if expected_version.is_some_and(|expected| expected != current_version) {
        return HttpResponse::json(
            409,
            json!({
                "error": "group changed while its node selection was being edited",
                "code": "group_version_conflict",
                "currentVersion": current_version,
            }),
        );
    }
    if let Err(err) = validate_group_node_ids_exist(&tx, &node_ids) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = tx.execute("DELETE FROM group_nodes WHERE group_id = ?1", params![id]) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_node_ids(&tx, id, &node_ids, true) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = tx.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = tx.commit() {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    get_group(state, id)
}

pub fn update_group_subscriptions(
    state: &Path,
    request: &HttpRequest,
    id: i64,
    add: bool,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "subscriptionIds");
    let name_filter_regex = body.get("nameFilterRegex").and_then(Value::as_str);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if add
        && let Err(err) =
            ensure_fixed_group_runtime_node_limit(&conn, id, &[], &ids, name_filter_regex)
    {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_subscription_ids(&conn, id, &ids, name_filter_regex, add) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let _ = conn.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    );
    get_group(state, id)
}
