use super::*;
use dae_product_subscription::{get_subscription_value, list_subscriptions_value};

pub(crate) fn list_subscriptions(state: &Path, request: &HttpRequest) -> HttpResponse {
    let expand_nodes = request
        .query
        .get("expand")
        .map(|values| values.iter().any(|value| value == "nodes"))
        .unwrap_or(false);
    match list_subscriptions_value(state, expand_nodes) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn create_subscription(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    request: &HttpRequest,
) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let link = body.get("link").and_then(Value::as_str).unwrap_or("");
    if link.is_empty() {
        return HttpResponse::json(400, json!({"error": "link is required"}));
    }
    if let Some(cron_exp) = body.get("cronExp").and_then(Value::as_str)
        && let Err(err) = validate_subscription_cron_expression(cron_exp)
    {
        return HttpResponse::json(400, json!({"error": err}));
    }
    let tag = body.get("tag").and_then(Value::as_str);
    let use_proxy = body
        .get("useProxy")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let now = now_text();
    let _guard = match subscription_write_guard() {
        Ok(guard) => guard,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    match subscription_tag_exists(&conn, tag) {
        Ok(true) => return SubscriptionTagConflict::response(),
        Ok(false) => {}
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    }
    if let Err(err) = conn.execute(
        "INSERT INTO subscriptions(updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            now,
            link,
            body.get("cronExp")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_SUBSCRIPTION_CRON_EXP),
            body.get("cronEnable")
                .and_then(Value::as_bool)
                .unwrap_or(DEFAULT_SUBSCRIPTION_CRON_ENABLE) as i64,
            DEFAULT_SUBSCRIPTION_STATUS,
            "",
            tag,
            use_proxy as i64
        ],
    ) {
        if SubscriptionTagConflict::matches(&err) {
            return SubscriptionTagConflict::response();
        }
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    drop(conn);
    drop(_guard);
    notify_subscription_scheduler();
    let import_log_message = format!("subscription {id} imported");
    let _ = append_log_for_config(config_dir, state, "info", &import_log_message);
    let import_report = refresh_subscription_from_remote(control_runtime, state, config_dir, id)
        .unwrap_or_else(|_| {
            json!({
                "link": link,
                "fetched": false,
                "fetchError": Value::Null,
                "refreshError": {
                    "code": "refresh_failed",
                    "message": "subscription refresh could not be completed",
                    "retryable": true,
                },
                "refreshOutcome": "refresh-error-preserved",
                "preservedExistingNodes": true,
                "runtimeInputChanged": false,
                "nodeImportResult": []
            })
        });
    let mut response =
        subscription_import_result::subscription_import_response_value(id, link, &import_report);
    copy_subscription_refresh_fields(&import_report, &mut response);
    let outcome = SubscriptionRefreshOutcome::from_report(&import_report);
    apply_runtime_after_subscription_change(
        state,
        config_dir,
        runtime,
        outcome.requests_runtime_apply(),
        "subscription-create",
    )
    .insert_into(&mut response);
    HttpResponse::json(201, response)
}

pub(crate) fn get_subscription(state: &Path, id: i64) -> HttpResponse {
    match get_subscription_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "subscription not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn update_subscription(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let link = body.get("link").and_then(Value::as_str);
    let tag_present = body.get("tag").is_some();
    let tag = body.get("tag").and_then(Value::as_str);
    let cron_exp = body.get("cronExp").and_then(Value::as_str);
    if let Some(cron_exp) = cron_exp
        && let Err(err) = validate_subscription_cron_expression(cron_exp)
    {
        return HttpResponse::json(400, json!({"error": err}));
    }
    let cron_enable = body
        .get("cronEnable")
        .and_then(Value::as_bool)
        .map(|value| value as i64);
    let use_proxy = body
        .get("useProxy")
        .and_then(Value::as_bool)
        .map(|value| value as i64);
    let _guard = match subscription_write_guard() {
        Ok(guard) => guard,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let mut conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let updated = match tx.execute(
        "UPDATE subscriptions
         SET link = COALESCE(?1, link),
             tag = CASE WHEN ?2 THEN ?3 ELSE tag END,
             cron_exp = COALESCE(?4, cron_exp),
             cron_enable = COALESCE(?5, cron_enable),
             use_proxy = COALESCE(?6, use_proxy),
             updated_at = ?7
         WHERE id = ?8",
        params![
            link,
            tag_present,
            tag,
            cron_exp,
            cron_enable,
            use_proxy,
            now_text(),
            id
        ],
    ) {
        Ok(updated) => updated,
        Err(err) if SubscriptionTagConflict::matches(&err) => {
            return SubscriptionTagConflict::response();
        }
        Err(err) => return HttpResponse::json(400, json!({"error": err.to_string()})),
    };
    if updated == 0 {
        return HttpResponse::json(404, json!({"error": "subscription not found"}));
    }
    if let Err(err) = tx.commit() {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    drop(conn);
    drop(_guard);
    notify_subscription_scheduler();
    get_subscription(state, id)
}

pub(crate) fn refresh_subscription(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    id: i64,
) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    notify_subscription_scheduler();
    match refresh_subscription_from_remote(control_runtime, state, config_dir, id) {
        Ok(mut report) => {
            let outcome = SubscriptionRefreshOutcome::from_report(&report);
            let (level, message) = if outcome.fetched {
                ("info", format!("subscription {id} refreshed"))
            } else {
                ("warn", format!("subscription {id} refresh fetch failed"))
            };
            let _ = append_log_for_config(config_dir, state, level, &message);
            apply_runtime_after_subscription_change(
                state,
                config_dir,
                runtime,
                outcome.requests_runtime_apply(),
                "subscription-refresh",
            )
            .insert_into(&mut report);
            if let Some(subscription) = get_subscription_value(state, id)
                .ok()
                .flatten()
                .and_then(|value| value.as_object().cloned())
                && let Value::Object(map) = &mut report
            {
                for (key, value) in subscription {
                    map.insert(key, value);
                }
            }
            HttpResponse::json(200, report)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            HttpResponse::json(404, json!({"error": err.to_string()}))
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(crate) fn delete_subscriptions(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    request: &HttpRequest,
) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    let removed = match delete_subscriptions_by_ids(state, &ids) {
        Ok(removed) => removed,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let mut response = json!({"removed": removed});
    apply_runtime_after_subscription_change(
        state,
        config_dir,
        runtime,
        removed != 0,
        "subscription-delete-bulk",
    )
    .insert_into(&mut response);
    HttpResponse::json(200, response)
}

pub(crate) fn delete_subscription_by_id(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    id: i64,
) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    match delete_subscription(state, id) {
        Ok(removed) => {
            let mut response = json!({"removed": removed});
            apply_runtime_after_subscription_change(
                state,
                config_dir,
                runtime,
                removed != 0,
                "subscription-delete",
            )
            .insert_into(&mut response);
            HttpResponse::json(200, response)
        }
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn copy_subscription_refresh_fields(source: &Value, target: &mut Value) {
    let (Value::Object(source), Value::Object(target)) = (source, target) else {
        return;
    };
    for key in [
        "fetched",
        "fetchedAt",
        "refreshOutcome",
        "sourceKind",
        "sourceNodeCount",
        "admittedNodeCount",
        "invalidNodeCount",
        "notAdmittedNodeCount",
        "preservedExistingNodes",
        "runtimeInputChanged",
        "fetchError",
        "refreshError",
    ] {
        if let Some(value) = source.get(key) {
            target.insert(key.to_owned(), value.clone());
        }
    }
}
