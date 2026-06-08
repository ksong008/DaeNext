use super::*;
#[test]
pub(super) fn daed_run_serves_minimal_api_and_static_webui() {
    let temp = temp_dir("run-api");
    let web = temp.join("web");
    fs::create_dir_all(&web).unwrap();
    fs::write(web.join("index.html"), "<!doctype html><title>daed</title>").unwrap();
    let port = free_port();
    let listen = loopback_listen_addr(port);
    let mut child = Command::new(binary())
        .args(["run", "-c"])
        .arg(&temp)
        .args(["--listen", &listen, "--web-root"])
        .arg(&web)
        .env("DAED_PRODUCT_RUNTIME_FAKE_START", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    wait_for_http(port, "/api/health", &mut child);

    let health = http_request(port, "GET", "/api/health", None, None);
    assert!(health.contains("200 OK"));
    assert!(health.contains("\"healthCheck\":1"));

    let status = http_request(port, "GET", "/api/auth/status", None, None);
    assert!(status.contains("\"numberUsers\":0"));

    let create = http_request(
        port,
        "POST",
        "/api/auth/users",
        Some(r#"{"username":"admin","password":"abc123"}"#),
        None,
    );
    assert!(create.contains("201 Created"), "{create}");
    let token = json_body(&create)["token"].as_str().unwrap().to_owned();
    assert!(!token.is_empty());

    let me = http_request(port, "GET", "/api/user/me", None, Some(&token));
    assert!(me.contains("\"username\":\"admin\""), "{me}");

    let set_storage = http_request(
        port,
        "PUT",
        "/api/user/me/storage",
        Some(r#"{"paths":["ui.sidebar"],"values":["open"]}"#),
        Some(&token),
    );
    assert!(set_storage.contains("\"updated\":1"), "{set_storage}");

    let get_storage = http_request(
        port,
        "GET",
        "/api/user/me/storage?path=ui.sidebar",
        None,
        Some(&token),
    );
    assert!(
        get_storage.contains("\"values\":[\"open\"]"),
        "{get_storage}"
    );

    let index = http_request(port, "GET", "/", None, None);
    assert!(index.contains("<title>daed</title>"), "{index}");

    child.kill().unwrap();
    let _ = child.wait();
    fs::remove_dir_all(temp).unwrap();
}

#[test]
pub(super) fn daed_run_serves_c10_resource_runtime_log_latency_and_bundle_surface() {
    let temp = temp_dir("run-c10-api");
    let web = temp.join("web");
    fs::create_dir_all(&web).unwrap();
    fs::write(web.join("index.html"), "<!doctype html><title>daed</title>").unwrap();
    let port = free_port();
    let listen = loopback_listen_addr(port);
    let mut child = Command::new(binary())
        .args(["run", "-c"])
        .arg(&temp)
        .args(["--listen", &listen, "--web-root"])
        .arg(&web)
        .env("DAED_PRODUCT_RUNTIME_FAKE_START", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    wait_for_http(port, "/api/health", &mut child);

    let create = http_request(
        port,
        "POST",
        "/api/auth/users",
        Some(r#"{"username":"admin","password":"abc123"}"#),
        None,
    );
    assert!(create.contains("201 Created"), "{create}");
    let token = json_body(&create)["token"].as_str().unwrap().to_owned();

    let (probe_port, probe_handle) = spawn_tcp_probe_server();
    let selected_subscription_node =
        loopback_http_fixture_url(probe_port, "/selected", Some("selected-sub-node"));
    let ignored_subscription_node =
        loopback_http_fixture_url(probe_port, "/ignored", Some("ignored-sub-node"));
    let subscription_source = format!(
        "{selected_subscription_node}\n\
         {ignored_subscription_node}\n"
    );
    let (subscription_port, subscription_handle) = spawn_text_server(&subscription_source);

    let config = http_request(
        port,
        "POST",
        "/api/configs",
        Some(r#"{"name":"global","global":"global {\n  log_level: \"info\"\n}"}"#),
        Some(&token),
    );
    assert!(config.contains("201 Created"), "{config}");
    let config_id = json_body(&config)["id"].as_i64().unwrap();
    let select_config = http_request(
        port,
        "POST",
        &format!("/api/configs/{config_id}/select"),
        Some("{}"),
        Some(&token),
    );
    assert!(
        select_config.contains("\"selected\":true"),
        "{select_config}"
    );

    let dns = http_request(
        port,
        "POST",
        "/api/dns",
        Some(r#"{"name":"dns","dns":"dns {}"}"#),
        Some(&token),
    );
    let dns_id = json_body(&dns)["id"].as_i64().unwrap();
    let _ = http_request(
        port,
        "POST",
        &format!("/api/dns/{dns_id}/select"),
        Some("{}"),
        Some(&token),
    );

    let routing = http_request(
        port,
        "POST",
        "/api/routings",
        Some(r#"{"name":"routing","routing":"routing {}"}"#),
        Some(&token),
    );
    let routing_id = json_body(&routing)["id"].as_i64().unwrap();
    let _ = http_request(
        port,
        "POST",
        &format!("/api/routings/{routing_id}/select"),
        Some("{}"),
        Some(&token),
    );

    let nodes = http_request(
        port,
        "POST",
        "/api/nodes",
        Some(&format!(
            r#"{{"args":[{{"link":"{}","tag":"n1"}}]}}"#,
            loopback_http_fixture_url(probe_port, "/node", Some("n1"))
        )),
        Some(&token),
    );
    let node_id = json_body(&nodes)["items"][0]["node"]["id"]
        .as_i64()
        .unwrap();
    let tag_node = http_request(
        port,
        "PUT",
        &format!("/api/nodes/{node_id}"),
        Some(r#"{"tag":"n1-renamed"}"#),
        Some(&token),
    );
    assert!(tag_node.contains("\"tag\":\"n1-renamed\""), "{tag_node}");

    let subscription = http_request(
        port,
        "POST",
        "/api/subscriptions",
        Some(&format!(
            r#"{{"link":"{}","tag":"sub1"}}"#,
            loopback_http_fixture_url(subscription_port, "/sub", None)
        )),
        Some(&token),
    );
    assert!(subscription.contains("201 Created"), "{subscription}");
    assert!(
        subscription.contains("selected-sub-node") && subscription.contains("ignored-sub-node"),
        "subscription fetch did not import local node: {subscription}"
    );
    subscription_handle.join().unwrap();
    let subscription_id = json_body(&subscription)["subscription"]["id"]
        .as_i64()
        .unwrap();
    let tag_subscription = http_request(
        port,
        "PUT",
        &format!("/api/subscriptions/{subscription_id}"),
        Some(r#"{"tag":"sub-renamed"}"#),
        Some(&token),
    );
    assert!(
        tag_subscription.contains("\"tag\":\"sub-renamed\""),
        "{tag_subscription}"
    );
    let cron_subscription = http_request(
        port,
        "PUT",
        &format!("/api/subscriptions/{subscription_id}"),
        Some(r#"{"cronExp":"0 */2 * * *","cronEnable":false}"#),
        Some(&token),
    );
    assert!(
        cron_subscription.contains("\"tag\":\"sub-renamed\""),
        "{cron_subscription}"
    );
    let refreshed = http_request(
        port,
        "POST",
        &format!("/api/subscriptions/{subscription_id}/refresh"),
        Some("{}"),
        Some(&token),
    );
    assert!(
        refreshed.contains("\"status\":\"fetch_error\""),
        "{refreshed}"
    );

    let group = http_request(
        port,
        "POST",
        "/api/groups",
        Some(r#"{"name":"egress","policy":"min","policyParams":[{"key":"interval","val":"30s"}]}"#),
        Some(&token),
    );
    assert!(group.contains("201 Created"), "{group}");
    let group_id = json_body(&group)["id"].as_i64().unwrap();
    let bind_node = http_request(
        port,
        "POST",
        &format!("/api/groups/{group_id}/nodes"),
        Some(&format!(r#"{{"nodeIds":[{node_id}]}}"#)),
        Some(&token),
    );
    assert!(bind_node.contains("\"nodes\""), "{bind_node}");
    let bind_subscription = http_request(
        port,
        "POST",
        &format!("/api/groups/{group_id}/subscriptions"),
        Some(&format!(
            r#"{{"subscriptionIds":[{subscription_id}],"nameFilterRegex":"^selected-"}}"#
        )),
        Some(&token),
    );
    assert!(
        bind_subscription.contains("\"matchedCount\""),
        "{bind_subscription}"
    );

    let groups = json_body(&http_request(
        port,
        "GET",
        "/api/groups",
        None,
        Some(&token),
    ));
    assert_eq!(groups["items"][0]["policy"].as_str().unwrap(), "min");
    assert_eq!(
        groups["items"][0]["nodes"][0]["id"].as_i64().unwrap(),
        node_id
    );
    let subscription_binding = &groups["items"][0]["subscriptions"][0];
    assert_eq!(subscription_binding["matchedCount"].as_i64().unwrap(), 1);
    assert_eq!(
        subscription_binding["matchedNodes"][0]["name"]
            .as_str()
            .unwrap(),
        "selected-sub-node"
    );
    assert!(
        !subscription_binding["matchedNodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["name"].as_str() == Some("ignored-sub-node")),
        "{subscription_binding}"
    );

    let latency = http_request(
        port,
        "POST",
        "/api/nodes/latencies",
        Some(&format!(r#"{{"ids":[{node_id}]}}"#)),
        Some(&token),
    );
    let latency = json_body(&latency);
    assert_eq!(latency["items"][0]["id"].as_i64().unwrap(), node_id);
    assert!(latency["items"][0]["alive"].as_bool().unwrap());
    assert!(latency["items"][0]["latencyMs"].is_number(), "{latency}");
    assert!(latency["items"][0]["message"].is_null(), "{latency}");
    probe_handle.join().unwrap();

    let settings = http_request(
        port,
        "PATCH",
        "/api/logs/settings",
        Some(r#"{"maxEntries":500,"maxBytes":131072}"#),
        Some(&token),
    );
    let settings = json_body(&settings);
    assert_eq!(settings["maxEntries"].as_i64().unwrap(), 500);
    assert_eq!(settings["minMaxEntries"].as_i64().unwrap(), 500);

    let log_level = http_request(
        port,
        "PATCH",
        "/api/runtime/log-level",
        Some(r#"{"level":"debug"}"#),
        Some(&token),
    );
    assert!(log_level.contains("\"level\":\"debug\""), "{log_level}");

    let reload = http_request(
        port,
        "POST",
        "/api/runtime/reload",
        Some(r#"{"dry":false}"#),
        Some(&token),
    );
    assert!(reload.contains("\"applied\":1"), "{reload}");
    assert!(reload.contains("\"runtimeStarted\":true"), "{reload}");
    assert!(
        reload.contains("\"runtimeControl\":\"fake-resident-runtime-test-only\""),
        "{reload}"
    );
    assert!(temp.join("runtime/generated.dae").is_file());
    let generated = fs::read_to_string(temp.join("runtime/generated.dae")).unwrap();
    assert!(generated.contains("generated by Rust daed C10 local product surface"));
    assert!(generated.contains("node {"), "{generated}");
    assert!(generated.contains("group {"), "{generated}");
    assert!(
        generated.contains("filter: name('n1-renamed'"),
        "{generated}"
    );
    assert!(
        generated.contains("filter: name('n1-renamed', 'selected-sub-node')"),
        "{generated}"
    );
    assert!(
        !generated.contains("filter: name('n1-renamed', 'ignored-sub-node')"),
        "{generated}"
    );

    let state = http_request(port, "GET", "/api/general/state", None, Some(&token));
    assert!(state.contains("\"running\":true"), "{state}");
    assert!(
        state.contains("\"attachBackend\":\"fake-resident-runtime-test-only\""),
        "{state}"
    );
    let overview = http_request(port, "GET", "/api/runtime/overview", None, Some(&token));
    assert!(overview.contains("\"rssBytes\""), "{overview}");
    assert!(overview.contains("\"runtime\""), "{overview}");
    let logs = http_request(port, "GET", "/api/logs?level=all", None, Some(&token));
    assert!(logs.contains("\"items\""), "{logs}");
    assert!(
        logs.contains("\"id\":1") && logs.contains("\"message\":\"[Reload] Finished\""),
        "{logs}"
    );
    let events = http_request_until(
        port,
        "GET",
        "/api/events/runtime",
        None,
        Some(&token),
        "event: runtime.overview",
    );
    assert!(events.contains("event: runtime.overview"), "{events}");
    let log_events = http_request_until(
        port,
        "GET",
        "/api/events/logs",
        None,
        Some(&token),
        "retry: 3000",
    );
    assert!(log_events.contains("retry: 3000"), "{log_events}");

    let bundle = json_body(&http_request(
        port,
        "GET",
        "/api/user/me/dae-bundle",
        None,
        Some(&token),
    ));
    assert_eq!(bundle["schemaVersion"].as_i64().unwrap(), 1);
    assert_eq!(bundle["groups"][0]["nodeIds"][0].as_i64().unwrap(), node_id);
    let import_bundle = http_request(
        port,
        "PUT",
        "/api/user/me/dae-bundle",
        Some(&bundle.to_string()),
        Some(&token),
    );
    assert!(
        import_bundle.contains("\"imported\":true"),
        "{import_bundle}"
    );

    let config_file = http_request(
        port,
        "GET",
        "/api/user/me/dae-config-file",
        None,
        Some(&token),
    );
    assert!(
        config_file.contains("\"filename\":\"generated.dae\""),
        "{config_file}"
    );
    let preview = http_request(
        port,
        "POST",
        "/api/user/me/dae-config-file/preview",
        Some(r#"{"content":"global {}"}"#),
        Some(&token),
    );
    assert!(preview.contains("\"bundle\""), "{preview}");

    let clear_logs = http_request(port, "DELETE", "/api/logs", Some("{}"), Some(&token));
    assert!(clear_logs.contains("\"cleared\":true"), "{clear_logs}");
    let stop = http_request(port, "POST", "/api/runtime/stop", Some("{}"), Some(&token));
    assert!(stop.contains("\"stopped\":true"), "{stop}");

    child.kill().unwrap();
    let _ = child.wait();
    fs::remove_dir_all(temp).unwrap();
}
