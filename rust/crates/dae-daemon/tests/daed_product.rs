use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_daed")
}

#[test]
fn daed_product_contract_reports_c10_first_batch_state_paths() {
    let output = Command::new(binary())
        .args(["service-contract", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["primary_state_store"].as_str().unwrap(),
        "/etc/daed/daed.db"
    );
    assert_eq!(
        report["protected_rollback_state_store"].as_str().unwrap(),
        "/etc/daed/wing.db"
    );
    assert!(
        !report["rust_daed_writes_wing_db_by_default"]
            .as_bool()
            .unwrap()
    );
    assert!(report["wing_db_import_supported"].as_bool().unwrap());
    assert!(
        report["rust_daed_setup_auth_user_storage_api_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_static_webui_serving_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_resource_crud_api_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_daed_materializer_ready"].as_bool().unwrap());
    assert!(report["rust_daed_runtime_owner_ready"].as_bool().unwrap());
    assert!(
        report["rust_daed_logs_sse_latency_subscription_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_import_export_package_surface_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_free_product_chain_typed_report"]["rust_product_binary_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["go_free_product_chain_typed_report"]["status"]
            .as_str()
            .unwrap(),
        "blocked"
    );
    assert!(!report["go_free_product_chain_ready"].as_bool().unwrap());

    let package = Command::new(binary())
        .args(["package-info", "--json"])
        .output()
        .unwrap();
    assert!(package.status.success());
    let package: Value = serde_json::from_slice(&package.stdout).unwrap();
    assert_eq!(
        package["primary_state_store"].as_str().unwrap(),
        "/etc/daed/daed.db"
    );
    assert!(!package["webui"]["leptos_considered"].as_bool().unwrap());
}

#[test]
fn daed_state_migrate_does_not_modify_wing_db() {
    let temp = temp_dir("state-migrate");
    let wing = temp.join("wing.db");
    let daed = temp.join("daed.db");

    let check_wing = Command::new(binary())
        .args(["state", "check", "--state"])
        .arg(&wing)
        .output()
        .unwrap();
    assert!(check_wing.status.success());
    let wing_hash_before = sha256(&wing);

    let migrate = Command::new(binary())
        .args(["state", "migrate", "--from-wing-db"])
        .arg(&wing)
        .args(["--to"])
        .arg(&daed)
        .output()
        .unwrap();
    assert!(
        migrate.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&migrate.stderr)
    );
    let report: Value = serde_json::from_slice(&migrate.stdout).unwrap();
    assert!(report["wing_db_unchanged"].as_bool().unwrap());
    assert_eq!(wing_hash_before, sha256(&wing));

    let check_daed = Command::new(binary())
        .args(["state", "check", "--state"])
        .arg(&daed)
        .output()
        .unwrap();
    assert!(check_daed.status.success());
    let report: Value = serde_json::from_slice(&check_daed.stdout).unwrap();
    assert!(report["schema_ready"].as_bool().unwrap());

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn daed_run_serves_minimal_api_and_static_webui() {
    let temp = temp_dir("run-api");
    let web = temp.join("web");
    fs::create_dir_all(&web).unwrap();
    fs::write(web.join("index.html"), "<!doctype html><title>daed</title>").unwrap();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = Command::new(binary())
        .args(["run", "-c"])
        .arg(&temp)
        .args(["--listen", &listen, "--web-root"])
        .arg(&web)
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
fn daed_run_serves_c10_resource_runtime_log_latency_and_bundle_surface() {
    let temp = temp_dir("run-c10-api");
    let web = temp.join("web");
    fs::create_dir_all(&web).unwrap();
    fs::write(web.join("index.html"), "<!doctype html><title>daed</title>").unwrap();
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = Command::new(binary())
        .args(["run", "-c"])
        .arg(&temp)
        .args(["--listen", &listen, "--web-root"])
        .arg(&web)
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
        Some(
            r#"{"args":[{"link":"vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls#n1","tag":"n1"}]}"#,
        ),
        Some(&token),
    );
    let node_id = json_body(&nodes)["items"][0]["node"]["id"]
        .as_i64()
        .unwrap();

    let subscription = http_request(
        port,
        "POST",
        "/api/subscriptions",
        Some(r#"{"link":"https://example.invalid/sub","tag":"sub1"}"#),
        Some(&token),
    );
    assert!(subscription.contains("201 Created"), "{subscription}");
    let subscription_id = json_body(&subscription)["subscription"]["id"]
        .as_i64()
        .unwrap();
    let refreshed = http_request(
        port,
        "POST",
        &format!("/api/subscriptions/{subscription_id}/refresh"),
        Some("{}"),
        Some(&token),
    );
    assert!(
        refreshed.contains("\"status\":\"refreshed\""),
        "{refreshed}"
    );

    let group = http_request(
        port,
        "POST",
        "/api/groups",
        Some(r#"{"name":"proxy","policy":"min","policyParams":[{"key":"interval","val":"30s"}]}"#),
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
            r#"{{"subscriptionIds":[{subscription_id}],"nameFilterRegex":"n.*"}}"#
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

    let settings = http_request(
        port,
        "PATCH",
        "/api/logs/settings",
        Some(r#"{"maxEntries":500,"maxBytes":131072}"#),
        Some(&token),
    );
    let settings = json_body(&settings);
    assert_eq!(settings["maxEntries"].as_i64().unwrap(), 500);
    assert_eq!(settings["minMaxEntries"].as_i64().unwrap(), 100);

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
    assert!(temp.join("runtime/generated.dae").is_file());
    let generated = fs::read_to_string(temp.join("runtime/generated.dae")).unwrap();
    assert!(generated.contains("generated by Rust daed C10 local product surface"));

    let state = http_request(port, "GET", "/api/general/state", None, Some(&token));
    assert!(state.contains("\"running\":true"), "{state}");
    let overview = http_request(port, "GET", "/api/runtime/overview", None, Some(&token));
    assert!(overview.contains("\"rssBytes\""), "{overview}");
    let events = http_request(port, "GET", "/api/events/runtime", None, Some(&token));
    assert!(events.contains("event: runtime.overview"), "{events}");
    let log_events = http_request(port, "GET", "/api/events/logs", None, Some(&token));
    assert!(log_events.contains("event: logs.append"), "{log_events}");

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

#[test]
fn daed_export_commands_report_c10_package_surface() {
    for command in ["openapi", "flatdesc", "outline"] {
        let output = Command::new(binary())
            .args(["export", command])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "command={command} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(value.to_string().contains("go-free-product-chain-v1"));
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("daed-product-{name}-{}", fastrand::u64(..)));
    fs::create_dir_all(&path).unwrap();
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_http(port: u16, path: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("daed exited early: {status}; stderr={stderr}");
        }
        if let Ok(response) = try_http_request(port, "GET", path, None, None) {
            if response.contains("200 OK") {
                return;
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for daed");
        thread::sleep(Duration::from_millis(50));
    }
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> String {
    try_http_request(port, method, path, body, token).unwrap()
}

fn try_http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
    )?;
    if let Some(token) = token {
        write!(stream, "Authorization: Bearer {token}\r\n")?;
    }
    if !body.is_empty() {
        write!(
            stream,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )?;
    }
    write!(stream, "\r\n")?;
    if !body.is_empty() {
        write!(stream, "{body}")?;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn json_body(response: &str) -> Value {
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}
