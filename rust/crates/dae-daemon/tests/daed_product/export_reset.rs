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
        assert!(value.to_string().contains("go-free-product-chain"));
    }
    for command in ["package-manifest", "admission-report", "webui-route-audit"] {
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
        assert!(value.to_string().contains("go-free-product-chain"));
    }
    let route_audit = Command::new(binary())
        .args(["export", "webui-route-audit"])
        .output()
        .unwrap();
    let route_audit: Value = serde_json::from_slice(&route_audit.stdout).unwrap();
    assert!(route_audit["pass"].as_bool().unwrap());
    assert!(route_audit["missing"].as_array().unwrap().is_empty());
    let manifest = Command::new(binary())
        .args(["export", "package-manifest"])
        .output()
        .unwrap();
    let manifest: Value = serde_json::from_slice(&manifest.stdout).unwrap();
    assert_eq!(
        manifest["binary"]["validateArgs"][0].as_str().unwrap(),
        "validate"
    );
    assert!(
        !manifest["admission"]["fullGoFreeProductChainReady"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !manifest["admission"]["rollbackValidationAppliedOnLiveHost"]
            .as_bool()
            .unwrap()
    );

    let admission = Command::new(binary())
        .args(["export", "admission-report"])
        .output()
        .unwrap();
    let admission: Value = serde_json::from_slice(&admission.stdout).unwrap();
    assert_eq!(admission["status"].as_str().unwrap(), "blocked");
    assert!(
        !admission["remainingBlockers"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let systemd = Command::new(binary())
        .args(["export", "systemd-unit"])
        .output()
        .unwrap();
    assert!(systemd.status.success());
    assert!(
        String::from_utf8_lossy(&systemd.stdout).contains("ExecStartPre=/usr/bin/daed validate")
    );
    assert!(String::from_utf8_lossy(&systemd.stdout).contains("ExecStart=/usr/bin/daed run"));

    let docker = Command::new(binary())
        .args(["export", "docker-entrypoint"])
        .output()
        .unwrap();
    assert!(docker.status.success());
    assert!(String::from_utf8_lossy(&docker.stdout).contains("/usr/bin/daed validate"));
    assert!(String::from_utf8_lossy(&docker.stdout).contains("exec /usr/bin/daed run"));
}

#[test]
fn daed_resetpass_updates_daed_db_users_without_wing_db() {
    let temp = temp_dir("resetpass");
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
    child.kill().unwrap();
    let _ = child.wait();

    let wing = temp.join("wing.db");
    fs::write(&wing, b"protected rollback db").unwrap();
    let wing_hash_before = sha256(&wing);
    let reset = Command::new(binary())
        .args(["resetpass", "-c"])
        .arg(&temp)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        reset.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&reset.stderr)
    );
    assert_eq!(wing_hash_before, sha256(&wing));
    let report: Value = serde_json::from_slice(&reset.stdout).unwrap();
    let password = report["users"][0]["password"].as_str().unwrap().to_owned();
    assert_eq!(report["users"][0]["username"].as_str().unwrap(), "admin");

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
    let token = http_request(
        port,
        "POST",
        "/api/auth/token",
        Some(&format!(
            r#"{{"username":"admin","password":"{password}"}}"#
        )),
        None,
    );
    assert!(token.contains("\"token\""), "{token}");
    child.kill().unwrap();
    let _ = child.wait();

    fs::remove_dir_all(temp).unwrap();
}
