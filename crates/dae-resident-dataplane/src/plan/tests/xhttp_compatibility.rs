use super::*;

fn xhttp_plan(extra: serde_json::Value, mode: &str) -> Result<ResidentProxyPlan, String> {
    let config = parse_config(
        "global {\nlan_interface: daerust0\nallow_insecure: false\nso_mark_from_dae: 1234\nmptcp: false\n}\nrouting {\nfallback: direct\n}",
    );
    build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "xhttp-compat".to_owned(),
        vless_xhttp_parser_fixture_url(mode, "h2", &extra.to_string()),
    )
}

#[test]
fn xhttp_methods_path_placement_and_resource_limits() {
    use serde_json::json;
    for method in ["PUT", "PATCH", "X-CUSTOM"] {
        let plan = xhttp_plan(
            json!({"uplinkHTTPMethod":method,"sessionIDPlacement":"header","seqPlacement":"query"}),
            "packet-up",
        )
        .unwrap();
        assert_eq!(plan.xhttp_settings.uplink_http_method, method);
        assert!(!plan.stream_path.split('?').next().unwrap().ends_with('/'));
    }
    assert!(
        xhttp_plan(json!({"uplinkHTTPMethod":"GET"}), "stream-up")
            .unwrap_err()
            .contains("packet-up")
    );
    assert!(
        xhttp_plan(json!({"uplinkHTTPMethod":"BAD METHOD"}), "packet-up")
            .unwrap_err()
            .contains("valid HTTP method")
    );
    for (key, value) in [
        ("xPaddingBytes", 16385),
        ("sessionIDLength", i32::MAX),
        ("scMaxEachPostBytes", 4194305),
        ("uplinkChunkSize", 16385),
    ] {
        let error = xhttp_plan(json!({key:value}), "packet-up").unwrap_err();
        assert!(
            error.contains(key) && error.contains("must be in"),
            "{error}"
        );
    }
    assert!(
        xhttp_plan(
            json!({"sessionIDTable":"Base62","sessionIDLength":"6-256"}),
            "packet-up"
        )
        .is_ok()
    );
    assert!(
        xhttp_plan(
            json!({"sessionIDTable":"number","sessionIDLength":1}),
            "packet-up"
        )
        .unwrap_err()
        .contains("too small")
    );
}

#[test]
fn xhttp_download_tls_defaults_to_its_own_address() {
    use serde_json::json;
    for explicit in [None, Some("explicit.download.example")] {
        let mut tls = json!({});
        if let Some(name) = explicit {
            tls["serverName"] = json!(name);
        }
        let plan = xhttp_plan(json!({"downloadSettings":{
            "address":"download.example","port":443,"network":"xhttp","security":"tls",
            "tlsSettings":tls,"xhttpSettings":{"path":"/download","sessionIDPlacement":"header","seqPlacement":"query"}
        }}), "packet-up").unwrap();
        let endpoint = plan.xhttp_download.unwrap();
        assert_eq!(endpoint.server_name, explicit.unwrap_or("download.example"));
        assert_eq!(endpoint.stream_path, "/download");
        assert!(!endpoint.allow_insecure);
    }
}

#[test]
fn xhttp_zero_post_limit_uses_official_default_and_keeps_resource_bounds() {
    use serde_json::json;
    for zero in [json!(0), json!("0"), json!("0-0"), json!({"from":0,"to":0})] {
        let plan = xhttp_plan(json!({"scMaxEachPostBytes":zero}), "packet-up").unwrap();
        assert_eq!(
            plan.xhttp_settings.normalized_sc_max_each_post_bytes(),
            (1_000_000, 1_000_000)
        );
    }
    for invalid in [json!(-1), json!("0-1024"), json!(4_194_305)] {
        assert!(
            xhttp_plan(json!({"scMaxEachPostBytes":invalid}), "packet-up")
                .unwrap_err()
                .contains("scMaxEachPostBytes")
        );
    }
}

#[test]
fn xhttp_download_reality_password_precedence_and_effective_identity() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;
    let key = URL_SAFE_NO_PAD.encode([7; 32]);
    let other = URL_SAFE_NO_PAD.encode([8; 32]);
    let download = |credentials: serde_json::Value| {
        let mut reality =
            json!({"serverName":"download.example","fingerprint":"chrome","shortId":"0102"});
        reality
            .as_object_mut()
            .unwrap()
            .extend(credentials.as_object().unwrap().clone());
        xhttp_plan(
            json!({"downloadSettings":{
                "address":"download.example","port":443,"network":"xhttp","security":"reality",
                "realitySettings":reality,"xhttpSettings":{"path":"/download"}
            }}),
            "packet-up",
        )
        .map(|p| p.xhttp_download.unwrap())
    };
    let reference = download(json!({"publicKey":key})).unwrap();
    for credentials in [
        json!({"password":key}),
        json!({"password":key,"publicKey":other}),
        json!({"password":"","publicKey":key}),
        json!({"password":key,"publicKey":"invalid-ignored"}),
    ] {
        // The normalized endpoint is also the input to TLS/session/XMUX keys.
        assert_eq!(download(credentials).unwrap(), reference);
    }
    assert_ne!(
        download(json!({"password":other})).unwrap().reality,
        reference.reality
    );
    for invalid in [
        json!("not!base64"),
        json!(URL_SAFE_NO_PAD.encode([0; 31])),
        json!(42),
    ] {
        assert!(download(json!({"password":invalid,"publicKey":key})).is_err());
    }
    assert!(
        download(json!({}))
            .unwrap_err()
            .contains("password or publicKey")
    );
}
