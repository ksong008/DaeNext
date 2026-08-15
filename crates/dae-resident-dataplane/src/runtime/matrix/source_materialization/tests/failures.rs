use super::*;
use base64::Engine;

#[test]
fn failed_builds_do_not_guess_production_source_shapes() {
    let vmess_json = r#"{"v":"2","ps":"","add":"vmess.fixture.invalid","port":"443","id":"7c12c745-63a5-433d-9e60-022e469b5bd4","aid":"1","net":"ws","type":"none","host":"front.fixture.invalid","path":"/ws","tls":"tls","sni":"front.fixture.invalid"}"#;
    let nodes = vec![
        plan::ResidentNodeLinkShape {
            tag: "passthrough-source".to_owned(),
            scheme: "socks5".to_owned(),
            link: "socks5://identity:credential@socks.fixture.invalid:1080?passthroughUdp=true"
                .to_owned(),
        },
        plan::ResidentNodeLinkShape {
            tag: "vmess-tls-ws-failure".to_owned(),
            scheme: "vmess".to_owned(),
            link: format!(
                "vmess://{}",
                base64::engine::general_purpose::STANDARD.encode(vmess_json)
            ),
        },
        plan::ResidentNodeLinkShape {
            tag: "trojan-inner-failure".to_owned(),
            scheme: "trojan-go".to_owned(),
            link: "trojan-go://credential@trojan.fixture.invalid:443?encryption=ss%3Baes-128-gcm%3A&host=front.fixture.invalid&path=%2Fws&sni=front.fixture.invalid&type=ws"
                .to_owned(),
        },
        plan::ResidentNodeLinkShape {
            tag: "vless-vision-reality-failure".to_owned(),
            scheme: "vless".to_owned(),
            link: "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@vless.fixture.invalid:443?flow=xtls-rprx-vision&security=reality&sni=front.fixture.invalid&type=tcp"
                .to_owned(),
        },
    ];

    reset_source_matrix_builder_calls();
    let matrix = resident_expanded_source_matrix(&fixture_config(), &nodes, &[]);
    let rows = matrix.rows;

    assert_eq!(source_matrix_builder_calls(), nodes.len());
    assert_eq!(matrix.source_admission_diagnostics.len(), nodes.len());
    assert!(
        matrix
            .source_admission_diagnostics
            .iter()
            .all(|diagnostic| {
                diagnostic["status"] == "source-materialization-failed"
                    && diagnostic["nodeIdentity"]
                        .as_str()
                        .is_some_and(|identity| identity.starts_with("sha256:"))
            })
    );
    let diagnostics = serde_json::to_string(&matrix.source_admission_diagnostics).unwrap();
    assert!(!diagnostics.contains("credential"));
    assert!(!diagnostics.contains("7c12c745-63a5-433d-9e60-022e469b5bd4"));
    for node in &nodes {
        assert_eq!(candidate_occurrences(&rows, &node.tag), 0, "{}", node.tag);
    }
    for shape_id in [
        "baseline-socks-endpoint",
        "plain-websocket-framed-endpoint",
        "stream-wrapper-websocket",
        "vless-native-tcp-endpoint",
    ] {
        assert_no_candidates(row(&rows, shape_id));
    }
}

#[test]
fn malformed_untagged_source_stays_visible_with_a_hashed_identity() {
    let source = "vless://matrix-secret@";
    let nodes = vec![plan::ResidentNodeLinkShape {
        tag: source.to_owned(),
        scheme: "vless".to_owned(),
        link: source.to_owned(),
    }];

    let rows = resident_full_matrix_config_rows(&fixture_config(), &nodes);
    let vless = rows
        .iter()
        .find(|row| row["formal_matrix_handler"] == "vless")
        .unwrap();
    assert_eq!(vless["planner_status"], "blocked");
    assert_eq!(vless["candidate_count"], 1);
    assert_eq!(vless["blocked_count"], 1);
    assert!(
        vless["candidates"][0]["node_tag"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    assert_eq!(
        vless["candidates"][0]["node_tag_source"],
        "derived-link-hash"
    );
    assert_eq!(
        vless["candidates"][0]["error"],
        "resident matrix operation failed; inspect protected daemon logs for details"
    );
    let rendered = serde_json::to_string(vless).unwrap();
    assert!(!rendered.contains(source));
    assert!(!rendered.contains("matrix-secret"));

    let matrix = resident_expanded_source_matrix(&fixture_config(), &nodes, &rows);
    assert_eq!(matrix.source_admission_diagnostics.len(), 1);
    let diagnostic = &matrix.source_admission_diagnostics[0];
    assert_eq!(diagnostic["status"], "source-materialization-failed");
    assert!(
        diagnostic["nodeTag"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    assert_eq!(diagnostic["nodeTagSource"], "derived-link-hash");
    let rendered = serde_json::to_string(diagnostic).unwrap();
    assert!(!rendered.contains(source));
    assert!(!rendered.contains("matrix-secret"));
}

#[test]
fn successful_unclassified_shape_uses_the_diagnostic_surface() {
    let node = plan::ResidentNodeLinkShape {
        tag: "future-shape".to_owned(),
        scheme: "vless".to_owned(),
        link: "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@vless.fixture.invalid:443?security=tls&sni=front.fixture.invalid&type=ws"
            .to_owned(),
    };
    let proxy = build_resident_source_plan(&fixture_config(), "vless", &node).unwrap();
    let mut shape = materialized_source_shape(&proxy, &node.link);
    shape.security = dae_outbound::MaterializedSecurity::Unsupported;
    shape.wrapper = dae_outbound::MaterializedWrapper::Unsupported;
    let materializations = [ResidentSourceMaterialization {
        node: &node,
        outcome: Ok(MaterializedResidentSourcePlan { proxy, shape }),
    }];

    let diagnostics = resident_source_materialization_diagnostics(
        dae_outbound::source_shape_registry_rows(),
        &materializations,
    );

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["status"], "unclassified-materialized-shape");
    assert_eq!(diagnostics[0]["nodeTag"], "future-shape");
    assert_eq!(diagnostics[0]["scheme"], "vless");
    assert!(
        diagnostics[0]["nodeIdentity"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
    let rendered = serde_json::to_string(&diagnostics).unwrap();
    assert!(!rendered.contains("7c12c745-63a5-433d-9e60-022e469b5bd4"));
}
