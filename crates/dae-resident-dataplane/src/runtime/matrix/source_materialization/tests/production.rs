use super::*;

#[test]
fn expanded_source_matrix_builds_each_production_node_once() {
    let nodes = vec![
        plan::ResidentNodeLinkShape {
            tag: "vless-source".to_owned(),
            scheme: "vless".to_owned(),
            link: "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@vless.fixture.invalid:443?allowInsecure=0&host=front.fixture.invalid&path=%2Fws&security=tls&sni=front.fixture.invalid&type=ws"
                .to_owned(),
        },
        plan::ResidentNodeLinkShape {
            tag: "trojan-source".to_owned(),
            scheme: "trojan-go".to_owned(),
            link: "trojan-go://fixture-secret@trojan.fixture.invalid:443?host=front.fixture.invalid&path=%2Fws&sni=front.fixture.invalid&type=ws"
                .to_owned(),
        },
        plan::ResidentNodeLinkShape {
            tag: "ffi-source".to_owned(),
            scheme: "ffi".to_owned(),
            link: "ffi://127.0.0.1:1".to_owned(),
        },
    ];

    reset_source_matrix_builder_calls();
    let rows = resident_expanded_source_matrix_rows(&fixture_config(), &nodes, &[]);

    assert_eq!(source_matrix_builder_calls(), 2);
    assert_eq!(candidate_occurrences(&rows, "vless-source"), 1);
    assert_eq!(candidate_occurrences(&rows, "trojan-source"), 1);

    let websocket = row(&rows, "stream-wrapper-websocket");
    let websocket_candidates = websocket["candidates"].as_array().unwrap();
    assert_eq!(
        websocket_candidates
            .iter()
            .map(|candidate| candidate["node_tag"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["vless-source", "trojan-source"]
    );
    assert!(
        websocket_candidates
            .iter()
            .all(|candidate| { candidate["group"].as_str() == Some("multi-protocol") })
    );
    assert_eq!(websocket["candidateEvaluation"], "per-node-materialization");
    assert_eq!(
        websocket["admitted_count"].as_u64().unwrap()
            + websocket["blocked_count"].as_u64().unwrap(),
        websocket["candidate_count"].as_u64().unwrap()
    );

    let rejected = row(&rows, "non-native-abi-outbound-shape");
    assert_eq!(rejected["planner_status"], "not-source-supported");
    assert_eq!(rejected["candidateEvaluation"], "source-policy-rejected");
    assert_no_candidates(rejected);
}
