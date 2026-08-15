use super::*;
use base64::Engine;

#[test]
fn expanded_source_matrix_keeps_report_only_rows_out_of_per_node_admission() {
    let nodes = vec![plan::ResidentNodeLinkShape {
        tag: "vless-source".to_owned(),
        scheme: "vless".to_owned(),
        link: "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@vless.fixture.invalid:443?allowInsecure=0&host=front.fixture.invalid&path=%2Fws&security=tls&sni=front.fixture.invalid&type=ws"
            .to_owned(),
    }];

    reset_source_matrix_builder_calls();
    let rows = resident_expanded_source_matrix_rows(&fixture_config(), &nodes, &[]);

    assert_eq!(source_matrix_builder_calls(), 1);

    let aggregate = row(&rows, "stream-wrapper-meek");
    assert_eq!(
        aggregate["planner_status"],
        PLANNER_STATUS_AGGREGATE_REPORT_ONLY
    );
    assert_eq!(aggregate["candidateEvaluation"], "aggregate-report-only");
    assert!(aggregate["capabilityReasonId"].is_null());
    assert_no_candidates(aggregate);
    assert_no_classified_candidates(aggregate);

    let deferred = row(&rows, "passthrough-udp-transport");
    assert_eq!(deferred["planner_status"], PLANNER_STATUS_BLOCKED_DEFERRED);
    assert_eq!(deferred["candidateEvaluation"], "deferred-row-blocker");
    assert_eq!(deferred["capabilityReasonId"], deferred["blockerId"]);
    assert_no_candidates(deferred);
    assert_no_classified_candidates(deferred);

    let counts = resident_matrix_status_counts(&rows);
    assert!(
        counts[PLANNER_STATUS_AGGREGATE_REPORT_ONLY]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        counts[PLANNER_STATUS_BLOCKED_DEFERRED]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
}

#[test]
fn expanded_source_matrix_does_not_misreport_classified_deferred_source() {
    let decoded = "auto:7c12c745-63a5-433d-9e60-022e469b5bd4@vmess.fixture.invalid:443";
    let source = format!(
        "vmess://{}?alterId=0&obfs=tcp",
        base64::engine::general_purpose::STANDARD.encode(decoded)
    );
    let nodes = vec![plan::ResidentNodeLinkShape {
        tag: "legacy-vmess-source".to_owned(),
        scheme: "vmess".to_owned(),
        link: source,
    }];

    reset_source_matrix_builder_calls();
    let rows = resident_expanded_source_matrix_rows(&fixture_config(), &nodes, &[]);

    assert_eq!(source_matrix_builder_calls(), 1);
    assert_eq!(candidate_occurrences(&rows, "legacy-vmess-source"), 0);
    let deferred = row(&rows, "legacy-layer-shape");
    assert_eq!(deferred["planner_status"], PLANNER_STATUS_BLOCKED_DEFERRED);
    assert_eq!(deferred["candidateEvaluation"], "deferred-row-blocker");
    assert_no_candidates(deferred);
    assert_eq!(deferred["classifiedCandidateCount"], 1);
    assert_eq!(deferred["classifiedCurrentConfigStatus"], "present");
    let classified = &deferred["classifiedCandidates"][0];
    assert_eq!(classified["nodeTag"], "legacy-vmess-source");
    assert_eq!(classified["nodeTagSource"], "explicit-display-tag");
    assert_eq!(classified["scheme"], "vmess");
    assert_eq!(classified["disposition"], "deferred-capability");
    assert_eq!(classified["contributesProductionWitness"], false);
    assert!(
        classified["nodeIdentity"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("sha256:"))
    );
}

#[test]
fn expanded_source_matrix_observes_extended_xhttp_without_admitting_it() {
    let source = "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@vless.fixture.invalid:443?alpn=h2&allowInsecure=0&extra=%7B%22headers%22%3A%7B%22X-Secret%22%3A%22classified-secret%22%7D%7D&mode=packet-up&security=tls&sni=front.fixture.invalid&type=xhttp";
    let nodes = vec![plan::ResidentNodeLinkShape {
        tag: "extended-xhttp-source".to_owned(),
        scheme: "vless".to_owned(),
        link: source.to_owned(),
    }];

    reset_source_matrix_builder_calls();
    let rows = resident_expanded_source_matrix_rows(&fixture_config(), &nodes, &[]);

    assert_eq!(source_matrix_builder_calls(), 1);
    assert_eq!(candidate_occurrences(&rows, "extended-xhttp-source"), 0);
    let aggregate = row(&rows, "xhttp-extended-settings-wrapper");
    assert_eq!(
        aggregate["planner_status"],
        PLANNER_STATUS_BLOCKED_AGGREGATE_REPORT_ONLY
    );
    assert_eq!(
        aggregate["candidateEvaluation"],
        "blocked-aggregate-classification"
    );
    assert_eq!(
        aggregate["blockerId"],
        "extended-xhttp-shape-not-exactly-classified"
    );
    assert_eq!(
        aggregate["capabilityReasonId"],
        "extended-xhttp-shape-not-exactly-classified"
    );
    assert_no_candidates(aggregate);
    assert_eq!(aggregate["classifiedCandidateCount"], 1);
    assert_eq!(aggregate["classifiedCurrentConfigStatus"], "present");
    assert_eq!(
        aggregate["classifiedCandidates"][0]["disposition"],
        "aggregate-capability"
    );
    let rendered = serde_json::to_string(aggregate).unwrap();
    assert!(!rendered.contains("classified-secret"));
    assert!(!rendered.contains(source));
}

#[test]
fn composed_aggregate_observes_an_exactly_admitted_component() {
    let nodes = vec![plan::ResidentNodeLinkShape {
        tag: "vless-meek-source".to_owned(),
        scheme: "vless".to_owned(),
        link: "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@vless.fixture.invalid:443?security=tls&sni=front.fixture.invalid&type=meek&url=https%3A%2F%2Ffront.fixture.invalid%2Fmeek"
            .to_owned(),
    }];

    reset_source_matrix_builder_calls();
    let rows = resident_expanded_source_matrix_rows(&fixture_config(), &nodes, &[]);

    assert_eq!(source_matrix_builder_calls(), 1);
    let exact = row(&rows, "vless-meek-tls-stream-wrapper");
    assert_eq!(exact["planner_status"], "admitted");
    assert_eq!(exact["candidate_count"], 1);
    assert_eq!(exact["admitted_count"], 1);

    let aggregate = row(&rows, "stream-wrapper-meek");
    assert_eq!(
        aggregate["planner_status"],
        PLANNER_STATUS_AGGREGATE_REPORT_ONLY
    );
    assert_no_candidates(aggregate);
    assert_eq!(aggregate["classifiedCandidateCount"], 1);
    assert_eq!(aggregate["classifiedCurrentConfigStatus"], "present");
    assert_eq!(
        aggregate["classifiedCandidates"][0]["nodeTag"],
        "vless-meek-source"
    );
    assert_eq!(
        aggregate["classifiedCandidates"][0]["contributesProductionWitness"],
        false
    );
}
