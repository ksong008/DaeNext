use super::*;
use serde_json::json;

pub(super) fn assert_stream_path_evidence(graph: &Value, expected_path: &str) {
    let expected_hash = if expected_path.is_empty() {
        Value::Null
    } else {
        json!(link_hash(expected_path))
    };
    for endpoint in [
        &graph["streamWrapperEndpoint"],
        &graph["runtimeComponents"]["streamWrapperFactory"]["endpoint"],
    ] {
        assert!(endpoint.get("path").is_none());
        let evidence = &endpoint["pathEvidence"];
        assert_eq!(evidence["present"], !expected_path.is_empty());
        assert_eq!(evidence["hash"], expected_hash);
        assert_eq!(evidence.as_object().unwrap().len(), 2);
    }
}

pub(super) fn assert_common_resident_graph_contracts(proxies: &[ResidentProxyPlan]) {
    for proxy in proxies {
        let graph = proxy.executable_graph_value();
        assert_eq!(graph["schemaVersion"], 2);
        assert_eq!(
            graph["runtimeComponents"]["streamWrapperFactory"]["schemaVersion"],
            2
        );
        assert!(
            graph["graphId"]
                .as_str()
                .unwrap()
                .starts_with("resident-graph:")
        );
        assert_eq!(graph["admission"]["status"], "admitted");
        assert_eq!(graph["chain"]["flattened"], false);
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["status"],
            "admitted"
        );
        assert_eq!(
            graph["runtimeComponents"]["streamWrapperFactory"]["status"],
            "admitted"
        );
        assert_eq!(
            graph["runtimeComponents"]["chainExecutor"]["executor"],
            "single-resident-graph"
        );
        assert_eq!(
            graph["runtimeComponents"]["generationCache"]["cacheScope"],
            "graph-and-reload-generation"
        );
        assert_eq!(
            graph["runtimeComponents"]["generationCache"]["materialized"],
            false
        );
        assert!(graph["runtimeComponents"]["generationCache"]["reloadGeneration"].is_null());
        let materialized = proxy.executable_graph_value_for_reload_generation(42);
        assert_eq!(proxy.runtime_component_evidence_value()["schemaVersion"], 2);
        assert_eq!(
            materialized["runtimeComponents"]["generationCache"]["reloadGeneration"],
            42
        );
        assert_eq!(
            materialized["runtimeComponents"]["generationCache"]["materialized"],
            true
        );
        assert_eq!(
            materialized["runtimeComponents"]["probeExecutor"]["reloadGeneration"],
            42
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["manager"],
            "resident-udp-session-manager"
        );
        assert_eq!(
            graph["runtimeComponents"]["probeExecutor"]["executor"],
            "resident-executable-graph"
        );
        let execution = proxy.execution_plan();
        assert_eq!(
            graph["transportUnderlay"],
            execution.security.transport_label()
        );
        assert_eq!(graph["securityUnderlay"], execution.security.graph_label());
        assert_eq!(graph["streamWrapper"], execution.wrapper.graph_label());
        assert_eq!(
            graph["packetSemantics"],
            graph["runtimeComponents"]["udpExecutionAgreement"]["packetSemantics"]
        );
        assert_eq!(
            graph["rawChildPacketSemantics"],
            execution.udp.packet_semantics().as_str()
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["executor"],
            execution.udp.executor_label()
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["status"],
            if execution.udp.policy_closed() {
                "fail-closed"
            } else {
                "admitted"
            }
        );
        let source_contract =
            &graph["runtimeComponents"]["udpExecutionAgreement"]["sourceContract"];
        assert_eq!(source_contract["schemaVersion"], 1);
        assert_eq!(
            &graph["runtimeComponents"]["packetSessionManager"]["sourceContract"],
            source_contract
        );
        assert_eq!(
            &graph["runtimeComponents"]["probeExecutor"]["udp"]["sourceContract"],
            source_contract
        );
        if execution.udp.policy_closed() {
            assert_eq!(source_contract["compatibilityMode"], "fail-closed");
            assert_eq!(source_contract["multiTargetMode"], "rejected-policy-closed");
        } else {
            assert_eq!(source_contract["compatibilityMode"], "strict-fixed-target");
            assert_eq!(source_contract["multiTargetMode"], "rejected-not-admitted");
            assert_eq!(
                source_contract["fixedTargetValidation"],
                "required-before-payload-consumption-or-forwarding"
            );
            assert_eq!(
                source_contract["replySource"],
                "validated-original-destination"
            );
        }
        assert!(
            graph["linkIdentity"]["linkHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            graph["linkIdentity"]["redactedSource"],
            format!(
                "{}:<redacted>",
                proxy
                    .redacted_link_source
                    .split_once(':')
                    .map(|(scheme, _)| scheme)
                    .unwrap_or("link")
            )
        );
        assert_stream_path_evidence(&graph, &proxy.stream_path);
        let graph_text = graph.to_string();
        if proxy.stream_path.len() > 1 {
            assert!(
                !graph_text.contains(&proxy.stream_path),
                "graph leaked raw stream path: {graph}"
            );
        }
        for secret in [
            format!("{}:{}", fixture_user(), fixture_secret()),
            format!(":{}@", fixture_secret()),
            fixture_client_id(),
        ] {
            assert!(
                !graph_text.contains(&secret),
                "graph leaked raw credential-bearing link: {graph}"
            );
        }
    }
}

#[test]
fn executable_graph_hashes_secret_xhttp_path_and_reports_only_field_names() {
    const SESSION_VALUE: &str = "private-session-value";
    const SEQ_VALUE: &str = "private-seq-value";
    const DATA_VALUE: &str = "private-data-value";
    const PADDING_VALUE: &str = "private-padding-value";
    const HEADER_VALUE: &str = "private-header-value";
    const FRAGMENT_VALUE: &str = "private-fragment-value";
    const PADDING_KEY_FIELD: &str = "padding_field";
    const PADDING_HEADER_FIELD: &str = "X-Padding-Field";
    const SESSION_FIELD: &str = "X-Session-Field";
    const SEQ_FIELD: &str = "sequence_field";
    const DATA_FIELD: &str = "X-Data-Field";

    let secret_path = format!("/{SESSION_VALUE}/{SEQ_VALUE}/{DATA_VALUE}/{PADDING_VALUE}");
    let extra = json!({
        "headers": {"X-Configured-Header": HEADER_VALUE},
        "xPaddingObfsMode": true,
        "xPaddingKey": PADDING_KEY_FIELD,
        "xPaddingHeader": PADDING_HEADER_FIELD,
        "xPaddingPlacement": "header",
        "sessionIDPlacement": "header",
        "sessionIDKey": SESSION_FIELD,
        "seqPlacement": "query",
        "seqKey": SEQ_FIELD,
        "uplinkDataPlacement": "header",
        "uplinkDataKey": DATA_FIELD,
    })
    .to_string();
    let mut link =
        VLESSLink::parse(&vless_xhttp_parser_fixture_url("packet-up", "h2", &extra)).unwrap();
    link.path = secret_path;
    link.ps = FRAGMENT_VALUE.to_owned();
    let proxy = build_resident_proxy_plan_for_node(
        &resident_tcp_handler_config(),
        "proxy".to_owned(),
        "xhttp_path_redaction".to_owned(),
        link.export_url(),
    )
    .unwrap();
    let graph = proxy.executable_graph_value();

    assert_stream_path_evidence(&graph, &proxy.stream_path);
    let graph_text = graph.to_string();
    for secret in [
        SESSION_VALUE,
        SEQ_VALUE,
        DATA_VALUE,
        PADDING_VALUE,
        HEADER_VALUE,
        FRAGMENT_VALUE,
    ] {
        assert!(
            !graph_text.contains(secret),
            "graph leaked {secret}: {graph}"
        );
    }

    let evidence =
        &graph["runtimeComponents"]["streamWrapperFactory"]["xhttpExtendedSettings"]["primary"];
    assert_eq!(evidence["xPadding"]["keyFieldName"], PADDING_KEY_FIELD);
    assert_eq!(
        evidence["xPadding"]["headerFieldName"],
        PADDING_HEADER_FIELD
    );
    assert_eq!(evidence["metadata"]["sessionIDFieldName"], SESSION_FIELD);
    assert_eq!(evidence["metadata"]["seqFieldName"], SEQ_FIELD);
    assert_eq!(evidence["uplink"]["dataFieldName"], DATA_FIELD);
    assert!(evidence["xPadding"].get("key").is_none());
    assert!(evidence["xPadding"].get("header").is_none());
    assert!(evidence["metadata"].get("sessionIDKey").is_none());
    assert!(evidence["metadata"].get("seqKey").is_none());
    assert!(evidence["uplink"].get("dataKey").is_none());
    assert_eq!(evidence["headers"]["valuesRedacted"], true);
}
