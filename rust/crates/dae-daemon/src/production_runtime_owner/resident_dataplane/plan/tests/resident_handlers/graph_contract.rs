use super::*;
pub(super) fn assert_common_resident_graph_contracts(proxies: &[ResidentProxyPlan]) {
    for proxy in proxies {
        let graph = proxy.executable_graph_value();
        assert_eq!(graph["schemaVersion"], 1);
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
            "bounded-resident-packet-session"
        );
        assert_eq!(
            graph["runtimeComponents"]["probeExecutor"]["executor"],
            "resident-executable-graph"
        );
        assert!(
            graph["linkIdentity"]["linkHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        let graph_text = graph.to_string();
        for secret in ["user:password", ":password@", "auth-token"] {
            assert!(
                !graph_text.contains(secret),
                "graph leaked raw credential-bearing link: {graph}"
            );
        }
    }
}
