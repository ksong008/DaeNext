use super::*;

pub(super) fn stage98_report(opts: &Stage98Options) -> Value {
    let grpc_options = opts.grpc_options();
    let mut report = json!({
        "name": "stage98-trojan-go-grpc-cache-cancellation-admission",
        "stage": "stage98",
        "evidence_class": "opt-in-protocol-trojan-go-grpc-cache-cleanup-cancellation-stress",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["socks5_protocol_true_dataplane_admitted"] = json!(true);
    report["http_connect_true_dataplane_admitted"] = json!(true);
    report["https_proxy_true_dataplane_admitted"] = json!(true);
    report["shadowsocks_protocol_true_dataplane_admitted"] = json!(true);
    report["trojan_protocol_true_dataplane_admitted"] = json!(true);
    report["trojan_go_wss_admitted"] = json!(true);
    report["trojan_go_httpupgrade_admitted"] = json!(true);
    report["trojan_go_grpc_hunk_admitted"] = json!(true);
    report["trojan_go_inner_shadowsocks_admitted"] = json!(true);
    report["trojan_go_grpc_http2_tls_lifecycle_admitted"] = json!(true);
    report["trojan_go_grpc_cache_cancellation_stress_passed"] = json!(false);
    report["trojan_go_grpc_cache_cleanup_admitted"] = json!(false);
    report["trojan_go_grpc_cancellation_stress_admitted"] = json!(false);
    report["trojan_go_shared_transport_partial_admitted"] = json!(true);
    report["trojan_go_shared_transport_admitted"] = json!(false);
    report["shared_transport_true_dataplane_admitted"] = json!(false);
    report["protocol_outbound_partial_admitted"] = json!(true);
    report["outbound_true_dataplane_admitted"] = json!(false);
    report["matched_go_rust_default_daemon_benchmark_recorded"] = json!(false);
    report["default_switch_allowed"] = json!(false);
    report["default_path_mutation_allowed"] = json!(false);
    report["product_chain_switch_allowed"] = json!(false);
    report["true_rust_default_daemon_admitted"] = json!(false);
    report["go_default_path_preserved"] = json!(true);
    report["go_fallback_required"] = json!(true);
    report["grpc_cache_contract"] = json!({
        "protocol": "trojan-go",
        "transport": "grpc",
        "scope": "global gRPC ClientConn cache key, clean hook, per-key canceller semantics, and detached stream cancellation stress",
        "grpc_address": opts.grpc_address,
        "grpc_service_name": opts.grpc_service_name,
        "grpc_server_name": opts.grpc_server_name,
        "grpc_dialer_id": opts.grpc_dialer_id,
        "grpc_allow_insecure": opts.allow_insecure,
        "requested_mark": opts.so_mark,
        "requested_mptcp": opts.mptcp,
        "base_cache_key": grpc_options.cache_key(),
        "sample_cache_keys": [],
        "same_key_reused": false,
        "server_name_splits_key": false,
        "allow_insecure_splits_key": false,
        "mark_splits_key": false,
        "mptcp_splits_key": false,
        "cleanup_closed_live_entries": false,
        "cleanup_zeroed_live_entries": false,
        "refill_after_cleanup_not_reused": false,
        "clean_hook_idempotent": false,
        "max_live_entries": null,
        "cleaned_entries_total": null,
        "closed_entries_total": null,
        "parent_cancel_propagates_before_stop_following": false,
        "parent_cancel_ignored_after_stop_following": false,
        "stream_close_cancels": false,
        "stream_close_idempotent": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_grpc_cache_cancellation_stress_iteration": null,
        "scope": "in-memory gRPC cache key split/reuse/cleanup/refill plus detached stream cancellation model stress",
        "network_dataplane_benchmark": false,
        "stage97_http2_tls_dataplane_benchmark_carried": "48361973.9 ns/op"
    });
    report["protocol_matrix"] = json!({
        "trojan_go_grpc_http2_tls_lifecycle_admitted": true,
        "trojan_go_grpc_cache_cleanup_admitted": false,
        "trojan_go_grpc_cancellation_stress_admitted": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go uTLS fingerprint, REALITY, TLS fragment, and cross-combination recertification are still deferred",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage98/trojan_go_grpc_cache_cancellation_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage98_trojan_go_grpc_cache_cancellation_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage98 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage98 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage98 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage98-trojan-go-grpc-cache-cancellation-admission --execute-smoke --benchmark-iters 1000",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage98",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/transport/grpc/grpc_client.go",
        "/root/project/outbound/transport/grpc/grpc_client_test.go",
        "rust/crates/dae-outbound/src/shared_transport/grpc_cache.rs",
        "rust/crates/dae-outbound/src/shared_transport/grpc.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }

    let start = Instant::now();
    let stress = shared_transport::grpc_cache_cleanup_cancellation_stress(
        &grpc_options,
        opts.benchmark_iters,
    );
    let elapsed_ns = start.elapsed().as_nanos();
    let detached = &stress.detached_stream_cancellation;
    let passed = stress.same_key_reused
        && stress.server_name_splits_key
        && stress.allow_insecure_splits_key
        && stress.mark_splits_key
        && stress.mptcp_splits_key
        && stress.cleanup_closed_live_entries
        && stress.cleanup_zeroed_live_entries
        && stress.refill_after_cleanup_not_reused
        && stress.clean_hook_idempotent
        && stress.cleaned_entries_total == stress.closed_entries_total
        && detached.parent_cancel_propagates_before_stop_following
        && detached.parent_cancel_ignored_after_stop_following
        && detached.stream_close_cancels
        && detached.stream_close_idempotent;

    report["read_only"] = json!(false);
    report["trojan_go_grpc_cache_cancellation_stress_passed"] = json!(passed);
    report["trojan_go_grpc_cache_cleanup_admitted"] = json!(passed);
    report["trojan_go_grpc_cancellation_stress_admitted"] = json!(passed);
    report["grpc_cache_contract"]["sample_cache_keys"] = json!(stress.sample_cache_keys);
    report["grpc_cache_contract"]["same_key_reused"] = json!(stress.same_key_reused);
    report["grpc_cache_contract"]["server_name_splits_key"] = json!(stress.server_name_splits_key);
    report["grpc_cache_contract"]["allow_insecure_splits_key"] =
        json!(stress.allow_insecure_splits_key);
    report["grpc_cache_contract"]["mark_splits_key"] = json!(stress.mark_splits_key);
    report["grpc_cache_contract"]["mptcp_splits_key"] = json!(stress.mptcp_splits_key);
    report["grpc_cache_contract"]["cleanup_closed_live_entries"] =
        json!(stress.cleanup_closed_live_entries);
    report["grpc_cache_contract"]["cleanup_zeroed_live_entries"] =
        json!(stress.cleanup_zeroed_live_entries);
    report["grpc_cache_contract"]["refill_after_cleanup_not_reused"] =
        json!(stress.refill_after_cleanup_not_reused);
    report["grpc_cache_contract"]["clean_hook_idempotent"] = json!(stress.clean_hook_idempotent);
    report["grpc_cache_contract"]["max_live_entries"] = json!(stress.max_live_entries);
    report["grpc_cache_contract"]["cleaned_entries_total"] = json!(stress.cleaned_entries_total);
    report["grpc_cache_contract"]["closed_entries_total"] = json!(stress.closed_entries_total);
    report["grpc_cache_contract"]["parent_cancel_propagates_before_stop_following"] =
        json!(detached.parent_cancel_propagates_before_stop_following);
    report["grpc_cache_contract"]["parent_cancel_ignored_after_stop_following"] =
        json!(detached.parent_cancel_ignored_after_stop_following);
    report["grpc_cache_contract"]["stream_close_cancels"] = json!(detached.stream_close_cancels);
    report["grpc_cache_contract"]["stream_close_idempotent"] =
        json!(detached.stream_close_idempotent);
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(elapsed_ns);
    report["benchmark"]["ns_per_grpc_cache_cancellation_stress_iteration"] =
        json!(elapsed_ns as f64 / opts.benchmark_iters as f64);
    report["benchmark"]["max_live_entries"] = json!(stress.max_live_entries);
    report["benchmark"]["cleaned_entries_total"] = json!(stress.cleaned_entries_total);
    report["protocol_matrix"]["trojan_go_grpc_cache_cleanup_admitted"] = json!(passed);
    report["protocol_matrix"]["trojan_go_grpc_cancellation_stress_admitted"] = json!(passed);
    report
}
