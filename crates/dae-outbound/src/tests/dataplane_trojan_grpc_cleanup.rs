use crate::shared_transport::{GrpcLifecycleOptions, grpc_cache_cleanup_cancellation_stress};

#[test]
fn case_grpc_cache_cleanup_and_cancellation_stress_matches_native_contract() {
    let base = GrpcLifecycleOptions::new(
        "fixture-grpc-proxy.fixture.invalid:443",
        "GunService",
        "fixture-grpc-sni.fixture.invalid",
        "fixture-dialer",
        true,
        1234,
        true,
    );
    let report = grpc_cache_cleanup_cancellation_stress(&base, 8);

    assert_eq!(report.iterations, 8);
    assert!(report.same_key_reused);
    assert!(report.server_name_splits_key);
    assert!(report.allow_insecure_splits_key);
    assert!(report.mark_splits_key);
    assert!(report.mptcp_splits_key);
    assert!(report.cleanup_closed_live_entries);
    assert!(report.cleanup_zeroed_live_entries);
    assert!(report.refill_after_cleanup_not_reused);
    assert!(report.clean_hook_idempotent);
    assert_eq!(report.max_live_entries, 5);
    assert_eq!(report.cleaned_entries_total, 48);
    assert_eq!(report.closed_entries_total, 48);
    assert_eq!(report.sample_cache_keys.len(), 5);
    assert!(report.sample_cache_keys[0].contains("fixture-grpc-proxy.fixture.invalid:443"));
    assert!(report.sample_cache_keys[0].contains("fixture-grpc-sni.fixture.invalid"));
    assert_ne!(report.sample_cache_keys[0], report.sample_cache_keys[3]);
    assert_ne!(report.sample_cache_keys[0], report.sample_cache_keys[4]);

    let detached = report.detached_stream_cancellation;
    assert!(detached.parent_cancel_propagates_before_stop_following);
    assert!(detached.parent_cancel_ignored_after_stop_following);
    assert!(detached.stream_close_cancels);
    assert!(detached.stream_close_idempotent);
}
