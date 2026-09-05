//! Deliberate host adapter surface; new domain exports require review.

/// Curated core contracts consumed by the daemon host adapter.
pub mod core {
    pub use dae_product_core::{
        DEFAULT_GLOBAL_RESOURCE_TEXT, DEFAULT_PRODUCT_CONFIG_NAME, DEFAULT_PRODUCT_CONTROL_SOCKET,
        DEFAULT_PRODUCT_DNS_NAME, DEFAULT_PRODUCT_GROUP_NAME, DEFAULT_PRODUCT_GROUP_POLICY,
        DEFAULT_PRODUCT_MODE, DEFAULT_PRODUCT_ROUTING_NAME, DaedProductOutput, GROUP_POLICY_FIXED,
        GROUP_POLICY_MIN, GROUP_POLICY_MIN_MOVING_AVG, PRODUCT_CONTROL_SOCKET_ENV,
        PRODUCT_HTTP_LOW_MEMORY_QUEUE_DEFAULT, PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MAX,
        PRODUCT_HTTP_LOW_MEMORY_WORKER_DEFAULT_MIN,
        PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT, PRODUCT_HTTP_PROFILE_ENV,
        PRODUCT_HTTP_PROFILE_LOW_MEMORY, PRODUCT_HTTP_PROFILE_STANDARD, PRODUCT_HTTP_QUEUE_DEFAULT,
        PRODUCT_HTTP_QUEUE_ENV, PRODUCT_HTTP_QUEUE_MAX, PRODUCT_HTTP_QUEUE_MIN,
        PRODUCT_HTTP_WORKER_DEFAULT_MAX, PRODUCT_HTTP_WORKER_DEFAULT_MIN, PRODUCT_HTTP_WORKER_MAX,
        PRODUCT_HTTP_WORKER_MIN, PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT,
        PRODUCT_HTTP_WORKER_STACK_BYTES_ENV, PRODUCT_HTTP_WORKER_STACK_BYTES_MAX,
        PRODUCT_HTTP_WORKER_STACK_BYTES_MIN, PRODUCT_HTTP_WORKERS_ENV, ProcessCpuTracker,
        ProcessMetrics, ProductHttpProfile, ProductHttpWorkerConfig, ProductPackageContext,
        ProductShutdown, ProductShutdownWakeHook, RUNTIME_PROBE_GENERATION_METADATA_KEY,
        RuntimeNodeTag, SectionKind, docker_entrypoint_text, help_text, hex_encode, hex_value,
        path_string, process_metrics_lifetime_snapshot, process_status_metrics_from_str,
        product_iso8601_utc, product_now_text, runtime_node_tag, systemd_unit_text, unix_now,
    };
}
/// Curated geodata contracts consumed by the daemon host adapter.
pub mod geodata {
    pub use dae_product_geodata::{
        GEODATA_HELPER_MAX_REQUEST_BYTES, GEODATA_REDIRECT_LIMIT, GEOIP_FILE, GEOSITE_FILE,
        GeodataCommitResult, GeodataFileDownload, GeodataHelperRequest, GeodataHttpFileResult,
        GeodataHttpResult, GeodataJournalPhase, GeodataKind, GeodataPreparationMode,
        GeodataPreparedDownload, GeodataRelease, GeodataResourceIdentity, GeodataSourceMode,
        GeodataSourceUrlUpdate, GeodataStatusCache, GeodataStatusCacheEntry,
        GeodataTransactionCheckpoint, GeodataUpdateCallbacks, GeodataUpdateJournal,
        GeodataUpdateRuntimeContext, PreparedGeodataGeneration, ProductGeodataUpdateCoordinator,
        ProductGeodataUpdateJob, ProductGeodataUpdateLease, ProductGeodataUpdateRuntime,
        ProductGeodataUpdateRuntimeConfig, ProductGeodataUpdateSubmissionError,
        ProductGeodataUpdateSubmissionReason, ProductGeodataUpdateWorker,
        ProductGeodataUpdateWorkerHooks, RuntimeInputVersions,
        commit_geodata_generation_with_checkpoints, decode_geodata_helper_request,
        encode_geodata_helper_failure, encode_geodata_helper_success, geodata_dir_for_web_root,
        geodata_http_body, geodata_http_request, geodata_http_response_limit,
        geodata_http_response_to_file_from_bytes, geodata_resource_status, geodata_source,
        geodata_source_status, geodata_sources_status, parse_geodata_latest_release,
        prepare_geodata_with_helper, read_geodata_http_response,
        read_geodata_http_response_to_file, read_runtime_input_versions,
        recover_geodata_transaction, reset_geodata_source_url, set_geodata_source_url,
        set_geodata_source_use_proxy, sha256_file, summarize_geodata_file,
        update_geodata_source_settings, update_geodata_with_lease_using, write_geodata_journal,
    };
}
/// Curated http contracts consumed by the daemon host adapter.
pub mod http {
    pub use dae_product_http::{
        DAE_BUNDLE_IMPORT_PATH, HttpRequest, HttpRequestReadError, HttpRequestReadErrorKind,
        HttpRequestReadPolicy, HttpResponse, LISTENER_SHUTDOWN_CHECK_INTERVAL, MAX_BODY_BYTES,
        MAX_BUNDLE_BODY_BYTES, MAX_HTTP_HEADER_BYTES, MAX_HTTP_HEADER_COUNT,
        PRODUCT_HTTP_REJECT_WRITE_TIMEOUT, ProductHttpConnectionRegistry, ProductHttpJobQueue,
        ProductHttpMetrics, ProductHttpQueueReceiveError, ProductHttpQueueSendError,
        ProductHttpRequestContext, ProductHttpRequestReadMetrics, ProductPprofRuntime,
        ProductUiReclaimHooks, ProductUiReclaimWorker, ProductUiRuntime, ProductUiStreamLease,
        allowed_cors_origin, allowed_cors_origin_value, find_subsequence,
        http_request_read_error_response, integer_array, json_body, product_openapi_skeleton,
        query_bool, query_u64, query_usize, read_http_request, read_http_request_with_policy,
        required_str, serve_static_file, split_path_query, status_reason, string_array,
        wait_for_listener_readiness, webui_route_audit_report, write_http_response,
        write_http_response_for_request, write_http_response_with_timeout,
        write_static_file_response,
    };
}
/// Curated identity contracts consumed by the daemon host adapter.
pub mod identity {
    pub use dae_product_identity::{
        DAEMON_CRATE_NAME, DAEMON_MANIFEST, PRODUCT_BINARY_NAME, daemon_identity, hash_password,
        hmac_sha256, legacy_password_hash_for_test, random_secret_hex, validate_password_strength,
        verify_password_hash,
    };
}
/// Curated persistence contracts consumed by the daemon host adapter.
pub mod persistence {
    pub use dae_product_persistence::{
        FaultCheckpoints, NoopFaultCheckpoints, ProductUserRecord, RunningRuntimeState,
        RuntimeDesiredStateRevision, RuntimeSectionState, STATE_DB_BUSY_TIMEOUT,
        STATE_SCHEMA_VERSION, apply_state_schema, bump_runtime_external_input_version,
        bump_runtime_geodata_input_version_with_connection, count_table, create_synced_file,
        current_runtime_external_input_version, current_runtime_geodata_input_version,
        ensure_state_schema, get_metadata, group_ids_text, group_version_sum,
        inspect_state_connection_read_only, load_user_by_username, migrate_wing_db,
        open_state_connection, open_state_connection_read_only, query_json_storage,
        remove_json_storage, running_runtime_state, runtime_desired_state_revision_from_connection,
        save_json_storage, selected_id, selected_section_state, set_json_storage, set_metadata,
        sha256_file_hex, sqlite_io_error, state_check_report, state_schema_version, sync_directory,
        user_resource, validate_state_connection_read_only,
    };
    #[cfg(feature = "test-support")]
    pub use dae_product_persistence::{
        ensure_state_schema_with_precommit_failure, load_user_by_id,
        reset_user_query_count_for_current_thread, user_query_count_for_current_thread,
    };
}
/// Curated runtime contracts consumed by the daemon host adapter.
pub mod runtime {
    pub use dae_product_runtime::{
        CoordinatedRuntimeReloadError, PreparedRuntimeGeneration, ProductRuntimeDomain,
        ProductRuntimeEventIdentity, ProductRuntimeLifecycleLogMode, ProductRuntimeReadSnapshot,
        ProductRuntimeReconcileAdmission, ProductRuntimeReconcileRequest, ProductRuntimeReconciler,
        ProductRuntimeState, RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY,
        RUNTIME_GENERATION_METADATA_KEY, RUNTIME_PROBE_GENERATION_METADATA_KEY,
        RUNTIME_PROCESS_TRANSITION_METADATA_KEY, RuntimeActivationIdentity, RuntimeApplyCheckpoint,
        RuntimeApplyCoordinator, RuntimeApplyIntent, RuntimeApplyPermit, RuntimeApplyState,
        RuntimeCleanupState, RuntimeDesiredStateRevision, RuntimeMaterializationPlan,
        RuntimeOverviewDeltaState, RuntimeReadBackend, RuntimeReloadPrepareError,
        RuntimeStartOutcome, RuntimeStopPermit, RuntimeTrafficAvailability, RuntimeTrafficCarry,
        RuntimeTrafficObservation, RuntimeTrafficRateSample, RuntimeTrafficRead,
        RuntimeTrafficStats, RuntimeTrafficTotalSample, RuntimeTransitionClass,
        RuntimeTransitionIdentity, apply_runtime_materialization_plan,
        build_runtime_config_from_content, cgroup_memory_snapshot_json,
        classify_runtime_transition, commit_runtime_state, display_global_config_text,
        materialize_runtime, normalize_global_result, normalize_global_value,
        persist_recovered_runtime_identity, prepare_runtime_apply_transaction,
        prepare_runtime_generation, prepare_runtime_materialization_plan,
        prepare_runtime_materialization_plan_with_connection,
        prepare_runtime_materialization_plan_with_modified_state, process_transition_for_config,
        recover_runtime_apply_transaction, render_dns_section, render_generated_config,
        render_global_config_text, render_routing_section, resident_runtime_traffic_stats,
        resource_pool_policy_json, restore_runtime_database,
        runtime_desired_state_revision_from_connection, runtime_health_seed_snapshots,
        runtime_modified, runtime_node_tag, runtime_traffic_observation,
        runtime_traffic_stats_from_history, sync_directory,
    };
    #[cfg(feature = "benchmark-support")]
    pub use dae_product_runtime::{
        ProductGlobalNormalizeBenchmarkFixture, product_global_normalize_benchmark_fixture,
    };
}
/// Curated subscription contracts consumed by the daemon host adapter.
pub mod subscription {
    pub use dae_product_subscription::{
        FetchedSubscriptionContent, InvalidCronLogTracker, LatencyJobAdmissionKind,
        LatencyJobCancelError, LatencyJobCancellation, LatencyJobManager, LatencyJobRunOutcome,
        LatencyProbeNode, LatencyProbeSeenLinks, NODE_LATENCY_DB_WRITE_BATCH_SIZE,
        NewSubscriptionRecord, NodeLatencyWrite, PreparedSubscriptionNode,
        PreparedSubscriptionNodes, PreparedSubscriptionRefresh, RejectedSubscriptionNode,
        RuntimeNodeLatencyIndex, RuntimeNodeTag, SUBSCRIPTION_HELPER_MAX_REQUEST_BYTES,
        SUBSCRIPTION_MAX_BYTES, SubscriptionCommitResult, SubscriptionContentReport,
        SubscriptionHelperOutcome, SubscriptionHelperRequest, SubscriptionHttpResponse,
        SubscriptionMutationError, SubscriptionRecordUpdate, SubscriptionRefreshCallbacks,
        SubscriptionRefreshFetch, SubscriptionRefreshOutcome, SubscriptionRefreshPersist,
        SubscriptionRefreshPersistContent, SubscriptionRuntimeApplyResult,
        SubscriptionSchedulerCallbacks, SubscriptionSchedulerHandle,
        SubscriptionSchedulerRuntimeApply, SubscriptionSourceIdentity, apply_group_node_ids,
        apply_prepared_subscription_refresh_report, cancel_node_latency_job_value,
        count_nodes_for_subscription, create_subscription_record, current_latency_probe_nodes,
        decode_chunked_body, decode_chunked_body_with_limit, decode_node_label,
        decode_subscription_helper_request, delete_subscription, delete_subscriptions_by_ids,
        encode_subscription_helper_failure, encode_subscription_helper_success, fetch_error,
        first_header, get_group_value, get_node_value, get_subscription_value,
        http_response_body_with_limit, is_subscription_redirect, latency_probe_link_chunks,
        latency_probe_nodes_for_ids, latency_probe_nodes_for_links,
        latency_probe_unique_link_count, latency_probe_unique_links, list_all_nodes_value,
        list_groups_value, list_nodes_value, list_stored_node_latencies_value,
        list_subscriptions_value, node_latency_results_for_runtime_snapshots, node_name_from_link,
        notify_subscription_scheduler, parse_node_link, parse_subscription_content,
        parse_subscription_http_response, persist_subscription_path,
        prepare_subscription_with_helper, read_subscription_file,
        read_subscription_http_response_with_limit, refresh_due_subscriptions_with_callbacks,
        refresh_subscription_from_remote_with_callbacks, replace_prepared_subscription_nodes,
        run_latency_job, runtime_execution_identity, runtime_link_hash,
        runtime_link_identity_value, runtime_node_latency_results_for_nodes,
        runtime_redacted_link_source, start_subscription_scheduler, store_node_latency_result,
        stored_successful_node_latency_seed_snapshots, subscription_file_path,
        subscription_http_request, subscription_http_response_limit,
        subscription_import_response_value, subscription_links_from_content,
        subscription_source_by_id, subscription_url_with_scheme, update_subscription_record,
        validate_subscription_cron_expression, write_node_latency_results,
        write_persisted_subscription,
    };
}
