use super::support::{FreshProductState, RuntimeFaultFixture, RuntimeFaultPoint};
use super::*;

struct CommittedRuntimeFixture {
    product: FreshProductState,
    config_dir: PathBuf,
    runtime: ProductRuntimeManager,
    generated_content: Vec<u8>,
    running_state: RunningRuntimeState,
    generation: String,
    tproxy_port: u16,
    log_level: String,
}

impl CommittedRuntimeFixture {
    fn new(scope: &str) -> Self {
        let product = FreshProductState::new(scope);
        product.seed_selected_resources();
        let config_dir = product.root().join("config");
        let runtime = ProductRuntimeManager::new();
        let prepared = prepare_runtime_reload_config(product.state()).unwrap();
        let mut checkpoints = NoopRuntimeApplyCheckpoints;
        apply_runtime_generation(
            &runtime,
            product.state(),
            Some(&config_dir),
            "runtime-generation-test",
            prepared,
            &[],
            &mut checkpoints,
        )
        .unwrap();
        let generated_content = fs::read(config_dir.join("runtime/generated.dae")).unwrap();
        let conn = product.connection();
        let running_state = running_runtime_state(&conn).unwrap().unwrap();
        let generation = get_metadata(product.state(), "runtime_generation_id")
            .unwrap()
            .unwrap();
        let tproxy_port = runtime.current_config().unwrap().global.tproxy_port;
        let log_level = current_runtime_log_level(product.state()).unwrap();
        Self {
            product,
            config_dir,
            runtime,
            generated_content,
            running_state,
            generation,
            tproxy_port,
            log_level,
        }
    }

    fn prepare_changed_generation(&self) -> PreparedRuntimeReload {
        self.product
            .connection()
            .execute(
                "UPDATE configs
                 SET global = 'global { tproxy_port: 23456 log_level: debug }', version = version + 1
                 WHERE selected = 1",
                [],
            )
            .unwrap();
        prepare_runtime_reload_config(self.product.state()).unwrap()
    }

    fn assert_previous_generation_is_intact(&self) {
        assert!(self.runtime.is_running());
        assert_eq!(
            self.runtime.current_config().unwrap().global.tproxy_port,
            self.tproxy_port
        );
        assert_eq!(
            fs::read(self.config_dir.join("runtime/generated.dae")).unwrap(),
            self.generated_content
        );
        assert_eq!(
            running_runtime_state(&self.product.connection())
                .unwrap()
                .unwrap(),
            self.running_state
        );
        assert_eq!(
            get_metadata(self.product.state(), "runtime_generation_id")
                .unwrap()
                .as_deref(),
            Some(self.generation.as_str())
        );
        assert_eq!(
            current_runtime_log_level(self.product.state()).unwrap(),
            self.log_level
        );
        assert_no_staged_runtime_files(&self.config_dir);
    }
}

fn assert_no_staged_runtime_files(config_dir: &Path) {
    let runtime_dir = config_dir.join("runtime");
    let names = fs::read_dir(runtime_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        names
            .iter()
            .all(|name| !name.ends_with(".candidate") && !name.ends_with(".rollback")),
        "staged runtime files remain: {names:?}"
    );
}

#[test]
fn runtime_generation_prepare_faults_leave_running_generation_untouched() {
    with_product_runtime_fake_start_override(true, || {
        for point in [
            RuntimeFaultPoint::CreateDirectory,
            RuntimeFaultPoint::WriteCandidate,
            RuntimeFaultPoint::SyncCandidate,
        ] {
            let fixture = CommittedRuntimeFixture::new(point.as_str());
            let prepared = fixture.prepare_changed_generation();
            let mut faults = RuntimeFaultFixture::default();
            faults.fail_next(point);

            let error = apply_runtime_generation(
                &fixture.runtime,
                fixture.product.state(),
                Some(&fixture.config_dir),
                "runtime-generation-test",
                prepared,
                &[],
                &mut faults,
            )
            .unwrap_err();

            assert!(error.contains(point.as_str()), "{error}");
            fixture.assert_previous_generation_is_intact();
            let summary = fixture.runtime.summary();
            assert_eq!(summary["apply"]["phase"], json!("prepare"));
            assert_eq!(summary["apply"]["reconciliationRequired"], json!(false));
        }
    });
}

#[test]
fn runtime_generation_activation_fault_does_not_replace_running_generation() {
    with_product_runtime_fake_start_override(true, || {
        let fixture = CommittedRuntimeFixture::new("activation-fault");
        let prepared = fixture.prepare_changed_generation();
        let mut faults = RuntimeFaultFixture::default();
        faults.fail_next(RuntimeFaultPoint::StartCandidate);

        let error = apply_runtime_generation(
            &fixture.runtime,
            fixture.product.state(),
            Some(&fixture.config_dir),
            "runtime-generation-test",
            prepared,
            &[],
            &mut faults,
        )
        .unwrap_err();

        assert!(error.contains(RuntimeFaultPoint::StartCandidate.as_str()));
        fixture.assert_previous_generation_is_intact();
        let summary = fixture.runtime.summary();
        assert_eq!(summary["apply"]["phase"], json!("activate"));
        assert_eq!(summary["apply"]["reconciliationRequired"], json!(false));
    });
}

#[test]
fn runtime_generation_commit_faults_restore_runtime_file_and_database() {
    with_product_runtime_fake_start_override(true, || {
        for point in [
            RuntimeFaultPoint::CommitPostStart,
            RuntimeFaultPoint::RenameCandidate,
            RuntimeFaultPoint::CommitDatabase,
            RuntimeFaultPoint::PublishLogPolicy,
        ] {
            let fixture = CommittedRuntimeFixture::new(point.as_str());
            let prepared = fixture.prepare_changed_generation();
            let mut faults = RuntimeFaultFixture::default();
            faults.fail_next(point);

            let error = apply_runtime_generation(
                &fixture.runtime,
                fixture.product.state(),
                Some(&fixture.config_dir),
                "runtime-generation-test",
                prepared,
                &[],
                &mut faults,
            )
            .unwrap_err();

            assert!(error.contains(point.as_str()), "{error}");
            assert!(error.contains("rollback restored previous runtime generation"));
            fixture.assert_previous_generation_is_intact();
            let summary = fixture.runtime.summary();
            assert_eq!(summary["apply"]["phase"], json!("rolled-back"));
            assert_eq!(summary["apply"]["rollbackResult"], json!("restored"));
            assert_eq!(summary["apply"]["reconciliationRequired"], json!(false));
            assert!(
                summary["lastError"]
                    .as_str()
                    .unwrap()
                    .contains(point.as_str())
            );
        }
    });
}

#[test]
fn runtime_generation_rollback_persists_the_restored_probe_identity() {
    with_product_runtime_fake_start_override(true, || {
        let fixture = CommittedRuntimeFixture::new("rollback-probe-identity");
        set_metadata(
            fixture.product.state(),
            RUNTIME_PROBE_GENERATION_METADATA_KEY,
            "41",
        )
        .unwrap();
        let prepared = fixture.prepare_changed_generation();
        let mut faults = RuntimeFaultFixture::default();
        faults.fail_next(RuntimeFaultPoint::CommitDatabase);

        let error = apply_runtime_generation(
            &fixture.runtime,
            fixture.product.state(),
            Some(&fixture.config_dir),
            "runtime-generation-test",
            prepared,
            &[],
            &mut faults,
        )
        .unwrap_err();

        assert!(
            error.contains("rollback restored previous runtime generation"),
            "{error}"
        );
        assert_eq!(
            get_metadata(
                fixture.product.state(),
                RUNTIME_PROBE_GENERATION_METADATA_KEY
            )
            .unwrap(),
            None
        );
        let state = general_state_report(
            fixture.product.state(),
            fixture.product.root(),
            &fixture.runtime,
        )
        .unwrap();
        assert_eq!(
            state["runtimeRevision"]["activationIdentityConsistent"],
            json!(true)
        );
    });
}

#[test]
fn runtime_generation_rollback_failure_is_reported_as_reconciliation_required() {
    with_product_runtime_fake_start_override(true, || {
        let fixture = CommittedRuntimeFixture::new("rollback-fault");
        let prepared = fixture.prepare_changed_generation();
        let candidate_content = prepared.plan.content.as_bytes().to_vec();
        let mut faults = RuntimeFaultFixture::default();
        faults.fail_next(RuntimeFaultPoint::CommitDatabase);
        faults.fail_next(RuntimeFaultPoint::Rollback);

        let error = apply_runtime_generation(
            &fixture.runtime,
            fixture.product.state(),
            Some(&fixture.config_dir),
            "runtime-generation-test",
            prepared,
            &[],
            &mut faults,
        )
        .unwrap_err();

        assert!(
            error.contains("runtime reconciliation is required"),
            "{error}"
        );
        assert!(fixture.runtime.is_running());
        assert_eq!(
            fixture.runtime.current_config().unwrap().global.tproxy_port,
            23456
        );
        assert_eq!(
            fs::read(fixture.config_dir.join("runtime/generated.dae")).unwrap(),
            candidate_content
        );
        assert_eq!(
            running_runtime_state(&fixture.product.connection())
                .unwrap()
                .unwrap(),
            fixture.running_state
        );
        assert_eq!(
            get_metadata(fixture.product.state(), "runtime_generation_id")
                .unwrap()
                .as_deref(),
            Some(fixture.generation.as_str())
        );
        let summary = fixture.runtime.summary();
        assert_eq!(summary["state"], json!("running"));
        assert_eq!(summary["apply"]["phase"], json!("reconcile"));
        assert_eq!(summary["apply"]["rollbackResult"], json!("failed"));
        assert_eq!(summary["apply"]["reconciliationRequired"], json!(true));
        let last_error = summary["lastError"].as_str().unwrap();
        assert!(last_error.contains(RuntimeFaultPoint::CommitDatabase.as_str()));
        assert!(last_error.contains(RuntimeFaultPoint::Rollback.as_str()));
        assert_no_staged_runtime_files(&fixture.config_dir);
    });
}

#[test]
fn waiting_reload_coalesces_after_the_active_generation_reaches_latest_state() {
    with_product_runtime_fake_start_override(true, || {
        let product = FreshProductState::new("coalesced-latest-state");
        product.seed_selected_resources();
        let config_dir = product.root().join("config");
        let runtime = Arc::new(ProductRuntimeManager::new());
        let initial = coordinate_runtime_reload(
            &runtime,
            product.state(),
            Some(&config_dir),
            RuntimeApplyIntent::ApiReload,
            &[],
            AllocatorReclaimReason::ReloadCompleted,
        )
        .unwrap();
        assert!(initial.applied);

        let active = runtime.begin_apply(RuntimeApplyIntent::ApiReload).unwrap();
        let state = product.state().to_path_buf();
        let config_dir_for_waiter = config_dir.clone();
        let waiting_runtime = Arc::clone(&runtime);
        let (started_tx, started_rx) = mpsc::channel();
        let waiting = thread::spawn(move || {
            with_product_runtime_fake_start_override(true, || {
                started_tx.send(()).unwrap();
                coordinate_runtime_reload(
                    &waiting_runtime,
                    &state,
                    Some(&config_dir_for_waiter),
                    RuntimeApplyIntent::LocalControlReload,
                    &[],
                    AllocatorReclaimReason::ReloadCompleted,
                )
            })
        });
        started_rx.recv().unwrap();
        active.finish("succeeded");

        let coalesced = waiting.join().unwrap().unwrap();
        assert!(!coalesced.applied);
        assert!(coalesced.coalesced);
        assert_eq!(runtime.summary()["reloadCount"], json!(1));
        assert_eq!(
            runtime.summary()["applyCoordinator"]["coalescedCount"],
            json!(1)
        );
    });
}

#[test]
fn consecutive_generic_config_changes_do_not_leave_a_cleanup_interlock() {
    with_product_runtime_fake_start_override(true, || {
        let product = FreshProductState::new("consecutive-generic-config-reloads");
        product.seed_selected_resources();
        let config_dir = product.root().join("config");
        let runtime = ProductRuntimeManager::new();
        let initial = coordinate_runtime_reload(
            &runtime,
            product.state(),
            Some(&config_dir),
            RuntimeApplyIntent::ApiReload,
            &[],
            AllocatorReclaimReason::ReloadCompleted,
        )
        .unwrap();
        assert!(initial.applied);

        for global in [
            "global { tproxy_port: 23456 log_level: debug }",
            "global { tproxy_port: 23457 log_level: warn mptcp: true }",
            "global { tproxy_port: 23458 log_level: info mptcp: false }",
        ] {
            product
                .connection()
                .execute(
                    "UPDATE configs SET global = ?1, version = version + 1 WHERE selected = 1",
                    [global],
                )
                .unwrap();
            let applied = coordinate_runtime_reload(
                &runtime,
                product.state(),
                Some(&config_dir),
                RuntimeApplyIntent::ApiReload,
                &[],
                AllocatorReclaimReason::ReloadCompleted,
            )
            .unwrap();
            assert!(applied.applied);
            assert!(!applied.coalesced);
            runtime.ensure_cleanup_allows_start().unwrap();
            let summary = runtime.summary();
            assert_eq!(summary["state"], json!("running"));
            assert_eq!(summary["cleanup"]["state"], json!("done"));
            assert_eq!(summary["cleanup"]["lastError"], Value::Null);
        }

        assert_eq!(runtime.summary()["reloadCount"], json!(4));
    });
}

#[test]
fn unchanged_desired_state_repairs_an_inconsistent_activation_identity() {
    with_product_runtime_fake_start_override(true, || {
        let product = FreshProductState::new("repair-inconsistent-activation-identity");
        product.seed_selected_resources();
        let config_dir = product.root().join("config");
        let runtime = ProductRuntimeManager::new();
        let initial = coordinate_runtime_reload(
            &runtime,
            product.state(),
            Some(&config_dir),
            RuntimeApplyIntent::ApiReload,
            &[],
            AllocatorReclaimReason::ReloadCompleted,
        )
        .unwrap();
        assert!(initial.applied);
        set_metadata(product.state(), RUNTIME_PROBE_GENERATION_METADATA_KEY, "41").unwrap();

        let inconsistent = general_state_report(product.state(), product.root(), &runtime).unwrap();
        assert_eq!(
            inconsistent["runtimeRevision"]["activationIdentityConsistent"],
            json!(false)
        );

        let repaired = coordinate_runtime_reload(
            &runtime,
            product.state(),
            Some(&config_dir),
            RuntimeApplyIntent::SubscriptionRefresh,
            &[],
            AllocatorReclaimReason::ReloadCompleted,
        )
        .unwrap();
        assert!(repaired.applied);
        assert!(!repaired.coalesced);
        assert_eq!(runtime.summary()["reloadCount"], json!(2));

        let consistent = general_state_report(product.state(), product.root(), &runtime).unwrap();
        assert_eq!(
            consistent["runtimeRevision"]["activationIdentityConsistent"],
            json!(true)
        );
        assert_eq!(
            get_metadata(product.state(), RUNTIME_PROBE_GENERATION_METADATA_KEY).unwrap(),
            None
        );
    });
}

#[test]
fn reload_reports_process_owned_http_changes_as_pending_transition() {
    with_product_runtime_fake_start_override(true, || {
        let product = FreshProductState::new("pending-process-transition");
        product.seed_selected_resources();
        let config_dir = product.root().join("config");
        let runtime = ProductRuntimeManager::new();
        coordinate_runtime_reload(
            &runtime,
            product.state(),
            Some(&config_dir),
            RuntimeApplyIntent::ApiReload,
            &[],
            AllocatorReclaimReason::ReloadCompleted,
        )
        .unwrap();
        let active_http = ProductHttpWorkerConfig::from_config(runtime.current_config().as_ref());
        runtime.set_process_http_config(active_http);
        let desired_workers = if active_http.worker_count == PRODUCT_HTTP_WORKER_MAX {
            PRODUCT_HTTP_WORKER_MIN
        } else {
            active_http.worker_count + 1
        };
        product
            .connection()
            .execute(
                "UPDATE configs SET global = ?1, version = version + 1 WHERE selected = 1",
                params![format!("global {{ http_workers: {desired_workers} }}")],
            )
            .unwrap();

        let applied = coordinate_runtime_reload(
            &runtime,
            product.state(),
            Some(&config_dir),
            RuntimeApplyIntent::ApiReload,
            &[],
            AllocatorReclaimReason::ReloadCompleted,
        )
        .unwrap();
        assert!(applied.applied);
        let pending = applied.pending_process_transition.unwrap();
        assert_eq!(pending["state"], json!("pending-process-transition"));
        assert_eq!(
            pending["active"]["workers"],
            json!(active_http.worker_count)
        );
        assert_eq!(pending["desired"]["workers"], json!(desired_workers));
        assert_eq!(
            get_metadata(product.state(), RUNTIME_PROCESS_TRANSITION_METADATA_KEY)
                .unwrap()
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                .unwrap()["desired"]["workers"],
            json!(desired_workers)
        );
    });
}

#[test]
fn general_state_exposes_desired_active_and_generation_consistency() {
    with_product_runtime_fake_start_override(true, || {
        let product = FreshProductState::new("runtime-revision-report");
        product.seed_selected_resources();
        let runtime = ProductRuntimeManager::new();
        coordinate_runtime_reload(
            &runtime,
            product.state(),
            Some(product.root()),
            RuntimeApplyIntent::ApiReload,
            &[],
            AllocatorReclaimReason::ReloadCompleted,
        )
        .unwrap();

        let current = general_state_report(product.state(), product.root(), &runtime).unwrap();
        let revision = &current["runtimeRevision"];
        assert_eq!(revision["desired"]["externalInputVersion"], json!(0));
        assert_eq!(revision["active"]["externalInputVersion"], json!(0));
        assert_eq!(revision["desiredMatchesActive"], json!(true));
        assert_eq!(revision["pending"], json!(false));
        assert_eq!(revision["productGenerationMatches"], json!(true));
        assert_eq!(revision["probeGenerationMatches"], json!(true));
        assert_eq!(revision["activationIdentityConsistent"], json!(true));

        bump_runtime_external_input_version(product.state()).unwrap();
        let pending = general_state_report(product.state(), product.root(), &runtime).unwrap();
        let revision = &pending["runtimeRevision"];
        assert_eq!(revision["desired"]["externalInputVersion"], json!(1));
        assert_eq!(revision["active"]["externalInputVersion"], json!(0));
        assert_eq!(revision["desiredMatchesActive"], json!(false));
        assert_eq!(revision["pending"], json!(true));
        assert_eq!(pending["modified"], json!(true));
    });
}
