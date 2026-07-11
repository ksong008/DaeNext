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
        Self {
            product,
            config_dir,
            runtime,
            generated_content,
            running_state,
            generation,
            tproxy_port,
        }
    }

    fn prepare_changed_generation(&self) -> PreparedRuntimeReload {
        self.product
            .connection()
            .execute(
                "UPDATE configs
                 SET global = 'global { tproxy_port: 23456 }', version = version + 1
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
