use super::support::FreshProductState;
use super::*;

fn running_stop_fixture(scope: &str) -> (FreshProductState, ProductRuntimeManager) {
    let fixture = FreshProductState::new(scope);
    fixture.seed_selected_resources();
    fixture
        .connection()
        .execute_batch(
            r#"
            INSERT INTO systems(
                running,
                running_config_version,
                running_dns_version,
                running_routing_version,
                running_group_version_sum,
                running_group_ids,
                running_config_id,
                running_dns_id,
                running_routing_id,
                running_external_input_version
            ) VALUES(1, 1, 1, 1, 0, '', 1, 1, 1, 0);
            INSERT OR REPLACE INTO daed_product_metadata(key, value)
                VALUES('runtime_running', 'true');
            "#,
        )
        .unwrap();
    let runtime = ProductRuntimeManager::new();
    {
        let mut inner = runtime.inner.lock().unwrap();
        inner.runtime = Some(ProductRuntimeInstance::Fake(FakeProductRuntime {
            started_at: "2026-07-11T00:00:00+08:00".to_owned(),
            tproxy_port: 12345,
        }));
        inner.runtime_started_at = Some("2026-07-11T00:00:00+08:00".to_owned());
    }
    (fixture, runtime)
}

#[test]
fn runtime_stop_persists_state_before_detaching_running_runtime() {
    let (fixture, runtime) = running_stop_fixture("runtime-stop-success");

    let report = stop_runtime_and_persist(fixture.state(), &runtime).unwrap();

    assert_eq!(report["stopped"], json!(true));
    assert_eq!(report["wasRunning"], json!(true));
    assert!(!runtime.is_running());
    assert!(runtime.wait_for_cleanup_idle(Duration::from_secs(1)));
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row("SELECT running FROM systems LIMIT 1", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        get_metadata(fixture.state(), "runtime_running")
            .unwrap()
            .as_deref(),
        Some("false")
    );
}

#[test]
fn runtime_stop_database_failure_keeps_runtime_and_persisted_state_running() {
    let (fixture, runtime) = running_stop_fixture("runtime-stop-database-failure");
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_runtime_stop_metadata
            BEFORE INSERT ON daed_product_metadata
            WHEN NEW.key = 'runtime_running' AND NEW.value = 'false'
            BEGIN
                SELECT RAISE(ABORT, 'injected runtime stop metadata failure');
            END;
            "#,
        )
        .unwrap();

    let error = stop_runtime_and_persist(fixture.state(), &runtime).unwrap_err();

    assert!(
        error.contains("injected runtime stop metadata failure"),
        "{error}"
    );
    assert!(runtime.is_running());
    let summary = runtime.summary();
    assert_eq!(summary["state"], json!("running"));
    assert_eq!(summary["stopCount"], json!(0));
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row("SELECT running FROM systems LIMIT 1", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        get_metadata(fixture.state(), "runtime_running")
            .unwrap()
            .as_deref(),
        Some("true")
    );
}
