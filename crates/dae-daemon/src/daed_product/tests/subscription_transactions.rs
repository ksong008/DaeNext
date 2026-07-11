use super::support::FreshProductState;
use super::*;

fn seed_subscription(fixture: &FreshProductState) {
    fixture
        .connection()
        .execute(
            "INSERT INTO subscriptions(
                id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy
             ) VALUES(7, 'old-time', 'https://example.invalid/old', ?1, 1, 'old-status', 'old-info', 'old-tag', 0)",
            params![DEFAULT_SUBSCRIPTION_CRON_EXP],
        )
        .unwrap();
}

fn reject_external_input_bump(fixture: &FreshProductState) {
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_external_input_bump
            BEFORE INSERT ON daed_product_metadata
            WHEN NEW.key = 'runtime_external_input_version'
            BEGIN
                SELECT RAISE(ABORT, 'injected external input bump failure');
            END;
            "#,
        )
        .unwrap();
}

#[test]
fn subscription_refresh_rolls_back_node_swap_when_external_input_bump_fails() {
    let fixture = FreshProductState::new("subscription-refresh-bump-transaction");
    seed_subscription(&fixture);
    reject_external_input_bump(&fixture);

    let error = apply_subscription_refresh_result(
        fixture.state(),
        7,
        "new-time",
        &["socks://127.0.0.1:1080#new-node".to_owned()],
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected external input bump failure")
    );
    let conn = fixture.connection();
    assert_eq!(count_nodes_for_subscription(&conn, 7).unwrap(), 0);
    assert_eq!(
        conn.query_row("SELECT status FROM subscriptions WHERE id = 7", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "old-status"
    );
    assert_eq!(current_runtime_external_input_version(&conn).unwrap(), 0);
}

#[test]
fn subscription_delete_rolls_back_when_external_input_bump_fails() {
    let fixture = FreshProductState::new("subscription-delete-bump-transaction");
    seed_subscription(&fixture);
    replace_subscription_nodes(
        &fixture.connection(),
        7,
        &["socks://127.0.0.1:1080#old-node".to_owned()],
    )
    .unwrap();
    reject_external_input_bump(&fixture);

    let error = delete_subscription(fixture.state(), 7).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected external input bump failure")
    );
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM subscriptions WHERE id = 7",
            [],
            |row| { row.get::<_, i64>(0) }
        )
        .unwrap(),
        1
    );
    assert_eq!(count_nodes_for_subscription(&conn, 7).unwrap(), 1);
    assert_eq!(current_runtime_external_input_version(&conn).unwrap(), 0);
}

#[test]
fn subscription_field_save_is_atomic() {
    let fixture = FreshProductState::new("subscription-field-transaction");
    seed_subscription(&fixture);
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_subscription_proxy_update
            BEFORE UPDATE OF use_proxy ON subscriptions
            WHEN NEW.id = 7
            BEGIN
                SELECT RAISE(ABORT, 'injected subscription field failure');
            END;
            "#,
        )
        .unwrap();
    let request = HttpRequest {
        method: "PATCH".to_owned(),
        path: "/api/subscriptions/7".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"link":"https://example.invalid/new","tag":"new-tag","cronExp":"15 * * * *","cronEnable":false,"useProxy":true}"#.to_vec(),
    };

    let response = update_subscription(fixture.state(), &request, 7);

    assert_eq!(response.status, 400);
    let subscription = get_subscription_value(fixture.state(), 7).unwrap().unwrap();
    assert_eq!(subscription["link"], json!("https://example.invalid/old"));
    assert_eq!(subscription["tag"], json!("old-tag"));
    assert_eq!(
        subscription["cronExp"],
        json!(DEFAULT_SUBSCRIPTION_CRON_EXP)
    );
    assert_eq!(subscription["cronEnable"], json!(true));
    assert_eq!(subscription["useProxy"], json!(false));
}
