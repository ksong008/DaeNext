use super::support::FreshProductState;
use super::*;

fn fixture_user(fixture: &FreshProductState) -> UserRecord {
    let conn = fixture.connection();
    conn.execute(
        "INSERT INTO users(username, password_hash, jwt_secret, json_storage, name, avatar)
         VALUES('original-user', 'hash', 'secret', '{}', 'Original Name', 'original-avatar')",
        [],
    )
    .unwrap();
    load_user_by_id(fixture.state(), conn.last_insert_rowid())
        .unwrap()
        .unwrap()
}

#[test]
fn default_resources_and_user_storage_roll_back_together() {
    let fixture = FreshProductState::new("default-resource-storage-transaction");
    let user = fixture_user(&fixture);
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_default_resource_storage
            BEFORE UPDATE OF json_storage ON users
            BEGIN
                SELECT RAISE(ABORT, 'injected default resource storage failure');
            END;
            "#,
        )
        .unwrap();
    let body = json!({
        "configName": "transaction-global",
        "global": "global {}",
        "dnsName": "transaction-dns",
        "dns": "dns {}",
        "routingName": "transaction-routing",
        "routing": "routing { fallback: direct }",
        "groupName": "transaction-group",
        "policy": "random",
        "mode": "rule",
    });

    let error = ensure_default_resources_for_user(fixture.state(), &body, &user).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected default resource storage failure")
    );
    let conn = fixture.connection();
    for table in ["configs", "dns", "routings", "groups"] {
        assert_eq!(
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0,
            "{table} changed despite storage failure"
        );
    }
    assert_eq!(
        conn.query_row(
            "SELECT json_storage FROM users WHERE id = ?1",
            params![user.id()],
            |row| { row.get::<_, String>(0) }
        )
        .unwrap(),
        user.json_storage()
    );
}
