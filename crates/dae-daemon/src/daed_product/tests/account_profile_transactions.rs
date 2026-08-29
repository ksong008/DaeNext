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
fn account_profile_fields_are_updated_by_one_statement() {
    let fixture = FreshProductState::new("account-profile-transaction");
    let user = fixture_user(&fixture);
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_account_avatar_update
            BEFORE UPDATE OF avatar ON users
            BEGIN
                SELECT RAISE(ABORT, 'injected account profile failure');
            END;
            "#,
        )
        .unwrap();
    let body = json!({
        "username": "changed-user",
        "name": "Changed Name",
        "avatar": "changed-avatar",
    });
    let mut update_user = user.clone();

    let error =
        apply_user_profile_update(&fixture.connection(), &body, &mut update_user).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected account profile failure")
    );
    let stored = load_user_by_id(fixture.state(), user.id())
        .unwrap()
        .unwrap();
    assert_eq!(stored.username(), "original-user");
    assert_eq!(stored.name(), Some("Original Name"));
    assert_eq!(stored.avatar(), Some("original-avatar"));
}
