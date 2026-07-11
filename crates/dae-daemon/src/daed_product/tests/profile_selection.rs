use super::support::FreshProductState;
use super::*;

fn selection_fixture(scope: &str) -> FreshProductState {
    let fixture = FreshProductState::new(scope);
    fixture.seed_selected_resources();
    fixture
        .connection()
        .execute_batch(
            r#"
            INSERT INTO configs(id, name, global, selected, version)
                VALUES(2, 'second-global', 'global { log_level: debug }', 0, 7);
            INSERT INTO dns(id, name, dns, selected, version)
                VALUES(2, 'second-dns', 'dns {}', 0, 8);
            INSERT INTO routings(id, name, routing, selected, version)
                VALUES(2, 'second-routing', 'routing { fallback: direct }', 0, 9);
            "#,
        )
        .unwrap();
    fixture
}

fn selected_and_version(fixture: &FreshProductState, kind: SectionKind) -> Vec<(i64, i64, i64)> {
    let conn = fixture.connection();
    let sql = format!(
        "SELECT id, selected, version FROM {} ORDER BY id",
        kind.table()
    );
    let mut stmt = conn.prepare(&sql).unwrap();
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn missing_single_selection_target_preserves_previous_selection() {
    let fixture = selection_fixture("single-selection-missing");
    let before = selected_and_version(&fixture, SectionKind::Config);

    let error =
        select_section_transactionally(fixture.state(), SectionKind::Config, 999).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(selected_and_version(&fixture, SectionKind::Config), before);
}

#[test]
fn profile_selection_validates_all_targets_before_mutation() {
    let fixture = selection_fixture("profile-selection-missing");
    let before = [
        selected_and_version(&fixture, SectionKind::Config),
        selected_and_version(&fixture, SectionKind::Dns),
        selected_and_version(&fixture, SectionKind::Routing),
    ];

    let error = select_profile_transactionally(
        fixture.state(),
        ProfileSelection {
            config_id: 2,
            dns_id: 2,
            routing_id: 999,
        },
    )
    .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        selected_and_version(&fixture, SectionKind::Config),
        before[0]
    );
    assert_eq!(selected_and_version(&fixture, SectionKind::Dns), before[1]);
    assert_eq!(
        selected_and_version(&fixture, SectionKind::Routing),
        before[2]
    );
}

#[test]
fn profile_selection_commits_all_resources_once() {
    let fixture = selection_fixture("profile-selection-success");

    select_profile_transactionally(
        fixture.state(),
        ProfileSelection {
            config_id: 2,
            dns_id: 2,
            routing_id: 2,
        },
    )
    .unwrap();

    assert_eq!(
        selected_and_version(&fixture, SectionKind::Config),
        vec![(1, 0, 1), (2, 1, 8)]
    );
    assert_eq!(
        selected_and_version(&fixture, SectionKind::Dns),
        vec![(1, 0, 1), (2, 1, 9)]
    );
    assert_eq!(
        selected_and_version(&fixture, SectionKind::Routing),
        vec![(1, 0, 1), (2, 1, 10)]
    );
}

#[test]
fn profile_selection_database_failure_rolls_back_every_section() {
    let fixture = selection_fixture("profile-selection-database-failure");
    let before = [
        selected_and_version(&fixture, SectionKind::Config),
        selected_and_version(&fixture, SectionKind::Dns),
        selected_and_version(&fixture, SectionKind::Routing),
    ];
    fixture
        .connection()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_dns_profile_selection
            BEFORE UPDATE OF selected ON dns
            WHEN NEW.id = 2 AND NEW.selected = 1
            BEGIN
                SELECT RAISE(ABORT, 'injected DNS profile selection failure');
            END;
            "#,
        )
        .unwrap();

    let error = select_profile_transactionally(
        fixture.state(),
        ProfileSelection {
            config_id: 2,
            dns_id: 2,
            routing_id: 2,
        },
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected DNS profile selection failure")
    );
    assert_eq!(
        selected_and_version(&fixture, SectionKind::Config),
        before[0]
    );
    assert_eq!(selected_and_version(&fixture, SectionKind::Dns), before[1]);
    assert_eq!(
        selected_and_version(&fixture, SectionKind::Routing),
        before[2]
    );
}

#[test]
fn profile_selection_api_accepts_product_string_ids() {
    let fixture = selection_fixture("profile-selection-api");
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/profiles/select".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{"configId":"2","dnsId":"2","routingId":"2"}"#.to_vec(),
    };

    let response = api_select_profile(fixture.state(), &request);

    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["selected"]["configId"], json!(2));
    assert_eq!(body["selected"]["dnsId"], json!(2));
    assert_eq!(body["selected"]["routingId"], json!(2));
}
