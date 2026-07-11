use super::*;

#[test]
fn geodata_version_stage_failure_keeps_live_generation_unchanged() {
    let fixture = GeodataTransactionFixture::new("version-stage-fault");
    let mut checkpoints = FailCheckpoint {
        point: GeodataTransactionCheckpoint::WriteVersionStage,
    };

    assert!(fixture.commit(None, &mut checkpoints).is_err());
    fixture.assert_old_generation();
    assert!(!fixture.data_stage.exists());
    fixture.cleanup();
}

#[test]
fn geodata_activation_faults_restore_the_complete_old_generation() {
    for point in [
        GeodataTransactionCheckpoint::RenameData,
        GeodataTransactionCheckpoint::RenameVersion,
        GeodataTransactionCheckpoint::SyncActivatedDirectory,
        GeodataTransactionCheckpoint::WriteFilesActivatedJournal,
        GeodataTransactionCheckpoint::BumpExternalInput,
    ] {
        let fixture = GeodataTransactionFixture::new(&format!("activation-{point:?}"));
        let mut checkpoints = FailCheckpoint { point };
        let external_input_version_before =
            (point == GeodataTransactionCheckpoint::BumpExternalInput).then_some(0);

        let error = fixture
            .commit(external_input_version_before, &mut checkpoints)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("previous generation was restored")
        );
        fixture.assert_old_generation();
        fixture.cleanup();
    }
}

#[test]
fn geodata_database_bump_failure_rolls_back_files() {
    let fixture = GeodataTransactionFixture::new("database-bump-fault");
    let conn = open_state_connection(&fixture.state).unwrap();
    conn.execute_batch(
        r#"
        CREATE TRIGGER reject_geodata_external_input_bump
        BEFORE INSERT ON daed_product_metadata
        WHEN NEW.key = 'runtime_external_input_version'
        BEGIN
            SELECT RAISE(ABORT, 'injected external input failure');
        END;
        "#,
    )
    .unwrap();
    drop(conn);
    let mut checkpoints = PassCheckpoints;

    let error = fixture.commit(Some(0), &mut checkpoints).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("previous generation was restored")
    );
    fixture.assert_old_generation();
    assert_eq!(
        current_runtime_external_input_version(&open_state_connection(&fixture.state).unwrap())
            .unwrap(),
        0
    );
    fixture.cleanup();
}

#[test]
fn geodata_success_commits_status_version_and_runtime_pending_together() {
    let fixture = GeodataTransactionFixture::new("success");
    let mut checkpoints = PassCheckpoints;

    let result = fixture.commit(Some(0), &mut checkpoints).unwrap();

    fixture.assert_new_generation();
    assert_eq!(result.status["version"], json!("new-tag"));
    assert_eq!(result.status["ruleCount"], json!(2));
    assert!(result.runtime_reload_required);
    assert_eq!(
        current_runtime_external_input_version(&open_state_connection(&fixture.state).unwrap())
            .unwrap(),
        1
    );
    fixture.cleanup();
}
