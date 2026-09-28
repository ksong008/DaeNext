use super::*;

#[test]
fn geodata_startup_recovery_finds_override_journal_when_live_file_is_missing() {
    let fixture = GeodataTransactionFixture::new("startup-override");
    fixture.prepare_crash_journal(None);
    fs::remove_file(fixture.dir.join(GEOSITE_FILE)).unwrap();
    let fallback = fixture.dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    fs::write(fallback.join(GEOSITE_FILE), &fixture.new_data).unwrap();
    let paths = geodata::ProductGeodataPaths::for_search_directories(
        vec![fixture.dir.clone(), fallback.clone()],
        Some(fixture.dir.clone()),
    );
    assert_eq!(paths.read_directory(GeodataKind::Geosite), fallback);
    recover_product_durable_state(&fixture.state, &fixture.dir, &paths).unwrap();
    fixture.assert_old_generation();
    assert_eq!(paths.read_directory(GeodataKind::Geosite), fixture.dir);
    fixture.cleanup();
}

#[test]
fn geodata_activating_crash_recovers_the_old_generation() {
    let fixture = GeodataTransactionFixture::new("recover-activating");
    let (_journal, _version_stage) = fixture.prepare_crash_journal(None);
    fs::rename(&fixture.data_stage, fixture.dir.join(GEOSITE_FILE)).unwrap();

    recover_geodata_transaction(&fixture.dir, &fixture.state, GeodataKind::Geosite).unwrap();
    recover_geodata_transaction(&fixture.dir, &fixture.state, GeodataKind::Geosite).unwrap();

    fixture.assert_old_generation();
    fixture.cleanup();
}

#[test]
fn geodata_files_activated_crash_keeps_new_generation_and_completes_pending_state() {
    let fixture = GeodataTransactionFixture::new("recover-files-activated");
    let (mut journal, version_stage) = fixture.prepare_crash_journal(Some(0));
    fs::rename(&fixture.data_stage, fixture.dir.join(GEOSITE_FILE)).unwrap();
    fs::rename(
        version_stage,
        fixture.dir.join(GeodataKind::Geosite.version_file_name()),
    )
    .unwrap();
    fs::File::open(&fixture.dir).unwrap().sync_all().unwrap();
    journal.phase = GeodataJournalPhase::FilesActivated;
    write_geodata_journal(&fixture.dir, GeodataKind::Geosite, &journal).unwrap();

    recover_geodata_transaction(&fixture.dir, &fixture.state, GeodataKind::Geosite).unwrap();
    recover_geodata_transaction(&fixture.dir, &fixture.state, GeodataKind::Geosite).unwrap();

    fixture.assert_new_generation();
    assert_eq!(
        current_runtime_external_input_version(&open_state_connection(&fixture.state).unwrap())
            .unwrap(),
        1
    );
    fixture.cleanup();
}

#[test]
fn geodata_committed_cleanup_interruption_is_recovered_without_rollback() {
    let fixture = GeodataTransactionFixture::new("recover-cleanup");
    let mut checkpoints = FailCheckpoint {
        point: GeodataTransactionCheckpoint::CleanupCommitted,
    };
    let result = fixture.commit(Some(0), &mut checkpoints).unwrap();
    assert_eq!(result.status["version"], json!("new-tag"));
    fixture.assert_new_generation();

    recover_geodata_transaction(&fixture.dir, &fixture.state, GeodataKind::Geosite).unwrap();
    recover_geodata_transaction(&fixture.dir, &fixture.state, GeodataKind::Geosite).unwrap();

    fixture.assert_new_generation();
    assert_eq!(
        current_runtime_external_input_version(&open_state_connection(&fixture.state).unwrap())
            .unwrap(),
        1
    );
    fixture.cleanup();
}

#[test]
fn geodata_recovery_rejects_untrusted_journal_paths() {
    let fixture = GeodataTransactionFixture::new("reject-path");
    let journal_path = fixture.dir.join(".geosite.dat.update-journal.json");
    fs::write(
        journal_path,
        serde_json::to_vec(&json!({
            "format_version": 1,
            "kind": "geosite",
            "phase": "activating",
            "data_stage": "../../outside.dat",
            "version_stage": ".geosite.dat.version.tmp.1.1",
            "data_backup": null,
            "version_backup": null,
            "external_input_version_before": null,
        }))
        .unwrap(),
    )
    .unwrap();

    let error = recover_geodata_transaction(&fixture.dir, &fixture.state, GeodataKind::Geosite)
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    fixture.assert_old_generation();
    fixture.cleanup();
}
