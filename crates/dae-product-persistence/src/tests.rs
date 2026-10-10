use super::*;

fn temp_dir(scope: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "daenext-durable-commit-{scope}-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn leaf_name_rejects_paths_and_parent_components() {
    for invalid in ["", ".", "..", "a/b", "/tmp/a"] {
        assert!(ValidatedLeafName::new(invalid).is_err(), "{invalid}");
    }
    assert_eq!(
        ValidatedLeafName::new("artifact.next").unwrap().as_str(),
        "artifact.next"
    );
}

#[test]
fn bounded_read_rejects_oversized_and_non_regular_inputs() {
    let directory = temp_dir("bounded-read");
    let file = directory.join("file");
    fs::write(&file, b"12345").unwrap();
    assert_eq!(read_bounded_regular_file(&file, 5).unwrap(), b"12345");
    assert_eq!(
        read_bounded_regular_file(&file, 4).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        read_bounded_regular_file(&directory, 5).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn bounded_read_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = temp_dir("symlink");
    let file = directory.join("file");
    let link = directory.join("link");
    fs::write(&file, b"value").unwrap();
    symlink(&file, &link).unwrap();
    assert!(read_bounded_regular_file(&link, 32).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn journal_replace_and_cleanup_are_idempotent() {
    let directory = temp_dir("journal");
    let journal = ValidatedLeafName::new("journal.json").unwrap();
    let next = ValidatedLeafName::new("journal.next").unwrap();
    write_json_journal(&directory, &journal, &next, 1024, &vec!["first"]).unwrap();
    write_json_journal(&directory, &journal, &next, 1024, &vec!["second"]).unwrap();
    let value: Vec<String> = read_json_journal(&journal.path_in(&directory), 1024).unwrap();
    assert_eq!(value, ["second"]);
    remove_leaf_if_exists_synced(&directory, &journal).unwrap();
    remove_leaf_if_exists_synced(&directory, &journal).unwrap();
    fs::remove_dir_all(directory).unwrap();
}

fn transaction_artifacts(directory: &Path) -> DurableArtifactSet {
    DurableArtifactSet::new(
        directory,
        ValidatedLeafName::new("target").unwrap(),
        ValidatedLeafName::new("candidate").unwrap(),
        Some(ValidatedLeafName::new("backup").unwrap()),
        ValidatedLeafName::new("journal").unwrap(),
        ValidatedLeafName::new("journal.next").unwrap(),
    )
    .unwrap()
}

#[test]
fn dropping_activated_transaction_restores_backup() {
    let directory = temp_dir("drop-rollback");
    fs::write(directory.join("target"), b"old").unwrap();
    fs::rename(directory.join("target"), directory.join("backup")).unwrap();
    fs::write(directory.join("candidate"), b"new").unwrap();
    {
        let mut transaction = DurableTransaction::new(transaction_artifacts(&directory));
        transaction.write_intent(1024, &vec!["intent"]).unwrap();
        transaction.activate().unwrap();
        assert_eq!(fs::read(directory.join("target")).unwrap(), b"new");
    }
    assert_eq!(fs::read(directory.join("target")).unwrap(), b"old");
    assert!(!directory.join("backup").exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn transaction_phase_tracks_the_shared_commit_lifecycle() {
    let directory = temp_dir("phase-lifecycle");
    fs::write(directory.join("target"), b"old").unwrap();
    fs::rename(directory.join("target"), directory.join("backup")).unwrap();
    fs::write(directory.join("candidate"), b"new").unwrap();
    let mut transaction = DurableTransaction::new(transaction_artifacts(&directory));

    assert_eq!(transaction.phase(), DurableTransactionPhase::Prepared);
    transaction.write_intent(1024, &vec!["intent"]).unwrap();
    assert_eq!(transaction.phase(), DurableTransactionPhase::IntentWritten);
    transaction.activate().unwrap();
    assert_eq!(transaction.phase(), DurableTransactionPhase::Activated);
    transaction
        .commit_database(|| Ok::<_, io::Error>(()))
        .unwrap();
    assert_eq!(
        transaction.phase(),
        DurableTransactionPhase::DatabaseCommitted
    );
    transaction.finish_in_place().unwrap();
    assert_eq!(transaction.phase(), DurableTransactionPhase::Cleaned);

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn transaction_rejects_phase_skips_and_repeated_intents() {
    let directory = temp_dir("phase-contract");
    let mut transaction = DurableTransaction::new(transaction_artifacts(&directory));

    assert_eq!(
        transaction.activate().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let mut callback_called = false;
    assert_eq!(
        transaction
            .commit_database(|| {
                callback_called = true;
                Ok::<_, io::Error>(())
            })
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(!callback_called);

    transaction.write_intent(1024, &vec!["intent"]).unwrap();
    assert_eq!(
        transaction
            .write_intent(1024, &vec!["duplicate"])
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn failed_rollback_enters_recovery_required_phase() {
    let directory = temp_dir("phase-recovery");
    fs::write(directory.join("backup"), b"old").unwrap();
    fs::write(directory.join("candidate"), b"new").unwrap();
    let mut transaction = DurableTransaction::new(transaction_artifacts(&directory));
    transaction.write_intent(1024, &vec!["intent"]).unwrap();
    transaction.activate().unwrap();
    fs::remove_file(directory.join("target")).unwrap();
    fs::create_dir(directory.join("target")).unwrap();

    assert!(transaction.rollback().is_err());
    assert_eq!(
        transaction.phase(),
        DurableTransactionPhase::RecoveryRequired
    );

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn failed_rollback_preserves_backup_for_recovery() {
    let directory = temp_dir("rollback-backup");
    fs::write(directory.join("backup"), b"old").unwrap();
    fs::write(directory.join("candidate"), b"new").unwrap();
    let mut transaction = DurableTransaction::new(transaction_artifacts(&directory));
    transaction.write_intent(1024, &vec!["intent"]).unwrap();
    transaction.activate().unwrap();
    fs::remove_file(directory.join("target")).unwrap();
    fs::create_dir(directory.join("target")).unwrap();
    assert!(transaction.rollback().is_err());
    assert_eq!(fs::read(directory.join("backup")).unwrap(), b"old");
    fs::remove_dir_all(directory).unwrap();
}
