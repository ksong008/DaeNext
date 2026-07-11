use super::*;

#[test]
fn run_rejects_file_config_path_before_state_or_workers_start() {
    let root = std::env::temp_dir().join(format!(
        "daed-config-directory-test-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    fs::create_dir_all(&root).unwrap();
    let config_file = root.join("config.dae");
    fs::write(&config_file, "global {}\nrouting { fallback: direct }\n").unwrap();
    let state = root.join("state").join("daed.db");

    let output = run_product_server_command(
        &[
            "--config".to_owned(),
            config_file.display().to_string(),
            "--state".to_owned(),
            state.display().to_string(),
            "--listen".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--api-only".to_owned(),
        ],
        "test",
    );

    assert_eq!(output.exit_code, 1);
    assert!(
        output.stderr.contains("config directory"),
        "{}",
        output.stderr
    );
    assert!(
        !state.exists(),
        "state was initialized before config validation"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn config_directory_contract_handles_missing_relative_and_symlink_paths() {
    let root = std::env::temp_dir().join(format!(
        "daed-config-directory-contract-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    fs::create_dir_all(&root).unwrap();

    let missing = root.join("missing").join("config");
    let prepared = prepare_config_directory(&missing).unwrap();
    assert!(prepared.is_absolute());
    assert!(prepared.is_dir());

    let relative_path = PathBuf::from("target").join(format!(
        "daed-relative-config-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    let relative = prepare_config_directory(&relative_path).unwrap();
    assert!(relative.is_absolute());
    assert!(relative.is_dir());
    fs::remove_dir_all(relative).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let directory_link = root.join("directory-link");
        symlink(&prepared, &directory_link).unwrap();
        assert_eq!(prepare_config_directory(&directory_link).unwrap(), prepared);

        let file = root.join("config-file");
        fs::write(&file, "global {}").unwrap();
        let file_link = root.join("file-link");
        symlink(&file, &file_link).unwrap();
        assert!(
            prepare_config_directory(&file_link)
                .unwrap_err()
                .contains("must be a directory")
        );
    }

    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn config_directory_rejects_read_only_mode_before_startup() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!(
        "daed-config-directory-readonly-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(
        prepare_config_directory(&root)
            .unwrap_err()
            .contains("not writable")
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_dir_all(root).unwrap();
}
