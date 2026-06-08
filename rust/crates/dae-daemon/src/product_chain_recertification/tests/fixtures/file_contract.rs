use super::*;
pub(crate) fn write_candidate_service_contract_value(path: &Path, report: &Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let report = serde_json::to_string(report).unwrap();
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"validate\" ]; then exit 0; fi\n\
             if [ \"$1\" = \"service-contract\" ]; then\n\
               cat <<'JSON'\n\
{report}\n\
JSON\n\
               exit 0\n\
             fi\n\
             exit 2\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

pub(crate) fn init_fixture_repo(path: &Path, branch: &str) {
    std::fs::create_dir_all(path).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["checkout", "--quiet", "-B", branch])
            .current_dir(path)
            .status()
            .unwrap()
            .success()
    );
}
