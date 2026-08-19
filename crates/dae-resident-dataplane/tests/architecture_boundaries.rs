use std::fs;
use std::path::{Path, PathBuf};

fn production_rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|err| panic!("read {}: {err}", directory.display()))
        {
            let path = entry.expect("read source directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if file_name == "tests.rs"
                || file_name.ends_with("_tests.rs")
                || file_name.ends_with("_benchmarks.rs")
            {
                continue;
            }
            sources.push(path);
        }
    }

    sources.sort();
    sources
}

fn assert_sources_exclude(root: &Path, forbidden: &[&str]) {
    let mut violations = Vec::new();
    for path in production_rust_sources(root) {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        for needle in forbidden {
            if source.contains(needle) {
                violations.push(format!("{} contains {needle}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "resident dataplane boundary violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dns_production_does_not_import_tcp_or_udp_private_modules() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../dae-resident-dns/src");
    assert_sources_exclude(
        &source_root,
        &[
            "crate::tcp::",
            "crate::udp::",
            "super::super::tcp::",
            "super::super::udp::",
        ],
    );
}

#[test]
fn tcp_and_udp_production_do_not_import_dns_private_modules() {
    let crates_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for domain in ["dae-resident-tcp", "dae-resident-udp"] {
        assert_sources_exclude(
            &crates_root.join(domain).join("src"),
            &["crate::dns::", "super::super::dns::"],
        );
    }
}
