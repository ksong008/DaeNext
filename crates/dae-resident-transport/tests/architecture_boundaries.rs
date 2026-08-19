use std::fs;
use std::path::{Path, PathBuf};

fn production_rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|err| panic!("read {}: {err}", directory.display()))
        {
            let path = entry.expect("read transport source entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && path.file_name().is_none_or(|name| name != "tests.rs")
            {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

#[test]
fn transport_manifest_has_no_coordinator_or_domain_dependencies() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read transport manifest");
    for forbidden in [
        "dae-daemon",
        "dae-resident-dataplane",
        "dae-resident-dns",
        "dae-resident-plan",
        "dae-resident-tcp",
        "dae-resident-udp",
        "rusqlite",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "transport manifest contains forbidden dependency {forbidden}"
        );
    }
}

#[test]
fn transport_production_sources_do_not_import_domain_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let forbidden = [
        "crate::dns::",
        "crate::plan::",
        "crate::tcp::",
        "crate::udp::",
    ];
    let mut violations = Vec::new();
    for path in production_rust_sources(&root) {
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
        "transport boundary violations:\n{}",
        violations.join("\n")
    );
}
