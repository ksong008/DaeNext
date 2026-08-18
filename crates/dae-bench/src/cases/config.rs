use std::hint::black_box;
use std::path::PathBuf;

use dae_config::marshal::marshal_config;
use dae_config::merger::merge_config_file;
use dae_config::parser::parse_config;
use dae_config::schema::{build_config, build_config_owned};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "config/parser_example",
            default_iters: 10_000,
            run: bench_config_parser_example,
        },
        BenchCase {
            id: "config/schema_example",
            default_iters: 1_000,
            run: bench_config_schema_example,
        },
        BenchCase {
            id: "config/schema_borrowed_example",
            default_iters: 10_000,
            run: bench_config_schema_borrowed_example,
        },
        BenchCase {
            id: "config/schema_owned_clone_example",
            default_iters: 10_000,
            run: bench_config_schema_owned_clone_example,
        },
        BenchCase {
            id: "config/schema_borrowed_large",
            default_iters: 100,
            run: bench_config_schema_borrowed_large,
        },
        BenchCase {
            id: "config/schema_owned_clone_large",
            default_iters: 100,
            run: bench_config_schema_owned_clone_large,
        },
        BenchCase {
            id: "config/include_merger",
            default_iters: 1_000,
            run: bench_config_include_merger,
        },
        BenchCase {
            id: "config/marshal_roundtrip_example",
            default_iters: 1_000,
            run: bench_config_marshal_roundtrip_example,
        },
    ]
}

fn bench_config_parser_example(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let example = include_str!("../../../../example.dae");
    Ok(measure(
        || {
            let sections = parse_config(black_box(example)).expect("parse example.dae");
            black_box(sections.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_config_schema_example(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let example = include_str!("../../../../example.dae");
    Ok(measure(
        || {
            let sections = parse_config(black_box(example)).expect("parse example.dae");
            let config = build_config_owned(sections).expect("build example.dae config");
            black_box(config.global.tproxy_port as u64 ^ config.routing.rules.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_config_schema_borrowed_example(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let sections = parse_config(include_str!("../../../../example.dae"))
        .map_err(|error| format!("parse example.dae failed: {error}"))?;
    Ok(measure(
        || {
            let config = build_config(black_box(&sections)).expect("build borrowed example config");
            black_box(config.global.tproxy_port as u64 ^ config.routing.rules.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_config_schema_owned_clone_example(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let sections = parse_config(include_str!("../../../../example.dae"))
        .map_err(|error| format!("parse example.dae failed: {error}"))?;
    Ok(measure(
        || {
            let config = build_config_owned(black_box(sections.clone()))
                .expect("build owned cloned example config");
            black_box(config.global.tproxy_port as u64 ^ config.routing.rules.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_config_schema_borrowed_large(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let text = large_config_text(2_000, 200);
    let sections =
        parse_config(&text).map_err(|error| format!("parse large config failed: {error}"))?;
    Ok(measure(
        || {
            let config = build_config(black_box(&sections)).expect("build borrowed large config");
            black_box(config.node.len() as u64 ^ config.group.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_config_schema_owned_clone_large(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let text = large_config_text(2_000, 200);
    let sections =
        parse_config(&text).map_err(|error| format!("parse large config failed: {error}"))?;
    Ok(measure(
        || {
            let config = build_config_owned(black_box(sections.clone()))
                .expect("build owned cloned large config");
            black_box(config.node.len() as u64 ^ config.group.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn large_config_text(node_count: usize, group_count: usize) -> String {
    use std::fmt::Write as _;

    let mut text = String::from("global {}\nnode {\n");
    for index in 0..node_count {
        writeln!(text, "  node_{index}: 'socks5://127.0.0.1:1080'").unwrap();
    }
    text.push_str("}\ngroup {\n");
    for index in 0..group_count {
        writeln!(
            text,
            "  group_{index} {{ filter: name(node_{index}) policy: fixed(0) }}"
        )
        .unwrap();
    }
    text.push_str("}\nrouting { fallback: direct }\n");
    text
}

fn bench_config_include_merger(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let include_tree = IncludeTree::new();
    // Assessment (kept as-is): this case measures the include-merge pipeline
    // end to end, and merge_config_file reads its include tree from disk
    // internally. There is no in-memory merge API in dae-config to split the
    // file reads into a warmup phase; the warmup loop pre-heats the page cache
    // so the measured reads are page-cache hits, but the open/read syscalls
    // remain part of the measurement by design.
    Ok(measure(
        || {
            let merged =
                merge_config_file(black_box(include_tree.path("entry.dae"))).expect("merge config");
            black_box(merged.sections.len() as u64 ^ merged.entries.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_config_marshal_roundtrip_example(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let example = include_str!("../../../../example.dae");
    let example_tree = IncludeTree::empty();
    example_tree.write_mode("example.dae", example, 0o640);
    let merged = merge_config_file(example_tree.path("example.dae"))
        .map_err(|err| format!("merge example.dae failed: {err}"))?;
    let config = build_config_owned(merged.sections)
        .map_err(|err| format!("build example.dae config failed: {err}"))?;

    Ok(measure(
        || {
            let text = marshal_config(black_box(&config), 2).expect("marshal example config");
            let sections = parse_config(black_box(&text)).expect("parse marshaled example config");
            let roundtrip =
                build_config_owned(sections).expect("build marshaled example config roundtrip");
            black_box(text.len() as u64 ^ roundtrip.routing.rules.len() as u64)
        },
        iters,
        warmup,
    ))
}

struct IncludeTree {
    root: PathBuf,
}

impl IncludeTree {
    fn new() -> Self {
        let tree = Self::empty();
        tree.mkdir("config.d");
        tree.mkdir("config.d/dir.dae");
        tree.write_mode(
            "entry.dae",
            r#"
include {
    config.d/*
    missing/*.dae
}
global {
    log_level: info
}
routing {
    fallback: parent
}
"#,
            0o640,
        );
        tree.write_mode(
            "config.d/child.dae",
            r#"
include {
    nested.dae
}
global {
    log_level: debug
}
routing {
    domain(child.example) -> child
}
"#,
            0o640,
        );
        tree.write_mode(
            "nested.dae",
            r#"
global {
    tcp_check_http_method: POST
}
node {
    nested: 'socks5://nested'
}
routing {
    domain(nested.example) -> nested
    fallback: nested
}
"#,
            0o640,
        );
        tree.write_mode("config.d/ignored.txt", "global {}", 0o640);
        tree
    }

    fn empty() -> Self {
        let root = std::env::temp_dir().join(format!(
            "dae-bench-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn mkdir(&self, rel: &str) {
        std::fs::create_dir_all(self.path(rel)).unwrap();
    }

    fn write_mode(&self, rel: &str, text: &str, mode: u32) {
        let path = self.path(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }
}

impl Drop for IncludeTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
