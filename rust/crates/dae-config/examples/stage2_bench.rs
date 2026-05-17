use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use dae_config::marshal::marshal_config;
use dae_config::merger::merge_config_file;
use dae_config::parser::parse_config;
use dae_config::schema::build_config;

fn main() {
    let iters = std::env::var("DAE_STAGE2_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000);
    let example = include_str!("../../../../example.dae");

    bench("parser_example", iters, || {
        black_box(parse_config(black_box(example)).unwrap());
    });

    bench("schema_example", iters, || {
        let sections = parse_config(black_box(example)).unwrap();
        black_box(build_config(&sections).unwrap());
    });

    let include_tree = IncludeTree::new();
    bench("include_merger", iters, || {
        black_box(merge_config_file(include_tree.path("entry.dae")).unwrap());
    });

    let example_tree = IncludeTree::empty();
    example_tree.write_mode("example.dae", example, 0o640);
    let merged = merge_config_file(example_tree.path("example.dae")).unwrap();
    let config = build_config(&merged.sections).unwrap();
    bench("marshal_roundtrip_example", iters, || {
        let text = marshal_config(&config, 2).unwrap();
        let sections = parse_config(&text).unwrap();
        black_box(build_config(&sections).unwrap());
    });
}

fn bench(name: &str, iters: u64, mut f: impl FnMut()) {
    for _ in 0..10 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    println!("{name}\t{ns_per_op:.1} ns/op\t{iters} iters");
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
            "dae-config-stage2-bench-{}-{}",
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
