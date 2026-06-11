use std::hint::black_box;
use std::time::Instant;

use dae_cli::{export_outline_json, validate_config_file};

fn main() {
    let iters = std::env::var("DAE_STAGE10_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000);
    let path = write_config();
    bench_validate(&path, iters);
    bench_export_outline(iters);
    let _ = std::fs::remove_file(path);
}

fn bench_validate(path: &std::path::Path, iters: usize) {
    let started = Instant::now();
    for _ in 0..iters {
        validate_config_file(black_box(path)).unwrap();
    }
    print_ns("cli_validate_minimal_config", started, iters);
}

fn bench_export_outline(iters: usize) {
    let started = Instant::now();
    for _ in 0..iters {
        black_box(export_outline_json(black_box("unknown")));
    }
    print_ns("cli_export_outline", started, iters);
}

fn print_ns(name: &str, started: Instant, iters: usize) {
    let ns = started.elapsed().as_nanos() as f64 / iters as f64;
    println!("{name}: {ns:.1} ns/op");
}

fn write_config() -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("dae-cli-fixture-bench-{}.dae", std::process::id()));
    std::fs::write(&path, "global {}\nrouting {}\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}
