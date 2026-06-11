use std::fs;
use std::hint::black_box;
use std::path::PathBuf;

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "cli/validate_minimal_config",
            default_iters: 1_000,
            run: bench_cli_validate_minimal_config,
        },
        BenchCase {
            id: "cli/export_outline",
            default_iters: 1_000,
            run: bench_cli_export_outline,
        },
    ]
}

fn bench_cli_validate_minimal_config(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let tree = TempConfig::new("dae-bench-cli-validate")?;
    let path = tree.write("config.dae", "global {}\nrouting {}\n")?;
    let measurement = measure(
        || {
            let result =
                dae_cli::validate_config_file(black_box(&path)).expect("cli validate config");
            black_box(result as u64)
        },
        iters,
        warmup,
    );
    Ok(measurement)
}

fn bench_cli_export_outline(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let outline = dae_cli::export_outline_json(black_box("unknown"));
            black_box(outline.len() as u64)
        },
        iters,
        warmup,
    ))
}

struct TempConfig {
    root: PathBuf,
}

impl TempConfig {
    fn new(name: &str) -> Result<Self, String> {
        let root = std::env::temp_dir().join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root)
            .map_err(|err| format!("create temp config root {} failed: {err}", root.display()))?;
        Ok(Self { root })
    }

    fn write(&self, rel: &str, content: &str) -> Result<PathBuf, String> {
        let path = self.root.join(rel);
        fs::write(&path, content)
            .map_err(|err| format!("write {} failed: {err}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|err| format!("chmod {} failed: {err}", path.display()))?;
        }
        Ok(path)
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
