use super::*;
#[derive(Debug, Clone)]
pub(super) struct VarRunSnapshot {
    pub(super) pid: Option<Vec<u8>>,
    pub(super) progress: Option<Vec<u8>>,
}

impl VarRunSnapshot {
    pub(super) fn capture() -> Result<Self, String> {
        Ok(Self {
            pid: read_optional_file(Path::new("/var/run/dae.pid"))?,
            progress: read_optional_file(Path::new("/var/run/dae.progress"))?,
        })
    }

    pub(super) fn reject_live_daemon(&self) -> Result<(), String> {
        let Some(pid_bytes) = &self.pid else {
            return Ok(());
        };
        let pid = String::from_utf8_lossy(pid_bytes).trim().to_owned();
        if pid.is_empty() {
            return Ok(());
        }
        let status = Command::new("kill").args(["-0", &pid]).status();
        if status.map(|status| status.success()).unwrap_or(false) {
            return Err(format!(
                "existing /var/run/dae.pid points to a live process ({pid}); stop it before running matched benchmark"
            ));
        }
        Ok(())
    }

    pub(super) fn restore(&self) -> Result<(), String> {
        restore_optional_file(Path::new("/var/run/dae.pid"), self.pid.as_deref())?;
        restore_optional_file(Path::new("/var/run/dae.progress"), self.progress.as_deref())
    }

    pub(super) fn to_json(&self) -> Value {
        json!({
            "pid_file_existed": self.pid.is_some(),
            "progress_file_existed": self.progress.is_some(),
            "pid_file_restored_after_benchmark": true,
            "progress_file_restored_after_benchmark": true,
        })
    }
}

pub(super) fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("read {} failed: {err}", path_string(path))),
    }
}

pub(super) fn restore_optional_file(path: &Path, content: Option<&[u8]>) -> Result<(), String> {
    match content {
        Some(content) => fs::write(path, content)
            .map_err(|err| format!("restore {} failed: {err}", path_string(path))),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("remove {} failed: {err}", path_string(path))),
        },
    }
}

pub(super) fn remove_var_run_files() -> Result<(), String> {
    for path in ["/var/run/dae.pid", "/var/run/dae.progress"] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("remove {path} failed: {err}")),
        }
    }
    Ok(())
}

pub(super) fn host_cleanup_snapshot() -> Value {
    json!({
        "dae0_exists": command_success("ip", &["link", "show", "dae0"]),
        "dae0peer_exists": command_success("ip", &["link", "show", "dae0peer"]),
        "daens_exists": Path::new("/run/netns/daens").exists() || Path::new("/var/run/netns/daens").exists(),
    })
}

pub(super) fn command_success(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
