use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use dae_core_types::reload::{RELOAD_DONE, RELOAD_ERROR, RELOAD_PROCESSING, RELOAD_SEND};
use serde_json::{Value, json};

use crate::config_validate::load_config_file;
use crate::production_runtime_owner::start_resident_production_runtime;

pub const PID_FILE_PATH: &str = "/var/run/dae.pid";
pub const PROGRESS_FILE_PATH: &str = "/var/run/dae.progress";
pub const ABORT_FILE_PATH: &str = "/var/run/dae.abort";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentRunOptions {
    pub config: PathBuf,
    pub logfile: Option<PathBuf>,
    pub pid_file: PathBuf,
    pub progress_file: PathBuf,
    pub abort_file: PathBuf,
    pub ready_record_file: Option<PathBuf>,
    pub disable_timestamp: bool,
    pub disable_pidfile: bool,
    pub disable_sudo: bool,
}

impl ResidentRunOptions {
    pub fn for_config(config: impl Into<PathBuf>) -> Self {
        Self {
            config: config.into(),
            logfile: None,
            pid_file: PID_FILE_PATH.into(),
            progress_file: PROGRESS_FILE_PATH.into(),
            abort_file: ABORT_FILE_PATH.into(),
            ready_record_file: None,
            disable_timestamp: false,
            disable_pidfile: false,
            disable_sudo: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOptions {
    pub pid: Option<i32>,
    pub pid_file: PathBuf,
    pub progress_file: PathBuf,
    pub abort_file: PathBuf,
    pub abort_connections: bool,
    pub timeout: Option<Duration>,
}

impl Default for ReloadOptions {
    fn default() -> Self {
        Self {
            pid: None,
            pid_file: PID_FILE_PATH.into(),
            progress_file: PROGRESS_FILE_PATH.into(),
            abort_file: ABORT_FILE_PATH.into(),
            abort_connections: false,
            timeout: None,
        }
    }
}

pub fn service_contract_capabilities(version: &str) -> Value {
    json!({
        "name": "dae-daemon-service-contract",
        "version": version,
        "resident_run_service_contract_ready": true,
        "reload_command_service_contract_ready": true,
        "systemd_notify_ready_supported": true,
        "pid_file_path": PID_FILE_PATH,
        "progress_file_path": PROGRESS_FILE_PATH,
        "abort_file_path": ABORT_FILE_PATH,
        "reload_progress_bytes": {
            "send": (RELOAD_SEND as char).to_string(),
            "processing": (RELOAD_PROCESSING as char).to_string(),
            "done": (RELOAD_DONE as char).to_string(),
            "error": (RELOAD_ERROR as char).to_string(),
        },
        "resident_production_dataplane_ready": true,
        "resident_default_daemon_switch_ready": true,
        "default_path_switch_blocker": Value::Null,
        "boundary": "resident run starts and owns production topology, PARAM-aware tc/eBPF attach, and tproxy listener/sockmap handoff; product-chain switch still requires clean admission evidence and explicit host mutation authorization",
    })
}

pub fn run_resident_service(options: &ResidentRunOptions) -> Result<(), String> {
    if options.disable_sudo && unsafe { libc::geteuid() } != 0 {
        return Err("auto-sudo is disabled and current user is not root".to_owned());
    }
    let runtime_config = load_config_file(&options.config)
        .map_err(|err| format!("resident run config validation failed: {err}"))?;
    block_service_signals()?;
    let mut production_runtime = Some(start_resident_production_runtime(&runtime_config)?);

    let started = (|| {
        if !options.disable_pidfile {
            write_text_file(&options.pid_file, &format!("{}", std::process::id()), 0o644)?;
        }
        write_progress(&options.progress_file, RELOAD_DONE, "")?;
        if let Some(path) = &options.ready_record_file {
            write_text_file(path, "READY=1\n", 0o644)?;
        }
        log_event(options, "service ready")?;
        notify_systemd("READY=1")?;
        Ok::<(), String>(())
    })();
    if let Err(err) = started {
        production_runtime.take();
        if !options.disable_pidfile {
            let _ = fs::remove_file(&options.pid_file);
        }
        return Err(err);
    }

    loop {
        let signal = wait_service_signal()?;
        match signal {
            libc::SIGUSR1 => handle_reload(options, &mut production_runtime)?,
            libc::SIGUSR2 => handle_suspend_compatibility(options)?,
            libc::SIGHUP => continue,
            libc::SIGTERM | libc::SIGINT | libc::SIGQUIT => {
                let _ = notify_systemd("STOPPING=1");
                let _ = log_event(options, "service stopping");
                production_runtime.take();
                if !options.disable_pidfile {
                    let _ = fs::remove_file(&options.pid_file);
                }
                return Ok(());
            }
            _ => continue,
        }
    }
}

pub fn reload_resident_service(options: &ReloadOptions) -> Result<String, String> {
    let pid = match options.pid {
        Some(pid) => pid,
        None => read_pid_file(&options.pid_file)?,
    };
    if options.abort_connections {
        write_text_file(&options.abort_file, "", 0o644)?;
    }
    if let Ok((code, _)) = read_progress(&options.progress_file)
        && code != RELOAD_DONE
        && code != RELOAD_ERROR
    {
        return Ok(format!(
            "{} shows another reload operation is in progress.\n",
            options.progress_file.display()
        ));
    }
    write_progress(&options.progress_file, RELOAD_SEND, "")?;
    let status = unsafe { libc::kill(pid, libc::SIGUSR1) };
    if status != 0 {
        return Err(io::Error::last_os_error().to_string());
    }

    let started = Instant::now();
    loop {
        if options
            .timeout
            .is_some_and(|timeout| started.elapsed() >= timeout)
        {
            return Err("reload progress timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(200));
        let Ok((code, content)) = read_progress(&options.progress_file) else {
            return Ok("OK\n".to_owned());
        };
        if code == RELOAD_DONE || code == RELOAD_ERROR {
            return Ok(format!("{content}\n"));
        }
    }
}

fn handle_reload(
    options: &ResidentRunOptions,
    production_runtime: &mut Option<crate::production_runtime_owner::ResidentProductionRuntime>,
) -> Result<(), String> {
    notify_systemd("RELOADING=1")?;
    write_progress(&options.progress_file, RELOAD_PROCESSING, "")?;
    let _abort_connections = fs::remove_file(&options.abort_file).is_ok();
    match load_config_file(&options.config) {
        Ok(runtime_config) => {
            production_runtime.take();
            match start_resident_production_runtime(&runtime_config) {
                Ok(next_runtime) => {
                    *production_runtime = Some(next_runtime);
                }
                Err(err) => {
                    write_progress(&options.progress_file, RELOAD_ERROR, &format!("\n{err}"))?;
                    log_event(options, "reload failed")?;
                    notify_systemd("READY=1")?;
                    return Ok(());
                }
            }
            write_progress(&options.progress_file, RELOAD_DONE, "\nOK")?;
            log_event(options, "reload completed")?;
        }
        Err(err) => {
            write_progress(&options.progress_file, RELOAD_ERROR, &format!("\n{err}"))?;
            log_event(options, "reload failed")?;
        }
    }
    notify_systemd("READY=1")
}

fn handle_suspend_compatibility(options: &ResidentRunOptions) -> Result<(), String> {
    notify_systemd("RELOADING=1")?;
    write_progress(&options.progress_file, RELOAD_PROCESSING, "")?;
    let _ = fs::remove_file(&options.abort_file);
    write_progress(
        &options.progress_file,
        RELOAD_ERROR,
        "\nsuspend runtime transition is not implemented by Rust service contract",
    )?;
    log_event(options, "suspend rejected")?;
    notify_systemd("READY=1")
}

fn write_progress(path: &Path, byte: u8, suffix: &str) -> Result<(), String> {
    let mut bytes = vec![byte];
    bytes.extend_from_slice(suffix.as_bytes());
    write_bytes_file(path, &bytes, 0o644)
}

fn read_progress(path: &Path) -> Result<(u8, String), String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let Some(code) = bytes.first().copied() else {
        return Err(format!("unexpected format: {}", path.display()));
    };
    let content = String::from_utf8_lossy(&bytes[1..])
        .trim_start_matches('\n')
        .to_owned();
    Ok((code, content))
}

fn read_pid_file(path: &Path) -> Result<i32, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read pid file {}: {err}", path.display()))?;
    text.trim()
        .parse::<i32>()
        .map_err(|err| format!("failed to parse pid file {}: {err}", path.display()))
}

fn log_event(options: &ResidentRunOptions, message: &str) -> Result<(), String> {
    let Some(path) = &options.logfile else {
        return Ok(());
    };
    let line = if options.disable_timestamp {
        format!("{message}\n")
    } else {
        format!("{} {message}\n", std::process::id())
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create log dir {}: {err}", parent.display()))?;
    }
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("failed to open log {}: {err}", path.display()))?;
    file.write_all(line.as_bytes())
        .map_err(|err| format!("failed to write log {}: {err}", path.display()))
}

fn write_text_file(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    write_bytes_file(path, content.as_bytes(), mode)
}

fn write_bytes_file(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create path {}: {err}", parent.display()))?;
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("failed to chmod {}: {err}", path.display()))
}

fn notify_systemd(state: &str) -> Result<(), String> {
    let Ok(address) = env::var("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket =
        UnixDatagram::unbound().map_err(|err| format!("failed to create notify socket: {err}"))?;
    if address.starts_with('@') {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;

            let target = SocketAddr::from_abstract_name(address.as_bytes()[1..].to_vec())
                .map_err(|err| format!("failed to parse abstract notify socket: {err}"))?;
            socket
                .send_to_addr(state.as_bytes(), &target)
                .map_err(|err| format!("failed to notify systemd: {err}"))?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("abstract systemd notify sockets are unsupported on this platform".to_owned());
    }
    socket
        .send_to(state.as_bytes(), address)
        .map_err(|err| format!("failed to notify systemd: {err}"))?;
    Ok(())
}

fn block_service_signals() -> Result<(), String> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0 {
            return Err("failed to block resident service signals".to_owned());
        }
    }
    Ok(())
}

fn wait_service_signal() -> Result<i32, String> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut received = 0_i32;
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGHUP,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGQUIT,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        let status = libc::sigwait(&signals, &mut received);
        if status != 0 {
            return Err(format!(
                "failed to wait for resident service signal: {status}"
            ));
        }
    }
    Ok(received)
}
