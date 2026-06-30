use super::*;
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};

const LOCAL_CONTROL_DIR_MODE: u32 = 0o700;
const LOCAL_CONTROL_SOCKET_MODE: u32 = 0o600;
const LOCAL_CONTROL_MAX_REQUEST_BYTES: u64 = 16 * 1024;
const LOCAL_CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(30);
const LOCAL_CONTROL_SERVER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const LOCAL_CONTROL_OP_RELOAD: &str = "reload";

pub(in crate::daed_product) fn spawn_local_control_socket(app: Arc<AppState>) -> io::Result<()> {
    let listener = bind_local_control_socket(&app.control_socket)?;
    thread::Builder::new()
        .name("daed-control".to_owned())
        .stack_size(PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT)
        .spawn(move || local_control_accept_loop(listener, app))?;
    Ok(())
}

pub(in crate::daed_product) fn run_local_control_reload_command(
    args: &[String],
) -> DaedProductOutput {
    let mut socket = std::env::var_os(PRODUCT_CONTROL_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_SOCKET));
    let mut timeout = LOCAL_CONTROL_IO_TIMEOUT;
    let mut json_output = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--control" | "--control-socket" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing reload --control value");
                };
                socket = value.into();
            }
            _ if arg.starts_with("--control=") => {
                socket = arg.split_once('=').unwrap().1.into();
            }
            _ if arg.starts_with("--control-socket=") => {
                socket = arg.split_once('=').unwrap().1.into();
            }
            "--timeout" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing reload --timeout value");
                };
                timeout = match parse_local_control_timeout(value) {
                    Ok(value) => value,
                    Err(err) => return DaedProductOutput::usage(err),
                };
            }
            _ if arg.starts_with("--timeout=") => {
                timeout = match parse_local_control_timeout(arg.split_once('=').unwrap().1) {
                    Ok(value) => value,
                    Err(err) => return DaedProductOutput::usage(err),
                };
            }
            "--json" => json_output = true,
            _ => return DaedProductOutput::usage(format!("unsupported reload argument: {arg}")),
        }
    }

    match request_local_control_reload(&socket, timeout) {
        Ok(response) => {
            if response["ok"].as_bool().unwrap_or(false) {
                if json_output {
                    DaedProductOutput::ok(format!("{response}\n"))
                } else {
                    DaedProductOutput::ok("OK\n".to_owned())
                }
            } else {
                let error = response["error"]
                    .as_str()
                    .unwrap_or("local reload request failed");
                DaedProductOutput::error(error)
            }
        }
        Err(err) => DaedProductOutput::error(format!("reload failed: {err}")),
    }
}

fn bind_local_control_socket(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(LOCAL_CONTROL_DIR_MODE))?;
    }
    remove_stale_local_control_socket(path)?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(LOCAL_CONTROL_SOCKET_MODE))?;
    Ok(listener)
}

fn remove_stale_local_control_socket(path: &Path) -> io::Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "control socket path exists and is not a socket: {}",
                path.display()
            ),
        ));
    }
    if UnixStream::connect(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "control socket is already accepting connections: {}",
                path.display()
            ),
        ));
    }
    fs::remove_file(path)
}

fn local_control_accept_loop(listener: UnixListener, app: Arc<AppState>) {
    for accepted in listener.incoming() {
        match accepted {
            Ok(mut stream) => {
                let response = handle_local_control_stream(&app, &mut stream);
                let _ = write_local_control_response(&mut stream, response);
            }
            Err(_) => break,
        }
    }
}

fn handle_local_control_stream(app: &AppState, stream: &mut UnixStream) -> Value {
    if let Err(err) = ensure_local_control_peer_is_root(stream) {
        return json!({"ok": false, "error": err.to_string()});
    }
    let request = match read_local_control_request(stream) {
        Ok(request) => request,
        Err(err) => return json!({"ok": false, "error": err.to_string()}),
    };
    match request.get("op").and_then(Value::as_str) {
        Some(LOCAL_CONTROL_OP_RELOAD) => handle_local_control_reload(app),
        Some(op) => {
            json!({"ok": false, "error": format!("unsupported local control operation: {op}")})
        }
        None => json!({"ok": false, "error": "missing local control operation"}),
    }
}

fn handle_local_control_reload(app: &AppState) -> Value {
    let reload_started_at = Instant::now();
    match should_restore_runtime_on_start(&app.state) {
        Ok(false) => json!({
            "ok": true,
            "applied": false,
            "skipped": true,
            "reason": "runtime is stopped",
        }),
        Err(err) => json!({"ok": false, "error": err.to_string()}),
        Ok(true) => match restore_runtime_from_state(
            &app.runtime,
            &app.state,
            Some(&app.config_dir),
            ProductRuntimeLifecycleLogMode::ReloadLocalControl,
        ) {
            Ok(report) => {
                let mut fields = BTreeMap::new();
                fields.insert("source".to_owned(), "local-control".to_owned());
                fields.insert("applied".to_owned(), "true".to_owned());
                fields.insert(
                    "elapsed".to_owned(),
                    format!("{:?}", reload_started_at.elapsed()),
                );
                let _ = append_lifecycle_log_fields_for_config(
                    &app.config_dir,
                    &app.state,
                    "info",
                    "[Reload] Finished",
                    fields,
                );
                json!({"ok": true, "applied": true, "skipped": false, "report": report})
            }
            Err(err) => {
                let mut fields = BTreeMap::new();
                fields.insert("source".to_owned(), "local-control".to_owned());
                fields.insert("error".to_owned(), err.clone());
                let _ = append_lifecycle_log_fields_for_config(
                    &app.config_dir,
                    &app.state,
                    "error",
                    "[Reload] Failed to reload",
                    fields,
                );
                json!({"ok": false, "error": err})
            }
        },
    }
}

fn read_local_control_request(stream: &mut UnixStream) -> io::Result<Value> {
    stream.set_read_timeout(Some(LOCAL_CONTROL_SERVER_READ_TIMEOUT))?;
    let mut text = String::new();
    stream
        .take(LOCAL_CONTROL_MAX_REQUEST_BYTES)
        .read_to_string(&mut text)?;
    serde_json::from_str(text.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid local control request: {err}"),
        )
    })
}

fn write_local_control_response(stream: &mut UnixStream, response: Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()
}

fn request_local_control_reload(path: &Path, timeout: Duration) -> io::Result<Value> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(br#"{"op":"reload"}"#)?;
    stream.write_all(b"\n")?;
    stream.shutdown(Shutdown::Write)?;
    let mut text = String::new();
    stream
        .take(LOCAL_CONTROL_MAX_REQUEST_BYTES)
        .read_to_string(&mut text)?;
    serde_json::from_str(text.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid local control response: {err}"),
        )
    })
}

fn ensure_local_control_peer_is_root(stream: &UnixStream) -> io::Result<()> {
    let uid = local_control_peer_uid(stream)?;
    if uid == 0 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "local control socket requires uid 0",
    ))
}

fn local_control_peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    };
    if status == 0 {
        Ok(credentials.uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn parse_local_control_timeout(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("invalid reload --timeout value".to_owned());
    }
    if let Some(milliseconds) = value.strip_suffix("ms") {
        return milliseconds
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|_| "invalid reload --timeout value".to_owned());
    }
    let seconds = value.strip_suffix('s').unwrap_or(value);
    seconds
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| "invalid reload --timeout value".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_control_timeout_accepts_seconds_and_milliseconds() {
        assert_eq!(
            parse_local_control_timeout("30").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_local_control_timeout("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_local_control_timeout("250ms").unwrap(),
            Duration::from_millis(250)
        );
        assert!(parse_local_control_timeout("bad").is_err());
    }
}
