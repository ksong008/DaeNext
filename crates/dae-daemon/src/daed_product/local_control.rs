use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};

const LOCAL_CONTROL_DIR_MODE: u32 = 0o700;
const LOCAL_CONTROL_SOCKET_MODE: u32 = 0o600;
const LOCAL_CONTROL_MAX_REQUEST_BYTES: u64 = 16 * 1024;
const LOCAL_CONTROL_SERVER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const LOCAL_CONTROL_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub(in crate::daed_product) struct ProductLocalControlRuntime {
    socket_path: PathBuf,
    join: Option<thread::JoinHandle<()>>,
}

impl ProductLocalControlRuntime {
    pub(in crate::daed_product) fn shutdown(mut self) -> io::Result<()> {
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| io::Error::other("local control thread panicked"))?;
        }
        remove_owned_local_control_socket(&self.socket_path)
    }
}

impl Drop for ProductLocalControlRuntime {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = remove_owned_local_control_socket(&self.socket_path);
    }
}

pub(in crate::daed_product) fn spawn_local_control_socket(
    app: Arc<AppState>,
) -> io::Result<ProductLocalControlRuntime> {
    let listener = bind_local_control_socket(&app.control_socket)?;
    listener.set_nonblocking(true)?;
    let socket_path = app.control_socket.clone();
    let join = thread::Builder::new()
        .name("daed-control".to_owned())
        .stack_size(PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT)
        .spawn(move || local_control_accept_loop(listener, app))?;
    Ok(ProductLocalControlRuntime {
        socket_path,
        join: Some(join),
    })
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

fn remove_owned_local_control_socket(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn local_control_accept_loop(listener: UnixListener, app: Arc<AppState>) {
    while !app.shutdown.is_requested() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if app.shutdown.is_requested() {
                    break;
                }
                let response = handle_local_control_stream(&app, &mut stream);
                let _ = write_local_control_response(&mut stream, response);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                app.shutdown
                    .wait_timeout(LOCAL_CONTROL_ACCEPT_POLL_INTERVAL);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
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
        Some(LOCAL_CONTROL_OP_STATUS) => handle_local_control_status(app),
        Some(LOCAL_CONTROL_OP_RELOAD) => handle_local_control_reload(app),
        Some(op) => {
            json!({"ok": false, "error": format!("unsupported local control operation: {op}")})
        }
        None => json!({"ok": false, "error": "missing local control operation"}),
    }
}

fn handle_local_control_status(app: &AppState) -> Value {
    let shutting_down = app.shutdown.is_requested();
    let product_ready = app.shutdown.is_ready();
    let runtime_running = app.runtime.is_running();
    let runtime_required = app.runtime.runtime_required_for_readiness();
    let ready = product_ready && (!runtime_required || runtime_running) && !shutting_down;
    json!({
        "ok": ready,
        "ready": ready,
        "productReady": product_ready,
        "shuttingDown": shutting_down,
        "runtimeRunning": runtime_running,
        "runtimeRequired": runtime_required,
        "contract": "local-control-readiness-v1",
    })
}

fn handle_local_control_reload(app: &AppState) -> Value {
    if app.shutdown.is_requested() {
        return json!({"ok": false, "error": "product shutdown is in progress"});
    }
    let reload_started_at = Instant::now();
    if !app.runtime.is_running() {
        if app.runtime.runtime_required_for_readiness() {
            return json!({
                "ok": false,
                "applied": false,
                "skipped": false,
                "runtimeRequired": true,
                "error": "runtime is required but not running",
            });
        }
        return json!({
            "ok": true,
            "applied": false,
            "skipped": true,
            "runtimeRequired": false,
            "reason": "runtime is stopped",
        });
    }
    match restore_runtime_from_state(
        &app.runtime,
        &app.state,
        Some(&app.config_dir),
        ProductRuntimeLifecycleLogMode::ReloadLocalControl,
    ) {
        Ok(report) => {
            let applied = report["applied"].as_bool().unwrap_or(true);
            let coalesced = report["coalesced"].as_bool().unwrap_or(false);
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "local-control".to_owned());
            fields.insert("applied".to_owned(), applied.to_string());
            fields.insert("coalesced".to_owned(), coalesced.to_string());
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
            json!({
                "ok": true,
                "applied": applied,
                "coalesced": coalesced,
                "skipped": !applied,
                "report": report
            })
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
    }
}

fn read_local_control_request(stream: &mut UnixStream) -> io::Result<Value> {
    stream.set_read_timeout(Some(LOCAL_CONTROL_SERVER_READ_TIMEOUT))?;
    let mut text = String::new();
    stream
        .take(LOCAL_CONTROL_MAX_REQUEST_BYTES.saturating_add(1))
        .read_to_string(&mut text)?;
    if text.len() as u64 > LOCAL_CONTROL_MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local control request exceeds the bounded message contract",
        ));
    }
    serde_json::from_str(text.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid local control request: {err}"),
        )
    })
}

fn write_local_control_response(stream: &mut UnixStream, response: Value) -> io::Result<()> {
    let bytes = bounded_local_control_response_bytes(response)?;
    stream.write_all(&bytes)?;
    stream.flush()
}

fn bounded_local_control_response_bytes(response: Value) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
    if bytes.len() as u64 > LOCAL_CONTROL_MAX_RESPONSE_BYTES {
        bytes = serde_json::to_vec(&json!({
            "ok": false,
            "error": "local control response exceeds the bounded message contract",
        }))
        .map_err(io::Error::other)?;
    }
    bytes.push(b'\n');
    Ok(bytes)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_control_reload_uses_live_runtime_state() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute_batch(
            r#"
            INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
                VALUES(1, 1, 1, 1, 0, '');
            "#,
        )
        .unwrap();
        drop(conn);
        let app = AppState {
            config_dir: dir.clone(),
            state: state.clone(),
            web_root: dir.clone(),
            api_only: true,
            control_socket: dir.join("control.sock"),
            shutdown: Arc::new(ProductShutdown::default()),
            runtime: Arc::new(ProductRuntimeManager::new()),
            runtime_sampler: None,
            latency_jobs: Arc::new(LatencyJobManager::default()),
            http_metrics: Arc::new(ProductHttpMetrics::default()),
            ui_runtime: product_ui_runtime(),
            auth_runtime: product_test_auth_runtime(),
            geodata_updates: Arc::new(geodata::ProductGeodataUpdateCoordinator::default()),
            geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
            geodata_update_runtime: None,
            control_runtime: product_test_control_runtime(),
        };

        assert!(app.shutdown.mark_ready());
        let fresh_status = handle_local_control_status(&app);
        assert_eq!(fresh_status["ready"], json!(true));
        assert_eq!(fresh_status["productReady"], json!(true));
        assert_eq!(fresh_status["runtimeRequired"], json!(false));
        assert_eq!(fresh_status["runtimeRunning"], json!(false));

        app.runtime.set_runtime_required_for_readiness(true);
        let status = handle_local_control_status(&app);
        assert_eq!(status["ready"], json!(false));
        assert_eq!(status["productReady"], json!(true));
        assert_eq!(status["runtimeRequired"], json!(true));
        assert_eq!(status["runtimeRunning"], json!(false));
        assert_eq!(status["contract"], json!("local-control-readiness-v1"));
        assert!(status.get("runtime").is_none());
        assert!(serde_json::to_vec(&status).unwrap().len() < 1024);

        let response = handle_local_control_reload(&app);
        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["applied"], json!(false));
        assert_eq!(response["skipped"], json!(false));
        assert_eq!(response["runtimeRequired"], json!(true));
        assert_eq!(
            response["error"],
            json!("runtime is required but not running")
        );

        app.runtime.set_runtime_required_for_readiness(false);
        let response = handle_local_control_reload(&app);
        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["applied"], json!(false));
        assert_eq!(response["skipped"], json!(true));
        assert_eq!(response["runtimeRequired"], json!(false));
        assert_eq!(response["reason"], json!("runtime is stopped"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn oversized_local_control_response_fails_as_compact_valid_json() {
        let bytes = bounded_local_control_response_bytes(json!({
            "ok": true,
            "report": "x".repeat(LOCAL_CONTROL_MAX_RESPONSE_BYTES as usize),
        }))
        .unwrap();
        let response: Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(response["ok"], json!(false));
        assert_eq!(
            response["error"],
            json!("local control response exceeds the bounded message contract")
        );
        assert!(bytes.len() as u64 <= LOCAL_CONTROL_MAX_RESPONSE_BYTES);
    }
}
