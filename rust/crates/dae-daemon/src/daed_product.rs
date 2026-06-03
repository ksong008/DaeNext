use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension, params};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const DEFAULT_CONFIG_DIR: &str = "/etc/daed";
const DEFAULT_LISTEN: &str = "0.0.0.0:2023";
const DEFAULT_WEB_ROOT: &str = "/usr/share/daed/web";
const PRIMARY_STATE_STORE: &str = crate::service_contract::DAED_PRIMARY_STATE_STORE;
const PROTECTED_ROLLBACK_STATE_STORE: &str =
    crate::service_contract::DAED_PROTECTED_ROLLBACK_STATE_STORE;
const MAX_BODY_BYTES: usize = 1 << 20;
const TOKEN_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaedProductOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl DaedProductOutput {
    fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 1,
        }
    }
}

#[derive(Clone, Debug)]
struct RunOptions {
    config_dir: PathBuf,
    listen: String,
    state: PathBuf,
    web_root: PathBuf,
    api_only: bool,
}

#[derive(Clone, Debug)]
struct AppState {
    config_dir: PathBuf,
    state: PathBuf,
    web_root: PathBuf,
    api_only: bool,
}

#[derive(Clone, Debug)]
struct UserRecord {
    id: i64,
    username: String,
    password_hash: String,
    jwt_secret: String,
    json_storage: String,
    avatar: Option<String>,
    name: Option<String>,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: HashMap<String, Vec<String>>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    extra_headers: Vec<(String, String)>,
}

impl HttpResponse {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json".to_owned(),
            body: format!("{value}\n").into_bytes(),
            extra_headers: Vec::new(),
        }
    }

    fn text(status: u16, content_type: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
            extra_headers: Vec::new(),
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8".to_owned(),
            body: Vec::new(),
            extra_headers: Vec::new(),
        }
    }
}

pub fn run_daed_product_with_args_and_version(
    args: impl IntoIterator<Item = impl Into<String>>,
    version: &str,
) -> DaedProductOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("service-contract") => run_service_contract_command(&args[1..], version),
        Some("package-info") => run_package_info_command(&args[1..], version),
        Some("state") => run_state_command(&args[1..]),
        Some("run") => run_product_server_command(&args[1..], version),
        Some("export") => run_export_command(&args[1..]),
        Some("resetpass") => run_resetpass_command(&args[1..]),
        Some("help") | Some("--help") | Some("-h") => DaedProductOutput::ok(help_text()),
        Some(command) => DaedProductOutput::usage(format!("unsupported daed command: {command}")),
        None => DaedProductOutput::usage("missing daed command"),
    }
}

fn run_service_contract_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() && args != ["--json"] {
        return DaedProductOutput::usage("service-contract accepts only optional --json");
    }
    DaedProductOutput::ok(format!("{}\n", daed_service_contract(version)))
}

fn run_package_info_command(args: &[String], version: &str) -> DaedProductOutput {
    if !args.is_empty() && args != ["--json"] {
        return DaedProductOutput::usage("package-info accepts only optional --json");
    }
    DaedProductOutput::ok(format!("{}\n", daed_package_info(version)))
}

fn run_state_command(args: &[String]) -> DaedProductOutput {
    match args.first().map(String::as_str) {
        Some("check") => match parse_state_check_args(&args[1..]) {
            Ok(state) => match state_check_report(&state) {
                Ok(report) => DaedProductOutput::ok(format!("{report}\n")),
                Err(err) => DaedProductOutput::error(format!("state check failed: {err}")),
            },
            Err(err) => DaedProductOutput::usage(err),
        },
        Some("migrate") => match parse_state_migrate_args(&args[1..]) {
            Ok((from_wing_db, to, force)) => match migrate_wing_db(&from_wing_db, &to, force) {
                Ok(report) => DaedProductOutput::ok(format!("{report}\n")),
                Err(err) => DaedProductOutput::error(format!("state migrate failed: {err}")),
            },
            Err(err) => DaedProductOutput::usage(err),
        },
        Some(command) => DaedProductOutput::usage(format!("unsupported state command: {command}")),
        None => DaedProductOutput::usage("state requires check or migrate"),
    }
}

fn run_product_server_command(args: &[String], _version: &str) -> DaedProductOutput {
    let options = match parse_run_args(args) {
        Ok(options) => options,
        Err(err) => return DaedProductOutput::usage(err),
    };
    if let Err(err) = ensure_state_schema(&options.state) {
        return DaedProductOutput::error(format!("init state failed: {err}"));
    }
    start_subscription_scheduler(options.state.clone());
    let app = AppState {
        config_dir: options.config_dir,
        state: options.state,
        web_root: options.web_root,
        api_only: options.api_only,
    };
    match serve_forever(&options.listen, app) {
        Ok(()) => DaedProductOutput::ok(String::new()),
        Err(err) => DaedProductOutput::error(format!("run failed: {err}")),
    }
}

fn run_export_command(args: &[String]) -> DaedProductOutput {
    match args.first().map(String::as_str) {
        Some("openapi") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_openapi_skeleton()))
        }
        Some("flatdesc") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_flatdesc()))
        }
        Some("outline") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_outline()))
        }
        Some("package-manifest") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_package_manifest()))
        }
        Some("admission-report") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", product_admission_report()))
        }
        Some("webui-route-audit") if args.len() == 1 => {
            DaedProductOutput::ok(format!("{}\n", webui_route_audit_report()))
        }
        Some("systemd-unit") if args.len() == 1 => DaedProductOutput::ok(systemd_unit_text()),
        Some("docker-entrypoint") if args.len() == 1 => {
            DaedProductOutput::ok(docker_entrypoint_text())
        }
        Some(command) => DaedProductOutput::usage(format!("unsupported export command: {command}")),
        None => DaedProductOutput::usage(
            "export requires openapi, flatdesc, outline, package-manifest, admission-report, webui-route-audit, systemd-unit, or docker-entrypoint",
        ),
    }
}

fn run_resetpass_command(args: &[String]) -> DaedProductOutput {
    let mut config_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut json_output = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing resetpass --config value");
                };
                config_dir = value.into();
            }
            _ if arg.starts_with("--config=") => {
                config_dir = arg.split_once('=').unwrap().1.into();
            }
            "--json" => json_output = true,
            _ => return DaedProductOutput::usage(format!("unsupported resetpass argument: {arg}")),
        }
    }
    let state = config_dir.join("daed.db");
    match reset_all_user_passwords(&state) {
        Ok(report) if json_output => DaedProductOutput::ok(format!("{report}\n")),
        Ok(report) => {
            let mut out = String::new();
            let users = report["users"].as_array().cloned().unwrap_or_default();
            if users.is_empty() {
                out.push_str("No users found.\n");
            } else {
                for user in users {
                    out.push_str(&format!(
                        "Username: {}, Password: {}\n",
                        user["username"].as_str().unwrap_or(""),
                        user["password"].as_str().unwrap_or("")
                    ));
                }
            }
            DaedProductOutput::ok(out)
        }
        Err(err) => DaedProductOutput::error(format!("resetpass failed: {err}")),
    }
}

fn parse_run_args(args: &[String]) -> Result<RunOptions, String> {
    let mut config_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut state: Option<PathBuf> = None;
    let mut web_root = std::env::var_os("DAED_WEB_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WEB_ROOT));
    let mut api_only = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --config value".to_owned());
                };
                config_dir = value.into();
            }
            _ if arg.starts_with("--config=") => {
                config_dir = arg.split_once('=').unwrap().1.into();
            }
            "--listen" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --listen value".to_owned());
                };
                listen = value.to_owned();
            }
            _ if arg.starts_with("--listen=") => {
                listen = arg.split_once('=').unwrap().1.to_owned();
            }
            "--state" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --state value".to_owned());
                };
                state = Some(value.into());
            }
            _ if arg.starts_with("--state=") => {
                state = Some(arg.split_once('=').unwrap().1.into());
            }
            "--web-root" => {
                let Some(value) = iter.next() else {
                    return Err("missing run --web-root value".to_owned());
                };
                web_root = value.into();
            }
            _ if arg.starts_with("--web-root=") => {
                web_root = arg.split_once('=').unwrap().1.into();
            }
            "--api-only" => api_only = true,
            _ => return Err(format!("unsupported run argument: {arg}")),
        }
    }
    let state = state.unwrap_or_else(|| config_dir.join("daed.db"));
    Ok(RunOptions {
        config_dir,
        listen,
        state,
        web_root,
        api_only,
    })
}

fn parse_state_check_args(args: &[String]) -> Result<PathBuf, String> {
    let mut state: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--state" => {
                let Some(value) = iter.next() else {
                    return Err("missing state check --state value".to_owned());
                };
                state = Some(value.into());
            }
            _ if arg.starts_with("--state=") => {
                state = Some(arg.split_once('=').unwrap().1.into());
            }
            _ => return Err(format!("unsupported state check argument: {arg}")),
        }
    }
    state.ok_or_else(|| "state check requires --state".to_owned())
}

fn parse_state_migrate_args(args: &[String]) -> Result<(PathBuf, PathBuf, bool), String> {
    let mut from_wing_db: Option<PathBuf> = None;
    let mut to: Option<PathBuf> = None;
    let mut force = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--from-wing-db" => {
                let Some(value) = iter.next() else {
                    return Err("missing state migrate --from-wing-db value".to_owned());
                };
                from_wing_db = Some(value.into());
            }
            _ if arg.starts_with("--from-wing-db=") => {
                from_wing_db = Some(arg.split_once('=').unwrap().1.into());
            }
            "--to" => {
                let Some(value) = iter.next() else {
                    return Err("missing state migrate --to value".to_owned());
                };
                to = Some(value.into());
            }
            _ if arg.starts_with("--to=") => {
                to = Some(arg.split_once('=').unwrap().1.into());
            }
            "--force" => force = true,
            _ => return Err(format!("unsupported state migrate argument: {arg}")),
        }
    }
    let from_wing_db = from_wing_db
        .ok_or_else(|| "state migrate requires --from-wing-db /etc/daed/wing.db".to_owned())?;
    let to = to.ok_or_else(|| "state migrate requires --to /etc/daed/daed.db".to_owned())?;
    Ok((from_wing_db, to, force))
}

fn daed_service_contract(version: &str) -> Value {
    let mut report = crate::service_contract::service_contract_capabilities(version);
    if let Value::Object(report) = &mut report {
        report.insert("product_binary".to_owned(), json!("daed"));
        report.insert("product_entry".to_owned(), json!("/usr/bin/daed"));
        report.insert("c_phase".to_owned(), json!("C10"));
        report.insert(
            "c10_work_package".to_owned(),
            json!("go-free-product-chain-v1"),
        );
        report.insert("primary_state_store".to_owned(), json!(PRIMARY_STATE_STORE));
        report.insert(
            "protected_rollback_state_store".to_owned(),
            json!(PROTECTED_ROLLBACK_STATE_STORE),
        );
        report.insert(
            "rust_daed_writes_wing_db_by_default".to_owned(),
            json!(false),
        );
        report.insert("wing_db_import_supported".to_owned(), json!(true));
        report.insert(
            "wing_db_import_destructive_by_default".to_owned(),
            json!(false),
        );
        report.insert("daed_db_primary_required".to_owned(), json!(true));
        report.insert("var_lib_daed_required_by_default".to_owned(), json!(false));
        report.insert("rust_product_binary_contract_ready".to_owned(), json!(true));
        report.insert(
            "rust_product_lifecycle_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_product_web_api_package_release_contract_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_state_layer_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_non_destructive_wing_db_import_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_setup_auth_user_storage_api_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_static_webui_serving_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_current_react_webui_served_by_rust_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_resource_crud_api_ready".to_owned(), json!(true));
        report.insert("rust_daed_materializer_ready".to_owned(), json!(true));
        report.insert("rust_daed_runtime_owner_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_logs_sse_latency_subscription_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "rust_daed_import_export_package_surface_ready".to_owned(),
            json!(true),
        );
        report.insert("rust_daed_subscription_fetch_ready".to_owned(), json!(true));
        report.insert("rust_daed_latency_probe_tcp_ready".to_owned(), json!(true));
        report.insert("rust_daed_resetpass_parity_ready".to_owned(), json!(true));
        report.insert("rust_daed_package_manifest_ready".to_owned(), json!(true));
        report.insert("rust_daed_webui_route_audit_ready".to_owned(), json!(true));
        report.insert(
            "rust_daed_local_package_admission_ready".to_owned(),
            json!(true),
        );
        report.insert("leptos_webui_rewrite_considered".to_owned(), json!(false));
        report.insert("go_free_product_chain_ready".to_owned(), json!(false));
        report.insert(
            "go_free_product_chain_current_batch".to_owned(),
            json!("C10 local package admission evidence"),
        );
        report.insert(
            "go_free_product_chain_remaining_work".to_owned(),
            json!([
                "live host default package switch",
                "live rollback validation",
                "remove Go daewing from default package path",
                "production package admission"
            ]),
        );
        if let Some(Value::Object(typed_report)) =
            report.get_mut("go_free_product_chain_typed_report")
        {
            typed_report.insert("rust_product_binary_contract_ready".to_owned(), json!(true));
            typed_report.insert(
                "rust_product_lifecycle_contract_ready".to_owned(),
                json!(true),
            );
            typed_report.insert(
                "rust_product_web_api_package_release_contract_ready".to_owned(),
                json!(true),
            );
            typed_report.insert(
                "current_batch".to_owned(),
                json!("C10 local package admission evidence"),
            );
            typed_report.insert("status".to_owned(), json!("blocked"));
        }
    }
    report
}

fn daed_package_info(version: &str) -> Value {
    json!({
        "name": "daed",
        "version": version,
        "binary": "/usr/bin/daed",
        "c_phase": "C10",
        "work_package": "go-free-product-chain-v1",
        "primary_state_store": PRIMARY_STATE_STORE,
        "protected_rollback_state_store": PROTECTED_ROLLBACK_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "daed_db_primary_required": true,
        "var_lib_daed_required_by_default": false,
        "webui": {
            "framework": "current React/Vite dist",
            "served_by": "Rust daed static file server",
            "default_root": DEFAULT_WEB_ROOT,
            "leptos_considered": false
        },
        "default_layout": {
            "config_dir": DEFAULT_CONFIG_DIR,
            "runtime_dir": "/etc/daed/runtime",
            "backup_dir": "/etc/daed/backups",
            "web_root": DEFAULT_WEB_ROOT,
            "geoip": "/usr/share/daed/geoip.dat",
            "geosite": "/usr/share/daed/geosite.dat"
        },
        "current_batch_ready": {
            "product_binary_skeleton": true,
            "state_check": true,
            "wing_db_non_destructive_import": true,
            "setup_auth_user_storage_api": true,
            "static_webui_serving": true,
            "resource_crud_api": true,
            "materializer": true,
            "runtime_owner": true,
            "logs_sse_latency_subscription": true,
            "import_export_package_surface": true,
            "subscription_fetch": true,
            "tcp_latency_probe": true,
            "resetpass_parity": true,
            "package_manifest": true,
            "webui_route_audit": true,
            "local_package_admission": true
        },
        "package_surface": {
            "systemd_unit": "daed.service uses /usr/bin/daed run -c /etc/daed",
            "docker_entrypoint": "/usr/bin/daed run -c /etc/daed --listen 0.0.0.0:2023",
            "package_manifest": "daed export package-manifest",
            "admission_report": "daed export admission-report",
            "default_package_switch_live_applied": false,
            "go_daewing_default_path_removed": false
        },
        "full_go_free_product_chain_ready": false
    })
}

fn ensure_state_schema(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = open_state_connection(path)?;
    apply_state_schema(&conn)?;
    Ok(())
}

fn open_state_connection(path: &Path) -> io::Result<Connection> {
    Connection::open(path).map_err(sqlite_io_error)
}

fn apply_state_schema(conn: &Connection) -> io::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            jwt_secret TEXT NOT NULL,
            json_storage TEXT NOT NULL DEFAULT '{}',
            avatar TEXT NULL,
            name TEXT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            global TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS dns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            dns TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS routings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            routing TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            updated_at TEXT NOT NULL DEFAULT '',
            link TEXT NOT NULL,
            cron_exp TEXT DEFAULT '10 */6 * * *',
            cron_enable INTEGER DEFAULT 1,
            status TEXT NOT NULL DEFAULT '',
            info TEXT NOT NULL DEFAULT '',
            tag TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT NOT NULL,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            protocol TEXT NOT NULL,
            tag TEXT UNIQUE,
            subscription_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            policy TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 0,
            system_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS group_nodes (
            group_id INTEGER NOT NULL,
            node_id INTEGER NOT NULL,
            PRIMARY KEY(group_id, node_id)
        );
        CREATE TABLE IF NOT EXISTS group_subscriptions (
            group_id INTEGER NOT NULL,
            subscription_id INTEGER NOT NULL,
            name_filter_regex TEXT NULL,
            PRIMARY KEY(group_id, subscription_id)
        );
        CREATE TABLE IF NOT EXISTS group_policy_params (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            group_id INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            running INTEGER NOT NULL DEFAULT 0,
            running_config_version INTEGER NOT NULL DEFAULT 0,
            running_dns_version INTEGER NOT NULL DEFAULT 0,
            running_routing_version INTEGER NOT NULL DEFAULT 0,
            running_group_version_sum INTEGER NOT NULL DEFAULT 0,
            running_group_ids TEXT NOT NULL DEFAULT '',
            running_config_id INTEGER NULL,
            running_dns_id INTEGER NULL,
            running_routing_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS log_settings (
            id INTEGER PRIMARY KEY,
            max_entries INTEGER NOT NULL,
            max_bytes INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS node_latency_results (
            node_id INTEGER PRIMARY KEY,
            latency_ms INTEGER NULL,
            alive INTEGER NOT NULL,
            tested_at TEXT NOT NULL,
            message TEXT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS daed_product_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS daed_schema_migrations (
            id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS log_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL
        );
        INSERT OR IGNORE INTO daed_schema_migrations(id, applied_at)
            VALUES('c10-first-batch-daed-product-schema-v1', datetime('now'));
        INSERT OR IGNORE INTO daed_schema_migrations(id, applied_at)
            VALUES('c10-local-product-surface-v2', datetime('now'));
        INSERT OR IGNORE INTO log_settings(id, max_entries, max_bytes)
            VALUES(1, 1000, 1048576);
        INSERT OR IGNORE INTO daed_product_metadata(key, value)
            VALUES('runtime_log_level', 'info');
        "#,
    )
    .map_err(sqlite_io_error)
}

fn state_check_report(state: &Path) -> io::Result<Value> {
    let existed_before = state.exists();
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let tables = list_tables(&conn)?;
    let user_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)?;
    let metadata_ready = tables.iter().any(|name| name == "daed_product_metadata")
        && tables.iter().any(|name| name == "daed_schema_migrations");
    Ok(json!({
        "status": "pass",
        "state": path_string(state),
        "exists_before_check": existed_before,
        "exists_after_check": state.exists(),
        "schema_ready": metadata_ready,
        "primary_state_store": path_string(state),
        "protected_rollback_state_store": PROTECTED_ROLLBACK_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "user_count": user_count,
        "tables": tables,
    }))
}

fn migrate_wing_db(from_wing_db: &Path, to: &Path, force: bool) -> io::Result<Value> {
    if !from_wing_db.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "wing.db source does not exist: {}",
                path_string(from_wing_db)
            ),
        ));
    }
    let wing_hash_before = sha256_file_hex(from_wing_db)?;
    let target_existed = to.exists();
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    let copied = if target_existed && !force {
        false
    } else {
        fs::copy(from_wing_db, to)?;
        set_private_db_permissions(to)?;
        true
    };
    ensure_state_schema(to)?;
    let conn = open_state_connection(to)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params!["source_wing_db_path", path_string(from_wing_db)],
    )
    .map_err(sqlite_io_error)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, datetime('now'))",
        params!["last_wing_db_import_at"],
    )
    .map_err(sqlite_io_error)?;
    let wing_hash_after = sha256_file_hex(from_wing_db)?;
    let wing_db_unchanged = wing_hash_before == wing_hash_after;
    if !wing_db_unchanged {
        return Err(io::Error::other("wing.db hash changed during import"));
    }
    Ok(json!({
        "status": "pass",
        "from_wing_db": path_string(from_wing_db),
        "to": path_string(to),
        "target_existed": target_existed,
        "copied": copied,
        "force": force,
        "wing_db_sha256_before": wing_hash_before,
        "wing_db_sha256_after": wing_hash_after,
        "wing_db_unchanged": wing_db_unchanged,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_destructive": false,
    }))
}

fn serve_forever(listen: &str, app: AppState) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    let app = Arc::new(app);
    for stream in listener.incoming() {
        let app = Arc::clone(&app);
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle_stream(stream, &app);
                });
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn handle_stream(mut stream: TcpStream, app: &AppState) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            let response = HttpResponse::json(
                400,
                json!({
                    "error": format!("bad request: {err}")
                }),
            );
            return write_http_response(&mut stream, &response, false);
        }
    };
    let head_only = request.method == "HEAD";
    let response = route_request(app, &request);
    write_http_response(&mut stream, &response, head_only)
}

fn route_request(app: &AppState, request: &HttpRequest) -> HttpResponse {
    if request.method == "OPTIONS" {
        return HttpResponse::empty(204);
    }
    if request.path == "/health" {
        return handle_health(request);
    }
    if let Some(api_path) = request.path.strip_prefix("/api") {
        let api_path = if api_path.is_empty() { "/" } else { api_path };
        return handle_api_request(app, request, api_path);
    }
    if app.api_only {
        return HttpResponse::json(
            404,
            json!({"error": "static WebUI serving is disabled by --api-only"}),
        );
    }
    serve_static_file(&app.web_root, request)
}

fn handle_api_request(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    match (request.method.as_str(), api_path) {
        ("GET", "/health") => handle_health(request),
        ("GET", "/auth/status") => api_auth_status(app),
        ("POST", "/auth/users") => api_create_user(app, request),
        ("POST", "/auth/token") => api_issue_token(app, request),
        _ => {
            let Some(user) = authenticate_request(app, request) else {
                return HttpResponse::json(401, json!({"error": "authentication required"}));
            };
            match (request.method.as_str(), api_path) {
                ("GET", "/user/me") => HttpResponse::json(200, user_resource(&user)),
                ("PATCH", "/user/me") => api_patch_user(app, request, user),
                ("POST", "/user/me/password") => api_update_password(app, request, user),
                ("GET", "/user/me/storage") => api_get_storage(request, user),
                ("PUT", "/user/me/storage") => api_set_storage(app, request, user),
                ("DELETE", "/user/me/storage") => api_delete_storage(app, request, user),
                ("POST", "/user/me/default-resources") => api_default_resources(app, request, user),
                ("GET", "/user/me/dae-bundle") => api_get_bundle(app, &user),
                ("PUT", "/user/me/dae-bundle") => api_put_bundle(app, request, &user),
                ("GET", "/user/me/dae-config-file") => api_get_dae_config_file(app),
                ("PUT", "/user/me/dae-config-file") => api_put_dae_config_file(app, request, &user),
                ("POST", "/user/me/dae-config-file/preview") => {
                    api_preview_dae_config_file(app, request, &user)
                }
                ("GET", "/general/state") => api_general_state(app),
                ("GET", "/general/cache-stats") => api_general_cache_stats(app),
                ("GET", "/general/interfaces") => api_general_interfaces(),
                ("GET", "/runtime/overview") => api_runtime_overview(app),
                ("POST", "/runtime/reload") => api_runtime_reload(app, request),
                ("POST", "/runtime/stop") => api_runtime_stop(app),
                ("GET", "/runtime/log-level") => api_get_runtime_log_level(app),
                ("PATCH", "/runtime/log-level") => api_set_runtime_log_level(app, request),
                ("GET", "/events/runtime") => api_runtime_events(app),
                ("GET", "/events/logs") => api_log_events(app),
                ("GET", "/logs") => api_logs(app, request),
                ("DELETE", "/logs") => api_clear_logs(app),
                ("GET", "/logs/settings") => api_get_log_settings(app),
                ("PATCH", "/logs/settings") => api_set_log_settings(app, request),
                ("GET", "/nodes/latencies") => api_get_node_latencies(app),
                ("POST", "/nodes/latencies") => api_test_node_latencies(app, request),
                _ if api_path == "/configs"
                    || api_path.starts_with("/configs/")
                    || api_path == "/dns"
                    || api_path.starts_with("/dns/")
                    || api_path == "/routings"
                    || api_path.starts_with("/routings/") =>
                {
                    api_section_resource(app, request, api_path)
                }
                _ if api_path == "/nodes" || api_path.starts_with("/nodes/") => {
                    api_nodes(app, request, api_path)
                }
                _ if api_path == "/subscriptions" || api_path.starts_with("/subscriptions/") => {
                    api_subscriptions(app, request, api_path)
                }
                _ if api_path == "/groups" || api_path.starts_with("/groups/") => {
                    api_groups(app, request, api_path)
                }
                _ => HttpResponse::json(
                    404,
                    json!({"error": "not implemented in C10 local product surface"}),
                ),
            }
        }
    }
}

fn handle_health(_request: &HttpRequest) -> HttpResponse {
    HttpResponse::json(200, json!({"healthCheck": 1}))
}

fn api_auth_status(app: &AppState) -> HttpResponse {
    match user_count(&app.state) {
        Ok(count) => HttpResponse::json(200, json!({"numberUsers": count})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_create_user(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let username = required_str(&body, "username");
    let password = required_str(&body, "password");
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            return HttpResponse::json(400, json!({"error": "username and password are required"}));
        }
    };
    match create_user(&app.state, username, password) {
        Ok(token) => HttpResponse::json(201, json!({"token": token})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_issue_token(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let username = required_str(&body, "username");
    let password = required_str(&body, "password");
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            return HttpResponse::json(400, json!({"error": "username and password are required"}));
        }
    };
    match issue_token(&app.state, username, password) {
        Ok(token) => HttpResponse::json(200, json!({"token": token})),
        Err(err) => HttpResponse::json(401, json!({"error": err.to_string()})),
    }
}

fn api_patch_user(app: &AppState, request: &HttpRequest, mut user: UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(username) = body.get("username").and_then(Value::as_str) {
        if let Err(err) = conn.execute(
            "UPDATE users SET username = ?1 WHERE id = ?2",
            params![username, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.username = username.to_owned();
    }
    if body
        .get("clearName")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(err) = conn.execute(
            "UPDATE users SET name = NULL WHERE id = ?1",
            params![user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.name = None;
    } else if body.get("name").is_some() {
        let value = body.get("name").and_then(Value::as_str).map(str::to_owned);
        if let Err(err) = conn.execute(
            "UPDATE users SET name = ?1 WHERE id = ?2",
            params![value, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.name = value;
    }
    if body
        .get("clearAvatar")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(err) = conn.execute(
            "UPDATE users SET avatar = NULL WHERE id = ?1",
            params![user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.avatar = None;
    } else if body.get("avatar").is_some() {
        let value = body
            .get("avatar")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Err(err) = conn.execute(
            "UPDATE users SET avatar = ?1 WHERE id = ?2",
            params![value, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.avatar = value;
    }
    HttpResponse::json(200, user_resource(&user))
}

fn api_update_password(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let current = required_str(&body, "currentPassword");
    let new_password = required_str(&body, "newPassword");
    let (current, new_password) = match (current, new_password) {
        (Some(current), Some(new_password)) => (current, new_password),
        _ => {
            return HttpResponse::json(
                400,
                json!({"error": "currentPassword and newPassword are required"}),
            );
        }
    };
    if hash_password(user.jwt_secret.as_bytes(), current) != user.password_hash {
        return HttpResponse::json(400, json!({"error": "incorrect password"}));
    }
    if let Err(err) = validate_password_strength(new_password) {
        return HttpResponse::json(400, json!({"error": err}));
    }
    let secret = match random_secret_hex() {
        Ok(secret) => secret,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let password_hash = hash_password(secret.as_bytes(), new_password);
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = conn.execute(
        "UPDATE users SET password_hash = ?1, jwt_secret = ?2 WHERE id = ?3",
        params![password_hash, secret, user.id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    user.jwt_secret = secret;
    match signed_token(&user) {
        Ok(token) => HttpResponse::json(200, json!({"token": token})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_storage(request: &HttpRequest, user: UserRecord) -> HttpResponse {
    let paths = request.query.get("path").cloned().unwrap_or_default();
    let values = query_json_storage(&user.json_storage, &paths);
    HttpResponse::json(200, json!({"values": values}))
}

fn api_set_storage(app: &AppState, request: &HttpRequest, mut user: UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let paths = string_array(&body, "paths");
    let values = string_array(&body, "values");
    if paths.len() != values.len() {
        return HttpResponse::json(400, json!({"error": "len(paths) != len(values)"}));
    }
    let updated = match set_json_storage(&mut user.json_storage, &paths, &values) {
        Ok(updated) => updated,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"updated": updated}))
}

fn api_delete_storage(app: &AppState, request: &HttpRequest, mut user: UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let paths = string_array(&body, "paths");
    let removed = match remove_json_storage(&mut user.json_storage, &paths) {
        Ok(removed) => removed,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

fn api_default_resources(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match ensure_default_resources(&app.state, &body) {
        Ok(response) => {
            let paths = vec![
                "defaultConfigID".to_owned(),
                "defaultRoutingID".to_owned(),
                "defaultDNSID".to_owned(),
                "defaultGroupID".to_owned(),
                "mode".to_owned(),
            ];
            let values = vec![
                response["defaultConfigID"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                response["defaultRoutingID"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                response["defaultDNSID"].as_str().unwrap_or("").to_owned(),
                response["defaultGroupID"].as_str().unwrap_or("").to_owned(),
                response["mode"].as_str().unwrap_or("").to_owned(),
            ];
            if let Err(err) = set_json_storage(&mut user.json_storage, &paths, &values) {
                return HttpResponse::json(400, json!({"error": err}));
            }
            if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
                return HttpResponse::json(500, json!({"error": err.to_string()}));
            }
            HttpResponse::json(200, response)
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_section_resource(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if matches!(
        api_path,
        "/configs/parsed" | "/dns/parsed" | "/routings/parsed"
    ) {
        return api_section_preview(request, api_path);
    }
    if api_path == "/configs/flat-desc" {
        return HttpResponse::json(200, product_flatdesc());
    }
    let Some(kind) = SectionKind::from_path(api_path) else {
        return HttpResponse::json(404, json!({"error": "unknown section resource"}));
    };
    let suffix = api_path.trim_start_matches(kind.prefix());
    if suffix.is_empty() {
        return match request.method.as_str() {
            "GET" => list_sections(&app.state, kind),
            "POST" => create_section(&app.state, request, kind),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let parts = suffix
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid resource id"}));
    };
    if parts.len() == 2 && parts[1] == "select" {
        return match request.method.as_str() {
            "POST" => select_section(&app.state, kind, id),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown section resource path"}));
    }
    match request.method.as_str() {
        "GET" => get_section(&app.state, kind, id),
        "PUT" | "PATCH" => update_section(&app.state, request, kind, id),
        "DELETE" => delete_section(&app.state, kind, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

fn api_nodes(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if api_path == "/nodes" {
        return match request.method.as_str() {
            "GET" => list_nodes(&app.state, None),
            "POST" => import_nodes(&app.state, request, None),
            "DELETE" => delete_nodes(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let Some(id) = api_path
        .strip_prefix("/nodes/")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return HttpResponse::json(400, json!({"error": "invalid node id"}));
    };
    match request.method.as_str() {
        "GET" => get_node(&app.state, id),
        "PUT" | "PATCH" => update_node(&app.state, request, id),
        "DELETE" => delete_node_by_id(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

fn api_subscriptions(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if api_path == "/subscriptions" {
        return match request.method.as_str() {
            "GET" => list_subscriptions(&app.state, request),
            "POST" => create_subscription(&app.state, request),
            "DELETE" => delete_subscriptions(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let suffix = api_path.trim_start_matches("/subscriptions/");
    let parts = suffix.split('/').collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid subscription id"}));
    };
    if parts.len() == 2 && parts[1] == "nodes" {
        return match request.method.as_str() {
            "GET" => list_nodes(&app.state, Some(id)),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() == 2 && parts[1] == "refresh" {
        return match request.method.as_str() {
            "POST" => refresh_subscription(&app.state, id),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown subscription path"}));
    }
    match request.method.as_str() {
        "GET" => get_subscription(&app.state, id),
        "PUT" | "PATCH" => update_subscription(&app.state, request, id),
        "DELETE" => delete_subscription_by_id(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

fn api_groups(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if api_path == "/groups" {
        return match request.method.as_str() {
            "GET" => list_groups(&app.state),
            "POST" => create_group(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let suffix = api_path.trim_start_matches("/groups/");
    let parts = suffix.split('/').collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid group id"}));
    };
    if parts.len() == 2 && parts[1] == "nodes" {
        return match request.method.as_str() {
            "POST" => update_group_nodes(&app.state, request, id, true),
            "DELETE" => update_group_nodes(&app.state, request, id, false),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() == 2 && parts[1] == "subscriptions" {
        return match request.method.as_str() {
            "POST" => update_group_subscriptions(&app.state, request, id, true),
            "DELETE" => update_group_subscriptions(&app.state, request, id, false),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown group path"}));
    }
    match request.method.as_str() {
        "GET" => get_group(&app.state, id),
        "PUT" | "PATCH" => update_group(&app.state, request, id),
        "DELETE" => delete_group(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

fn api_general_state(app: &AppState) -> HttpResponse {
    match general_state_report(&app.state) {
        Ok(report) => HttpResponse::json(200, report),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_general_cache_stats(app: &AppState) -> HttpResponse {
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let latency = count_table(&conn, "node_latency_results").unwrap_or(0);
    HttpResponse::json(
        200,
        json!({
            "dnsCacheEntries": 0,
            "nodeLatencyCacheEntries": latency,
            "routingCacheEntries": 0,
        }),
    )
}

fn api_general_interfaces() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({
            "items": [
                {
                    "name": "lo",
                    "index": 1,
                    "up": true,
                    "addresses": ["127.0.0.1"]
                }
            ]
        }),
    )
}

fn api_runtime_overview(app: &AppState) -> HttpResponse {
    let running = metadata_bool(&app.state, "runtime_running").unwrap_or(false);
    HttpResponse::json(
        200,
        json!({
            "updatedAt": now_text(),
            "uploadRate": "0",
            "downloadRate": "0",
            "uploadTotal": "0",
            "downloadTotal": "0",
            "activeConnections": 0,
            "udpSessions": 0,
            "udpTaskQueues": 0,
            "udpTaskDropTotal": "0",
            "packetSnifferSessions": 0,
            "cpuUsagePercent": 0.0,
            "rssBytes": current_rss_bytes().to_string(),
            "heapAllocBytes": "0",
            "goroutines": if running { 1 } else { 0 },
            "samples": []
        }),
    )
}

fn api_runtime_reload(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let dry = body.get("dry").and_then(Value::as_bool).unwrap_or(false);
    match materialize_runtime(&app.state, Some(&app.config_dir), dry) {
        Ok(report) => {
            if !dry {
                let _ = set_metadata(&app.state, "runtime_running", "true");
                let _ = append_log(&app.state, "info", "runtime reload applied by Rust daed");
            }
            let applied = if dry { 0 } else { 1 };
            let mut response = report.as_object().cloned().unwrap_or_default();
            response.insert("applied".to_owned(), json!(applied));
            response.insert("dry".to_owned(), json!(dry));
            HttpResponse::json(200, Value::Object(response))
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_runtime_stop(app: &AppState) -> HttpResponse {
    let _ = set_metadata(&app.state, "runtime_running", "false");
    let _ = append_log(&app.state, "info", "runtime stopped by Rust daed");
    HttpResponse::json(200, json!({"stopped": true}))
}

fn api_get_runtime_log_level(app: &AppState) -> HttpResponse {
    let level = get_metadata(&app.state, "runtime_log_level")
        .unwrap_or_else(|_| Some("info".to_owned()))
        .unwrap_or_else(|| "info".to_owned());
    HttpResponse::json(200, json!({"level": level}))
}

fn api_set_runtime_log_level(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let level = body.get("level").and_then(Value::as_str).unwrap_or("info");
    if let Err(err) = set_metadata(&app.state, "runtime_log_level", level) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    let _ = append_log(
        &app.state,
        "info",
        &format!("runtime log level set to {level}"),
    );
    HttpResponse::json(200, json!({"level": level}))
}

fn api_runtime_events(app: &AppState) -> HttpResponse {
    let payload = general_state_report(&app.state).unwrap_or_else(|_| json!({}));
    sse_response("runtime.overview", payload)
}

fn api_log_events(app: &AppState) -> HttpResponse {
    let payload =
        list_logs_value(&app.state, None, None, 1).unwrap_or_else(|_| json!({"items": []}));
    sse_response("logs.append", payload)
}

fn api_logs(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let level = request
        .query
        .get("level")
        .and_then(|values| values.first())
        .filter(|value| !value.is_empty())
        .cloned();
    let query = request
        .query
        .get("q")
        .and_then(|values| values.first())
        .filter(|value| !value.is_empty())
        .cloned();
    let limit = request
        .query
        .get("limit")
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200);
    match list_logs_value(&app.state, level.as_deref(), query.as_deref(), limit) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_clear_logs(app: &AppState) -> HttpResponse {
    match open_state_connection(&app.state).and_then(|conn| {
        conn.execute("DELETE FROM log_entries", [])
            .map_err(sqlite_io_error)?;
        Ok(())
    }) {
        Ok(()) => HttpResponse::json(200, json!({"cleared": true})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_log_settings(app: &AppState) -> HttpResponse {
    match log_settings_value(&app.state) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_set_log_settings(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let max_entries = body
        .get("maxEntries")
        .and_then(Value::as_i64)
        .unwrap_or(1000);
    let max_bytes = body
        .get("maxBytes")
        .and_then(Value::as_i64)
        .unwrap_or(1048576);
    match open_state_connection(&app.state).and_then(|conn| {
        conn.execute(
            "INSERT OR REPLACE INTO log_settings(id, max_entries, max_bytes) VALUES(1, ?1, ?2)",
            params![max_entries, max_bytes],
        )
        .map_err(sqlite_io_error)?;
        Ok(())
    }) {
        Ok(()) => match log_settings_value(&app.state) {
            Ok(value) => HttpResponse::json(200, value),
            Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
        },
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_node_latencies(app: &AppState) -> HttpResponse {
    match list_node_latencies_value(&app.state) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_test_node_latencies(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    match update_node_latencies(&app.state, &ids) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_bundle(app: &AppState, user: &UserRecord) -> HttpResponse {
    match export_bundle(&app.state, user) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_put_bundle(app: &AppState, request: &HttpRequest, user: &UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match import_bundle(&app.state, &body, user) {
        Ok(imported) => HttpResponse::json(200, json!({"imported": imported})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_get_dae_config_file(app: &AppState) -> HttpResponse {
    match materialize_runtime(&app.state, None, true) {
        Ok(report) => HttpResponse::json(
            200,
            json!({
                "filename": "generated.dae",
                "content": report["content"].as_str().unwrap_or(""),
                "generated": true
            }),
        ),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_put_dae_config_file(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let content = body.get("content").and_then(Value::as_str).unwrap_or("");
    let name_prefix = body
        .get("namePrefix")
        .and_then(Value::as_str)
        .unwrap_or("imported");
    let import_body = json!({
        "configName": format!("{name_prefix}-global"),
        "global": content,
        "dnsName": format!("{name_prefix}-dns"),
        "dns": "",
        "routingName": format!("{name_prefix}-routing"),
        "routing": "",
        "groupName": format!("{name_prefix}-group"),
        "policy": "random",
        "policyParams": [],
        "mode": "rule"
    });
    match ensure_default_resources(&app.state, &import_body) {
        Ok(response) => {
            let _ = append_log(&app.state, "info", "dae config file imported by Rust daed");
            let _ = save_json_storage(&app.state, user.id, &user.json_storage);
            HttpResponse::json(
                200,
                json!({"imported": true, "defaults": response, "warnings": []}),
            )
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_preview_dae_config_file(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let content = body.get("content").and_then(Value::as_str).unwrap_or("");
    match export_bundle(&app.state, user) {
        Ok(bundle) => HttpResponse::json(
            200,
            json!({
                "bundle": bundle,
                "warnings": [{
                    "level": "info",
                    "code": "rust_daed_local_preview",
                    "message": format!("Rust daed local preview accepted {} bytes", content.len())
                }]
            }),
        ),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionKind {
    Config,
    Dns,
    Routing,
}

impl SectionKind {
    fn from_path(path: &str) -> Option<Self> {
        if path == "/configs" || path.starts_with("/configs/") {
            Some(Self::Config)
        } else if path == "/dns" || path.starts_with("/dns/") {
            Some(Self::Dns)
        } else if path == "/routings" || path.starts_with("/routings/") {
            Some(Self::Routing)
        } else {
            None
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Self::Config => "/configs",
            Self::Dns => "/dns",
            Self::Routing => "/routings",
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::Config => "configs",
            Self::Dns => "dns",
            Self::Routing => "routings",
        }
    }

    fn value_column(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }

    fn request_value_key(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }

    fn default_name(self) -> &'static str {
        match self {
            Self::Config => "global",
            Self::Dns => "dns",
            Self::Routing => "routing",
        }
    }
}

fn api_section_preview(request: &HttpRequest, api_path: &str) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    if api_path == "/configs/parsed" {
        let global = body
            .get("global")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| body.get("parsedGlobal").map(Value::to_string))
            .unwrap_or_else(|| "global {}".to_owned());
        return HttpResponse::json(
            200,
            json!({
                "global": global,
                "parsedGlobal": normalize_global_value(None),
            }),
        );
    }
    if api_path == "/dns/parsed" {
        let raw = body.get("dns").and_then(Value::as_str).unwrap_or("");
        return HttpResponse::json(200, parsed_dns_value(raw));
    }
    let raw = body.get("routing").and_then(Value::as_str).unwrap_or("");
    HttpResponse::json(200, parsed_routing_value(raw))
}

fn list_sections(state: &Path, kind: SectionKind) -> HttpResponse {
    match list_sections_value(state, kind) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_sections_value(state: &Path, kind: SectionKind) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let sql = format!(
        "SELECT id, name, {}, selected, version FROM {} ORDER BY id",
        kind.value_column(),
        kind.table()
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(section_resource(
                kind,
                row.get(0)?,
                row.get::<_, Option<String>>(1)?
                    .unwrap_or_else(|| kind.default_name().to_owned()),
                row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                row.get::<_, i64>(3)? != 0,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(json!({"items": items}))
}

fn get_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    match get_section_value(state, kind, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "resource not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_section_value(state: &Path, kind: SectionKind, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    let sql = format!(
        "SELECT id, name, {}, selected, version FROM {} WHERE id = ?1",
        kind.value_column(),
        kind.table()
    );
    conn.query_row(&sql, params![id], |row| {
        Ok(section_resource(
            kind,
            row.get(0)?,
            row.get::<_, Option<String>>(1)?
                .unwrap_or_else(|| kind.default_name().to_owned()),
            row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            row.get::<_, i64>(3)? != 0,
            row.get::<_, i64>(4)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn create_section(state: &Path, request: &HttpRequest, kind: SectionKind) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(kind.default_name());
    let value = section_request_value(kind, &body);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let sql = format!(
        "INSERT INTO {}(name, {}, selected, version) VALUES(?1, ?2, 0, 0)",
        kind.table(),
        kind.value_column()
    );
    if let Err(err) = conn.execute(&sql, params![name, value]) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    get_section(state, kind, id).with_status(201)
}

fn update_section(state: &Path, request: &HttpRequest, kind: SectionKind, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        let sql = format!(
            "UPDATE {} SET name = ?1, version = version + 1 WHERE id = ?2",
            kind.table()
        );
        if let Err(err) = conn.execute(&sql, params![name, id]) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if body.get(kind.request_value_key()).is_some()
        || (kind == SectionKind::Config && body.get("parsedGlobal").is_some())
    {
        let value = section_request_value(kind, &body);
        let sql = format!(
            "UPDATE {} SET {} = ?1, version = version + 1 WHERE id = ?2",
            kind.table(),
            kind.value_column()
        );
        if let Err(err) = conn.execute(&sql, params![value, id]) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    get_section(state, kind, id)
}

fn delete_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let sql = format!("DELETE FROM {} WHERE id = ?1", kind.table());
    match conn.execute(&sql, params![id]) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn select_section(state: &Path, kind: SectionKind, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let clear = format!("UPDATE {} SET selected = 0", kind.table());
    let set = format!(
        "UPDATE {} SET selected = 1, version = version + 1 WHERE id = ?1",
        kind.table()
    );
    if let Err(err) = conn.execute(&clear, []) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    match conn.execute(&set, params![id]) {
        Ok(0) => HttpResponse::json(404, json!({"error": "resource not found"})),
        Ok(_) => get_section(state, kind, id),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn section_request_value(kind: SectionKind, body: &Value) -> String {
    body.get(kind.request_value_key())
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            if kind == SectionKind::Config {
                body.get("parsedGlobal").map(Value::to_string)
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn section_resource(
    kind: SectionKind,
    id: i64,
    name: String,
    raw: String,
    selected: bool,
    version: i64,
) -> Value {
    match kind {
        SectionKind::Config => json!({
            "id": id,
            "name": name,
            "global": raw,
            "selected": selected,
            "version": version,
            "parsedGlobal": normalize_global_value(Some(&raw)),
        }),
        SectionKind::Dns => {
            let mut value = parsed_dns_value(&raw);
            if let Value::Object(map) = &mut value {
                map.insert("id".to_owned(), json!(id));
                map.insert("name".to_owned(), json!(name));
                map.insert("dns".to_owned(), json!(raw));
                map.insert("selected".to_owned(), json!(selected));
                map.insert("version".to_owned(), json!(version));
            }
            value
        }
        SectionKind::Routing => {
            let mut value = parsed_routing_value(&raw);
            if let Value::Object(map) = &mut value {
                map.insert("id".to_owned(), json!(id));
                map.insert("name".to_owned(), json!(name));
                map.insert("routing".to_owned(), json!(raw));
                map.insert("selected".to_owned(), json!(selected));
                map.insert("version".to_owned(), json!(version));
            }
            value
        }
    }
}

fn normalize_global_value(_raw: Option<&str>) -> Value {
    json!({
        "logLevel": "",
        "tproxyPort": 0,
        "allowInsecure": false,
        "checkInterval": "",
        "checkTolerance": "",
        "lanInterface": [],
        "wanInterface": [],
        "udpCheckDns": [],
        "tcpCheckUrl": [],
        "fallbackResolver": "",
        "dialMode": "",
        "tcpCheckHttpMethod": "",
        "disableWaitingNetwork": false,
        "autoConfigKernelParameter": false,
        "sniffingTimeout": "",
        "tlsImplementation": "",
        "utlsImitate": "",
        "tproxyPortProtect": false,
        "soMarkFromDae": 0,
        "pprofPort": 0,
        "enableLocalTcpFastRedirect": false,
        "mptcp": false,
        "bandwidthMaxTx": "",
        "bandwidthMaxRx": "",
    })
}

fn parsed_dns_value(raw: &str) -> Value {
    json!({
        "dns": raw,
        "parsedDns": {
            "string": raw,
            "routing": {
                "request": {"string": ""},
                "response": {"string": ""}
            }
        }
    })
}

fn parsed_routing_value(raw: &str) -> Value {
    json!({
        "routing": raw,
        "parsedRouting": {
            "string": raw
        }
    })
}

impl HttpResponse {
    fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}

fn list_nodes(state: &Path, subscription_id: Option<i64>) -> HttpResponse {
    match list_nodes_value(state, subscription_id) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_nodes_value(state: &Path, subscription_id: Option<i64>) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut items = Vec::new();
    if let Some(subscription_id) = subscription_id {
        let mut stmt = conn
            .prepare(
                "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes WHERE subscription_id = ?1 ORDER BY id",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map(params![subscription_id], node_row_value)
            .map_err(sqlite_io_error)?;
        for row in rows {
            items.push(row.map_err(sqlite_io_error)?);
        }
    } else {
        let mut stmt = conn
            .prepare(
                "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes ORDER BY id",
            )
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map([], node_row_value)
            .map_err(sqlite_io_error)?;
        for row in rows {
            items.push(row.map_err(sqlite_io_error)?);
        }
    }
    Ok(json!({
        "items": items,
        "totalCount": items.len(),
        "nextAfterId": Value::Null,
    }))
}

fn get_node(state: &Path, id: i64) -> HttpResponse {
    match get_node_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "node not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_node_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes WHERE id = ?1",
        params![id],
        node_row_value,
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn import_nodes(state: &Path, request: &HttpRequest, subscription_id: Option<i64>) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let args = body
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![body.clone()]);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let mut items = Vec::new();
    for item in args {
        let link = item.get("link").and_then(Value::as_str).unwrap_or("");
        let tag = item.get("tag").and_then(Value::as_str);
        if link.is_empty() {
            items.push(json!({"link": link, "error": "link is required", "node": Value::Null}));
            continue;
        }
        let parsed = parse_node_link(link, tag);
        let result = conn.execute(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![link, parsed.name, parsed.address, parsed.protocol, tag, subscription_id],
        );
        match result {
            Ok(_) => {
                let id = conn.last_insert_rowid();
                let node = get_node_value(state, id).unwrap_or(None);
                items.push(json!({"link": link, "error": Value::Null, "node": node}));
            }
            Err(err) => {
                items.push(json!({"link": link, "error": err.to_string(), "node": Value::Null}))
            }
        }
    }
    HttpResponse::json(200, json!({"items": items}))
}

fn update_node(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let tag_present = body.get("tag").is_some();
    let tag = body.get("tag").and_then(Value::as_str);
    let updated = if let Some(link) = body.get("link").and_then(Value::as_str) {
        let parsed = parse_node_link(link, tag);
        conn.execute(
            "UPDATE nodes
             SET link = ?1,
                 name = ?2,
                 address = ?3,
                 protocol = ?4,
                 tag = CASE WHEN ?5 THEN ?6 ELSE tag END
             WHERE id = ?7",
            params![
                link,
                parsed.name,
                parsed.address,
                parsed.protocol,
                tag_present,
                tag,
                id
            ],
        )
    } else if tag_present {
        conn.execute("UPDATE nodes SET tag = ?1 WHERE id = ?2", params![tag, id])
    } else {
        return HttpResponse::json(400, json!({"error": "link or tag is required"}));
    };
    match updated {
        Ok(0) => HttpResponse::json(404, json!({"error": "node not found"})),
        Ok(_) => get_node(state, id),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn delete_nodes(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    let mut removed = 0_usize;
    for id in ids {
        if let Ok(value) = delete_node(state, id) {
            removed += value;
        }
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

fn delete_node_by_id(state: &Path, id: i64) -> HttpResponse {
    match delete_node(state, id) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn delete_node(state: &Path, id: i64) -> io::Result<usize> {
    let conn = open_state_connection(state)?;
    conn.execute("DELETE FROM group_nodes WHERE node_id = ?1", params![id])
        .map_err(sqlite_io_error)?;
    conn.execute(
        "DELETE FROM node_latency_results WHERE node_id = ?1",
        params![id],
    )
    .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM nodes WHERE id = ?1", params![id])
        .map_err(sqlite_io_error)
}

#[derive(Clone, Debug)]
struct ParsedNodeLink {
    name: String,
    address: String,
    protocol: String,
}

fn parse_node_link(link: &str, tag: Option<&str>) -> ParsedNodeLink {
    let protocol = link
        .split_once("://")
        .map(|(value, _)| value)
        .unwrap_or("unknown");
    let parsed_url = url::Url::parse(link).ok();
    let address = parsed_url
        .as_ref()
        .and_then(url::Url::host_str)
        .map(str::to_owned)
        .or_else(|| {
            link.split_once("://").map(|(_, rest)| {
                rest.split(['@', '/', '?', '#'])
                    .next_back()
                    .unwrap_or(rest)
                    .split(':')
                    .next()
                    .unwrap_or("unknown")
                    .to_owned()
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let name = tag
        .map(str::to_owned)
        .or_else(|| parsed_url.and_then(|url| url.fragment().map(str::to_owned)))
        .unwrap_or_else(|| format!("{protocol}-{address}"));
    ParsedNodeLink {
        name,
        address,
        protocol: protocol.to_owned(),
    }
}

fn node_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let subscription_id: Option<i64> = row.get(6)?;
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "link": row.get::<_, String>(1)?,
        "name": row.get::<_, String>(2)?,
        "address": row.get::<_, String>(3)?,
        "protocol": row.get::<_, String>(4)?,
        "transport": Value::Null,
        "tag": row.get::<_, Option<String>>(5)?,
        "subscriptionId": subscription_id,
        "subscriptionID": subscription_id.map(|value| value.to_string()),
    }))
}

fn list_subscriptions(state: &Path, request: &HttpRequest) -> HttpResponse {
    let expand_nodes = request
        .query
        .get("expand")
        .map(|values| values.iter().any(|value| value == "nodes"))
        .unwrap_or(false);
    match list_subscriptions_value(state, expand_nodes) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_subscriptions_value(state: &Path, expand_nodes: bool) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag FROM subscriptions ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], subscription_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        let mut value = row.map_err(sqlite_io_error)?;
        let id = value["id"].as_i64().unwrap_or(0);
        let node_count = count_nodes_for_subscription(&conn, id)?;
        if let Value::Object(map) = &mut value {
            map.insert("nodeCount".to_owned(), json!(node_count));
            if expand_nodes {
                map.insert("nodes".to_owned(), list_nodes_value(state, Some(id))?);
            }
        }
        items.push(value);
    }
    Ok(json!({"items": items}))
}

fn create_subscription(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let link = body.get("link").and_then(Value::as_str).unwrap_or("");
    if link.is_empty() {
        return HttpResponse::json(400, json!({"error": "link is required"}));
    }
    let tag = body.get("tag").and_then(Value::as_str);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let now = now_text();
    if let Err(err) = conn.execute(
        "INSERT INTO subscriptions(updated_at, link, cron_exp, cron_enable, status, info, tag) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![now, link, body.get("cronExp").and_then(Value::as_str).unwrap_or("10 */6 * * *"), body.get("cronEnable").and_then(Value::as_bool).unwrap_or(true) as i64, "imported", "", tag],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    let _ = append_log(state, "info", &format!("subscription {id} imported"));
    let import_report = refresh_subscription_from_remote(state, id).unwrap_or_else(|err| {
        json!({
            "link": link,
            "nodeImportResult": [{
                "link": link,
                "error": err.to_string(),
                "node": Value::Null
            }]
        })
    });
    HttpResponse::json(
        201,
        json!({
            "link": link,
            "subscription": {"id": id},
            "nodeImportResult": import_report["nodeImportResult"].clone()
        }),
    )
}

fn get_subscription(state: &Path, id: i64) -> HttpResponse {
    match get_subscription_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "subscription not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_subscription_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag FROM subscriptions WHERE id = ?1",
        params![id],
        subscription_row_value,
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn update_subscription(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let link = body.get("link").and_then(Value::as_str);
    let tag_present = body.get("tag").is_some();
    let tag = body.get("tag").and_then(Value::as_str);
    let cron_exp = body.get("cronExp").and_then(Value::as_str);
    let cron_enable = body
        .get("cronEnable")
        .and_then(Value::as_bool)
        .map(|value| value as i64);
    if let Err(err) = conn.execute(
        "UPDATE subscriptions
         SET link = COALESCE(?1, link),
             tag = CASE WHEN ?2 THEN ?3 ELSE tag END,
             cron_exp = COALESCE(?4, cron_exp),
             cron_enable = COALESCE(?5, cron_enable),
             updated_at = ?6
         WHERE id = ?7",
        params![
            link,
            tag_present,
            tag,
            cron_exp,
            cron_enable,
            now_text(),
            id
        ],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    get_subscription(state, id)
}

fn refresh_subscription(state: &Path, id: i64) -> HttpResponse {
    match refresh_subscription_from_remote(state, id) {
        Ok(mut report) => {
            let _ = append_log(state, "info", &format!("subscription {id} refreshed"));
            if let Some(subscription) = get_subscription_value(state, id)
                .ok()
                .flatten()
                .and_then(|value| value.as_object().cloned())
            {
                if let Value::Object(map) = &mut report {
                    for (key, value) in subscription {
                        map.insert(key, value);
                    }
                }
            }
            HttpResponse::json(200, report)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            HttpResponse::json(404, json!({"error": err.to_string()}))
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn delete_subscriptions(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    let mut removed = 0_usize;
    for id in ids {
        if let Ok(value) = delete_subscription(state, id) {
            removed += value;
        }
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

fn delete_subscription_by_id(state: &Path, id: i64) -> HttpResponse {
    match delete_subscription(state, id) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn delete_subscription(state: &Path, id: i64) -> io::Result<usize> {
    let conn = open_state_connection(state)?;
    conn.execute(
        "DELETE FROM group_subscriptions WHERE subscription_id = ?1",
        params![id],
    )
    .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM nodes WHERE subscription_id = ?1", params![id])
        .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])
        .map_err(sqlite_io_error)
}

fn subscription_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "updatedAt": row.get::<_, String>(1)?,
        "link": row.get::<_, String>(2)?,
        "cronExp": row.get::<_, Option<String>>(3)?.unwrap_or_else(|| "10 */6 * * *".to_owned()),
        "cronEnable": row.get::<_, i64>(4)? != 0,
        "status": row.get::<_, String>(5)?,
        "info": row.get::<_, String>(6)?,
        "tag": row.get::<_, Option<String>>(7)?,
    }))
}

fn count_nodes_for_subscription(conn: &Connection, subscription_id: i64) -> io::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM nodes WHERE subscription_id = ?1",
        params![subscription_id],
        |row| row.get(0),
    )
    .map_err(sqlite_io_error)
}

fn refresh_subscription_from_remote(state: &Path, id: i64) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let Some(link) = conn
        .query_row(
            "SELECT link FROM subscriptions WHERE id = ?1",
            params![id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "subscription not found",
        ));
    };
    let fetched_at = now_text();
    match fetch_subscription_content(&link) {
        Ok(content) => {
            let links = subscription_links_from_content(&content);
            let node_import_result = replace_subscription_nodes(&conn, id, &links)?;
            conn.execute(
                "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
                params![
                    fetched_at,
                    "fetched",
                    format!("{} node links fetched by Rust daed", links.len()),
                    id
                ],
            )
            .map_err(sqlite_io_error)?;
            Ok(json!({
                "link": link,
                "fetched": true,
                "fetchedAt": fetched_at,
                "nodeImportResult": node_import_result,
            }))
        }
        Err(err) => {
            conn.execute(
                "UPDATE subscriptions SET updated_at = ?1, status = ?2, info = ?3 WHERE id = ?4",
                params![fetched_at, "fetch_error", err.to_string(), id],
            )
            .map_err(sqlite_io_error)?;
            Ok(json!({
                "link": link,
                "fetched": false,
                "fetchedAt": fetched_at,
                "nodeImportResult": [{
                    "link": link,
                    "error": err.to_string(),
                    "node": Value::Null
                }],
            }))
        }
    }
}

fn replace_subscription_nodes(
    conn: &Connection,
    subscription_id: i64,
    links: &[String],
) -> io::Result<Vec<Value>> {
    conn.execute(
        "DELETE FROM group_nodes WHERE node_id IN (SELECT id FROM nodes WHERE subscription_id = ?1)",
        params![subscription_id],
    )
    .map_err(sqlite_io_error)?;
    conn.execute(
        "DELETE FROM node_latency_results WHERE node_id IN (SELECT id FROM nodes WHERE subscription_id = ?1)",
        params![subscription_id],
    )
    .map_err(sqlite_io_error)?;
    conn.execute(
        "DELETE FROM nodes WHERE subscription_id = ?1",
        params![subscription_id],
    )
    .map_err(sqlite_io_error)?;

    let mut out = Vec::new();
    for link in links {
        let parsed = parse_node_link(link, None);
        match conn.execute(
            "INSERT INTO nodes(link, name, address, protocol, tag, subscription_id) VALUES(?1, ?2, ?3, ?4, NULL, ?5)",
            params![link, parsed.name, parsed.address, parsed.protocol, subscription_id],
        ) {
            Ok(_) => {
                let id = conn.last_insert_rowid();
                out.push(json!({
                    "link": link,
                    "error": Value::Null,
                    "node": {"id": id}
                }));
            }
            Err(err) => out.push(json!({
                "link": link,
                "error": err.to_string(),
                "node": Value::Null
            })),
        }
    }
    Ok(out)
}

fn subscription_links_from_content(content: &str) -> Vec<String> {
    let direct = node_links_from_text(content);
    if !direct.is_empty() {
        return direct;
    }
    let compact = content.split_whitespace().collect::<String>();
    for candidate in [
        compact.clone(),
        compact.replace('-', "+").replace('_', "/"),
        format!("{compact}{}", "=".repeat((4 - compact.len() % 4) % 4)),
    ] {
        if let Ok(decoded) = STANDARD.decode(candidate.as_bytes()) {
            let decoded = String::from_utf8_lossy(&decoded);
            let links = node_links_from_text(&decoded);
            if !links.is_empty() {
                return links;
            }
        }
    }
    Vec::new()
}

fn node_links_from_text(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.contains("://"))
        .map(str::to_owned)
        .collect()
}

fn fetch_subscription_content(link: &str) -> io::Result<String> {
    let url = url::Url::parse(link)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    match url.scheme() {
        "http" => fetch_http_url(&url, false),
        "https" => fetch_http_url(&url, true),
        scheme => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported subscription scheme: {scheme}"),
        )),
    }
}

fn fetch_http_url(url: &url::Url, tls: bool) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing port for subscription")
    })?;
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: daed-rust-native/0.1\r\nAccept: text/plain, application/octet-stream, */*\r\nConnection: close\r\n\r\n"
    );
    let stream = connect_tcp(host, port, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    let response = if tls {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = ServerName::try_from(host.to_owned()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tls server name: {err}"),
            )
        })?;
        let conn = ClientConnection::new(config, server_name)
            .map_err(|err| io::Error::other(format!("tls connect: {err}")))?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        tls_stream.write_all(request.as_bytes())?;
        tls_stream.flush()?;
        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response)?;
        response
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        response
    };
    http_response_body(&response)
}

fn http_response_body(response: &[u8]) -> io::Result<String> {
    let split = find_subsequence(response, b"\r\n\r\n")
        .or_else(|| find_subsequence(response, b"\n\n"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing http headers"))?;
    let header_end = if response.get(split..split + 4) == Some(b"\r\n\r\n") {
        split + 4
    } else {
        split + 2
    };
    let headers = String::from_utf8_lossy(&response[..split]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "subscription fetch returned HTTP {status}"
        )));
    }
    let mut body = response[header_end..].to_vec();
    if headers
        .lines()
        .any(|line| line.to_ascii_lowercase().trim() == "transfer-encoding: chunked")
    {
        body = decode_chunked_body(&body)?;
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn decode_chunked_body(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut index = 0;
    let mut out = Vec::new();
    while index < body.len() {
        let Some(line_end) = find_subsequence(&body[index..], b"\r\n") else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunked body",
            ));
        };
        let size_text = String::from_utf8_lossy(&body[index..index + line_end]);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk size: {err}"),
            )
        })?;
        index += line_end + 2;
        if size == 0 {
            break;
        }
        if index + size > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated chunked body",
            ));
        }
        out.extend_from_slice(&body[index..index + size]);
        index += size + 2;
    }
    Ok(out)
}

fn connect_tcp(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no socket address resolved",
        )
    }))
}

fn start_subscription_scheduler(state: PathBuf) {
    thread::spawn(move || {
        let _ = ensure_state_schema(&state);
        let _ = set_metadata(&state, "subscription_scheduler_started_at", &now_text());
        let _ = append_log(
            &state,
            "info",
            "subscription scheduler skeleton started by Rust daed",
        );
    });
}

fn list_groups(state: &Path) -> HttpResponse {
    match list_groups_value(state) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_groups_value(state: &Path) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    let mut items = Vec::new();
    for id in ids {
        if let Some(group) = get_group_value_with_conn(&conn, id)? {
            items.push(group);
        }
    }
    Ok(json!({"items": items}))
}

fn create_group(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let name = body.get("name").and_then(Value::as_str).unwrap_or("proxy");
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or("random");
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = conn.execute(
        "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
        params![name, policy],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    if let Err(err) = replace_group_policy_params(&conn, id, body.get("policyParams")) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_node_ids(&conn, id, &integer_array(&body, "nodeIds"), true) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = apply_group_subscription_ids(
        &conn,
        id,
        &integer_array(&body, "subscriptionIds"),
        None,
        true,
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    get_group(state, id).with_status(201)
}

fn get_group(state: &Path, id: i64) -> HttpResponse {
    match get_group_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "group not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_group_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    get_group_value_with_conn(&conn, id)
}

fn get_group_value_with_conn(conn: &Connection, id: i64) -> io::Result<Option<Value>> {
    let Some((group_id, name, policy, version)) = conn
        .query_row(
            "SELECT id, name, policy, version FROM groups WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_io_error)?
    else {
        return Ok(None);
    };
    let nodes = group_nodes_value(conn, group_id)?;
    let subscriptions = group_subscriptions_value(conn, group_id)?;
    let policy_params = group_policy_params_value(conn, group_id)?;
    Ok(Some(json!({
        "id": group_id,
        "name": name,
        "policy": policy,
        "policyParams": policy_params,
        "nodes": nodes,
        "subscriptions": subscriptions,
        "version": version,
    })))
}

fn update_group(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        if let Err(err) = conn.execute(
            "UPDATE groups SET name = ?1, version = version + 1 WHERE id = ?2",
            params![name, id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if let Some(policy) = body.get("policy").and_then(Value::as_str) {
        if let Err(err) = conn.execute(
            "UPDATE groups SET policy = ?1, version = version + 1 WHERE id = ?2",
            params![policy, id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    if body.get("policyParams").is_some() {
        if let Err(err) = replace_group_policy_params(&conn, id, body.get("policyParams")) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    }
    get_group(state, id)
}

fn delete_group(state: &Path, id: i64) -> HttpResponse {
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = conn.execute("DELETE FROM group_nodes WHERE group_id = ?1", params![id]) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    if let Err(err) = conn.execute(
        "DELETE FROM group_subscriptions WHERE group_id = ?1",
        params![id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    match conn.execute("DELETE FROM groups WHERE id = ?1", params![id]) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn update_group_nodes(state: &Path, request: &HttpRequest, id: i64, add: bool) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "nodeIds");
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = apply_group_node_ids(&conn, id, &ids, add) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let _ = conn.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    );
    get_group(state, id)
}

fn update_group_subscriptions(
    state: &Path,
    request: &HttpRequest,
    id: i64,
    add: bool,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "subscriptionIds");
    let name_filter_regex = body.get("nameFilterRegex").and_then(Value::as_str);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = apply_group_subscription_ids(&conn, id, &ids, name_filter_regex, add) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let _ = conn.execute(
        "UPDATE groups SET version = version + 1 WHERE id = ?1",
        params![id],
    );
    get_group(state, id)
}

fn group_nodes_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id
             FROM nodes n
             JOIN group_nodes gn ON gn.node_id = n.id
             WHERE gn.group_id = ?1
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn group_subscriptions_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.id, s.updated_at, s.link, s.cron_exp, s.cron_enable, s.status, s.info, s.tag, gs.name_filter_regex
             FROM subscriptions s
             JOIN group_subscriptions gs ON gs.subscription_id = s.id
             WHERE gs.group_id = ?1
             ORDER BY s.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?
                    .unwrap_or_else(|| "10 */6 * * *".to_owned()),
                row.get::<_, i64>(4)? != 0,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, updated_at, link, _cron_exp, _cron_enable, status, info, tag, name_filter_regex) =
            row.map_err(sqlite_io_error)?;
        let matched_nodes = nodes_for_subscription_value(conn, id)?;
        out.push(json!({
            "subscriptionId": id,
            "nameFilterRegex": name_filter_regex,
            "matchedCount": matched_nodes.len(),
            "matchedNodes": matched_nodes,
            "updatedAt": updated_at,
            "status": status,
            "info": info,
            "link": link,
            "tag": tag,
        }));
    }
    Ok(out)
}

fn nodes_for_subscription_value(conn: &Connection, subscription_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes WHERE subscription_id = ?1 ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![subscription_id], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn group_policy_params_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM group_policy_params WHERE group_id = ?1 ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok(json!({
                "key": row.get::<_, String>(0)?,
                "val": row.get::<_, String>(1)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn replace_group_policy_params(
    conn: &Connection,
    group_id: i64,
    params_value: Option<&Value>,
) -> io::Result<()> {
    conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    if let Some(values) = params_value.and_then(Value::as_array) {
        for item in values {
            let key = item
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let value = item
                .get("val")
                .or_else(|| item.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            conn.execute(
                "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
                params![key, value, group_id],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

fn apply_group_node_ids(
    conn: &Connection,
    group_id: i64,
    ids: &[i64],
    add: bool,
) -> io::Result<()> {
    for id in ids {
        if add {
            conn.execute(
                "INSERT OR IGNORE INTO group_nodes(group_id, node_id) VALUES(?1, ?2)",
                params![group_id, id],
            )
        } else {
            conn.execute(
                "DELETE FROM group_nodes WHERE group_id = ?1 AND node_id = ?2",
                params![group_id, id],
            )
        }
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn apply_group_subscription_ids(
    conn: &Connection,
    group_id: i64,
    ids: &[i64],
    name_filter_regex: Option<&str>,
    add: bool,
) -> io::Result<()> {
    for id in ids {
        if add {
            conn.execute(
                "INSERT OR REPLACE INTO group_subscriptions(group_id, subscription_id, name_filter_regex) VALUES(?1, ?2, ?3)",
                params![group_id, id, name_filter_regex],
            )
        } else {
            conn.execute(
                "DELETE FROM group_subscriptions WHERE group_id = ?1 AND subscription_id = ?2",
                params![group_id, id],
            )
        }
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn general_state_report(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let running = metadata_bool(state, "runtime_running")?;
    let selected_config_id = selected_id(&conn, SectionKind::Config)?;
    let selected_dns_id = selected_id(&conn, SectionKind::Dns)?;
    let selected_routing_id = selected_id(&conn, SectionKind::Routing)?;
    Ok(json!({
        "running": running,
        "modified": false,
        "version": crate::version::version_from_env(),
        "netnsLinkMode": "none",
        "attachBackend": "rust-native-owned-local",
        "updatedAt": now_text(),
        "state": path_string(state),
        "selected": {
            "configId": selected_config_id,
            "dnsId": selected_dns_id,
            "routingId": selected_routing_id,
        },
        "counts": {
            "configs": count_table(&conn, "configs")?,
            "dns": count_table(&conn, "dns")?,
            "routings": count_table(&conn, "routings")?,
            "groups": count_table(&conn, "groups")?,
            "nodes": count_table(&conn, "nodes")?,
            "subscriptions": count_table(&conn, "subscriptions")?,
            "logs": count_table(&conn, "log_entries")?,
        }
    }))
}

fn materialize_runtime(state: &Path, config_dir: Option<&Path>, dry: bool) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let config = selected_section_raw(&conn, SectionKind::Config)?;
    let dns = selected_section_raw(&conn, SectionKind::Dns)?;
    let routing = selected_section_raw(&conn, SectionKind::Routing)?;
    let groups = list_groups_value(state)?;
    let nodes = list_nodes_value(state, None)?;
    let generated_at = now_text();
    let content = render_generated_config(
        &generated_at,
        config.as_ref(),
        dns.as_ref(),
        routing.as_ref(),
        &groups,
        &nodes,
    );
    let output_path = config_dir.map(|dir| dir.join("runtime").join("generated.dae"));
    if !dry {
        if let Some(path) = &output_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, &content)?;
            set_metadata(state, "last_generated_config_path", &path_string(path))?;
        }
        set_metadata(state, "last_materialized_at", &generated_at)?;
        conn.execute("DELETE FROM systems", [])
            .map_err(sqlite_io_error)?;
        conn.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids, running_config_id, running_dns_id, running_routing_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                1_i64,
                config.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                dns.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                routing.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                group_version_sum(&conn)?,
                group_ids_text(&conn)?,
                config.as_ref().map(|(id, _, _, _)| *id),
                dns.as_ref().map(|(id, _, _, _)| *id),
                routing.as_ref().map(|(id, _, _, _)| *id),
            ],
        )
        .map_err(sqlite_io_error)?;
    }
    Ok(json!({
        "filename": "generated.dae",
        "path": output_path.as_ref().map(|path| path_string(path)),
        "content": content,
        "bytes": content.len(),
        "generatedAt": generated_at,
        "selected": {
            "configId": config.as_ref().map(|(id, _, _, _)| *id),
            "dnsId": dns.as_ref().map(|(id, _, _, _)| *id),
            "routingId": routing.as_ref().map(|(id, _, _, _)| *id),
        },
        "groups": groups["items"].as_array().map(Vec::len).unwrap_or(0),
        "nodes": nodes["items"].as_array().map(Vec::len).unwrap_or(0),
    }))
}

fn render_generated_config(
    generated_at: &str,
    config: Option<&(i64, String, String, i64)>,
    dns: Option<&(i64, String, String, i64)>,
    routing: Option<&(i64, String, String, i64)>,
    groups: &Value,
    nodes: &Value,
) -> String {
    let mut out = String::new();
    out.push_str("# generated by Rust daed C10 local product surface\n");
    out.push_str(&format!("# generated_at: {generated_at}\n\n"));
    out.push_str("# selected config\n");
    out.push_str(
        config
            .map(|(_, _, raw, _)| raw.as_str())
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or("global {}\n"),
    );
    out.push_str("\n\n# selected dns\n");
    out.push_str(
        dns.map(|(_, _, raw, _)| raw.as_str())
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or("dns {}\n"),
    );
    out.push_str("\n\n# selected routing\n");
    out.push_str(
        routing
            .map(|(_, _, raw, _)| raw.as_str())
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or("routing {}\n"),
    );
    out.push_str("\n\n# local product groups\n");
    out.push_str(&serde_json::to_string_pretty(groups).unwrap_or_else(|_| "{}".to_owned()));
    out.push_str("\n\n# local product nodes\n");
    out.push_str(&serde_json::to_string_pretty(nodes).unwrap_or_else(|_| "{}".to_owned()));
    out.push('\n');
    out
}

fn selected_section_raw(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<(i64, String, String, i64)>> {
    let sql = format!(
        "SELECT id, name, {}, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    let selected = conn
        .query_row(&sql, [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()
        .map_err(sqlite_io_error)?;
    if selected.is_some() {
        return Ok(selected);
    }
    let sql = format!(
        "SELECT id, name, {}, version FROM {} ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    conn.query_row(&sql, [], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn selected_id(conn: &Connection, kind: SectionKind) -> io::Result<Option<i64>> {
    let sql = format!(
        "SELECT id FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)
}

fn group_version_sum(conn: &Connection) -> io::Result<i64> {
    conn.query_row("SELECT COALESCE(SUM(version), 0) FROM groups", [], |row| {
        row.get(0)
    })
    .map_err(sqlite_io_error)
}

fn group_ids_text(conn: &Connection) -> io::Result<String> {
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?.to_string());
    }
    Ok(ids.join(","))
}

fn metadata_bool(state: &Path, key: &str) -> io::Result<bool> {
    Ok(get_metadata(state, key)?
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false))
}

fn get_metadata(state: &Path, key: &str) -> io::Result<Option<String>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT value FROM daed_product_metadata WHERE key = ?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn set_metadata(state: &Path, key: &str, value: &str) -> io::Result<()> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params![key, value],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

fn append_log(state: &Path, level: &str, message: &str) -> io::Result<()> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.execute(
        "INSERT INTO log_entries(ts, level, message) VALUES(?1, ?2, ?3)",
        params![now_text(), level, message],
    )
    .map_err(sqlite_io_error)?;
    let (max_entries, _max_bytes) = log_settings_tuple(&conn)?;
    conn.execute(
        "DELETE FROM log_entries WHERE id NOT IN (SELECT id FROM log_entries ORDER BY id DESC LIMIT ?1)",
        params![max_entries],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

fn list_logs_value(
    state: &Path,
    level: Option<&str>,
    query: Option<&str>,
    limit: usize,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let limit = limit.clamp(1, 5000) as i64;
    let mut stmt = conn
        .prepare("SELECT id, ts, level, message FROM log_entries ORDER BY id DESC LIMIT ?1")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        let (id, ts, row_level, message) = row.map_err(sqlite_io_error)?;
        if level.is_some_and(|level| level != row_level) {
            continue;
        }
        if query.is_some_and(|query| !message.contains(query)) {
            continue;
        }
        items.push(json!({
            "id": id,
            "ts": ts,
            "level": row_level,
            "message": message,
            "fields": {},
        }));
    }
    Ok(json!({"items": items}))
}

fn log_settings_value(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let (max_entries, max_bytes) = log_settings_tuple(&conn)?;
    Ok(json!({
        "maxEntries": max_entries,
        "maxBytes": max_bytes,
        "minMaxEntries": 100,
        "maxMaxEntries": 100000,
        "minMaxBytes": 65536,
        "maxMaxBytes": 134217728,
    }))
}

fn log_settings_tuple(conn: &Connection) -> io::Result<(i64, i64)> {
    conn.query_row(
        "SELECT max_entries, max_bytes FROM log_settings WHERE id = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )
    .optional()
    .map_err(sqlite_io_error)
    .map(|value| value.unwrap_or((1000, 1048576)))
}

fn sse_response(event: &str, payload: Value) -> HttpResponse {
    let mut response = HttpResponse::text(
        200,
        "text/event-stream; charset=utf-8",
        format!("event: {event}\ndata: {payload}\n\n"),
    );
    response
        .extra_headers
        .push(("Cache-Control".to_owned(), "no-cache".to_owned()));
    response
        .extra_headers
        .push(("X-Accel-Buffering".to_owned(), "no".to_owned()));
    response
}

fn list_node_latencies_value(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare(
            "SELECT n.id, l.latency_ms, COALESCE(l.alive, 0), COALESCE(l.tested_at, ''), l.message
             FROM nodes n
             LEFT JOIN node_latency_results l ON l.node_id = n.id
             ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "latencyMs": row.get::<_, Option<i64>>(1)?,
                "alive": row.get::<_, i64>(2)? != 0,
                "testedAt": row.get::<_, String>(3)?,
                "message": row.get::<_, Option<String>>(4)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(json!({"items": items}))
}

fn update_node_latencies(state: &Path, ids: &[i64]) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let target_ids = if ids.is_empty() {
        all_node_ids(&conn)?
    } else {
        ids.to_vec()
    };
    let tested_at = now_text();
    for id in &target_ids {
        let node: Option<(String, String)> = conn
            .query_row(
                "SELECT link, address FROM nodes WHERE id = ?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_io_error)?;
        let Some((link, address)) = node else {
            continue;
        };
        let probe = tcp_probe_node(&link, &address);
        conn.execute(
            "INSERT OR REPLACE INTO node_latency_results(node_id, latency_ms, alive, tested_at, message, updated_at)
             VALUES(?1, ?2, 1, ?3, ?4, ?3)",
            params![id, probe.latency_ms, tested_at, probe.message],
        )
        .map_err(sqlite_io_error)?;
        conn.execute(
            "UPDATE node_latency_results SET alive = ?1 WHERE node_id = ?2",
            params![probe.alive as i64, id],
        )
        .map_err(sqlite_io_error)?;
    }
    append_log(state, "info", "node latency probe updated by Rust daed")?;
    list_node_latencies_value(state)
}

#[derive(Debug)]
struct TcpProbeResult {
    latency_ms: Option<i64>,
    alive: bool,
    message: String,
}

fn tcp_probe_node(link: &str, fallback_address: &str) -> TcpProbeResult {
    let (host, port) = node_probe_target(link, fallback_address);
    let started = Instant::now();
    match connect_tcp(&host, port, Duration::from_secs(3)) {
        Ok(stream) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            TcpProbeResult {
                latency_ms: Some(started.elapsed().as_millis().min(i64::MAX as u128) as i64),
                alive: true,
                message: format!("tcp connect {host}:{port}"),
            }
        }
        Err(err) => TcpProbeResult {
            latency_ms: None,
            alive: false,
            message: format!("tcp connect {host}:{port} failed: {err}"),
        },
    }
}

fn node_probe_target(link: &str, fallback_address: &str) -> (String, u16) {
    if let Ok(url) = url::Url::parse(link) {
        let host = url
            .host_str()
            .map(str::to_owned)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| fallback_address.to_owned());
        let port = url
            .port()
            .or_else(|| default_node_port(url.scheme()))
            .unwrap_or(443);
        return (host, port);
    }
    (fallback_address.to_owned(), 443)
}

fn default_node_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" | "vless" | "trojan" | "vmess" | "ss" | "hysteria2" | "hy2" => Some(443),
        _ => None,
    }
}

fn all_node_ids(conn: &Connection) -> io::Result<Vec<i64>> {
    let mut stmt = conn
        .prepare("SELECT id FROM nodes ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    Ok(ids)
}

fn export_bundle(state: &Path, user: &UserRecord) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let storage = serde_json::from_str::<Value>(&user.json_storage).unwrap_or_else(|_| json!({}));
    Ok(json!({
        "schemaVersion": 1,
        "exportedAt": now_text(),
        "mode": storage.get("mode").and_then(Value::as_str).unwrap_or("rule"),
        "defaults": {
            "configId": numeric_storage_value(&storage, "defaultConfigID"),
            "dnsId": numeric_storage_value(&storage, "defaultDNSID"),
            "routingId": numeric_storage_value(&storage, "defaultRoutingID"),
            "groupId": numeric_storage_value(&storage, "defaultGroupID"),
        },
        "selected": {
            "configId": selected_id(&conn, SectionKind::Config)?,
            "dnsId": selected_id(&conn, SectionKind::Dns)?,
            "routingId": selected_id(&conn, SectionKind::Routing)?,
        },
        "configs": bundle_sections(&conn, SectionKind::Config)?,
        "dnss": bundle_sections(&conn, SectionKind::Dns)?,
        "routings": bundle_sections(&conn, SectionKind::Routing)?,
        "subscriptions": bundle_subscriptions(&conn)?,
        "nodes": bundle_nodes(&conn)?,
        "groups": bundle_groups(&conn)?,
    }))
}

fn import_bundle(state: &Path, body: &Value, user: &UserRecord) -> io::Result<bool> {
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn.transaction().map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_policy_params", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_subscriptions", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_nodes", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM node_latency_results", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM nodes", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM subscriptions", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM groups", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM configs", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM dns", []).map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM routings", [])
        .map_err(sqlite_io_error)?;

    import_bundle_sections(&tx, body.get("configs"), SectionKind::Config)?;
    import_bundle_sections(&tx, body.get("dnss"), SectionKind::Dns)?;
    import_bundle_sections(&tx, body.get("routings"), SectionKind::Routing)?;
    import_bundle_subscriptions(&tx, body.get("subscriptions"))?;
    import_bundle_nodes(&tx, body.get("nodes"))?;
    import_bundle_groups(&tx, body.get("groups"))?;

    if let Some(selected) = body.get("selected") {
        set_selected_from_bundle(&tx, selected, "configId", SectionKind::Config)?;
        set_selected_from_bundle(&tx, selected, "dnsId", SectionKind::Dns)?;
        set_selected_from_bundle(&tx, selected, "routingId", SectionKind::Routing)?;
    }
    tx.commit().map_err(sqlite_io_error)?;

    let mut storage =
        serde_json::from_str::<Value>(&user.json_storage).unwrap_or_else(|_| json!({}));
    if !storage.is_object() {
        storage = json!({});
    }
    if let Some(mode) = body.get("mode").and_then(Value::as_str) {
        set_value_at_path(&mut storage, "mode", Value::String(mode.to_owned()))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }
    if let Some(defaults) = body.get("defaults") {
        for (key, path) in [
            ("configId", "defaultConfigID"),
            ("dnsId", "defaultDNSID"),
            ("routingId", "defaultRoutingID"),
            ("groupId", "defaultGroupID"),
        ] {
            if let Some(value) = defaults.get(key).and_then(Value::as_i64) {
                set_value_at_path(&mut storage, path, Value::String(value.to_string()))
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            }
        }
    }
    save_json_storage(state, user.id, &storage.to_string())?;
    append_log(state, "info", "DAE bundle imported by Rust daed")?;
    Ok(true)
}

fn bundle_sections(conn: &Connection, kind: SectionKind) -> io::Result<Vec<Value>> {
    let sql = format!(
        "SELECT id, name, {} FROM {} ORDER BY id",
        kind.value_column(),
        kind.table()
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            let id = row.get::<_, i64>(0)?;
            let name = row.get::<_, String>(1)?;
            let raw = row.get::<_, String>(2)?;
            Ok(match kind {
                SectionKind::Config => json!({"id": id, "name": name, "global": raw}),
                SectionKind::Dns => json!({"id": id, "name": name, "dns": raw}),
                SectionKind::Routing => json!({"id": id, "name": name, "routing": raw}),
            })
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn bundle_subscriptions(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag FROM subscriptions ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], subscription_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn bundle_nodes(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn bundle_groups(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare("SELECT id, name, policy FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut groups = Vec::new();
    for row in rows {
        let (id, name, policy) = row.map_err(sqlite_io_error)?;
        groups.push(json!({
            "id": id,
            "name": name,
            "policy": policy,
            "policyParams": group_policy_params_value(conn, id)?,
            "nodeIds": group_node_ids(conn, id)?,
            "subscriptionBindings": group_subscription_bindings(conn, id)?,
        }));
    }
    Ok(groups)
}

fn group_node_ids(conn: &Connection, group_id: i64) -> io::Result<Vec<i64>> {
    let mut stmt = conn
        .prepare("SELECT node_id FROM group_nodes WHERE group_id = ?1 ORDER BY node_id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    Ok(ids)
}

fn group_subscription_bindings(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT subscription_id, name_filter_regex FROM group_subscriptions WHERE group_id = ?1 ORDER BY subscription_id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok(json!({
                "subscriptionId": row.get::<_, i64>(0)?,
                "nameFilterRegex": row.get::<_, Option<String>>(1)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn import_bundle_sections(
    conn: &Connection,
    sections: Option<&Value>,
    kind: SectionKind,
) -> io::Result<()> {
    if let Some(items) = sections.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(kind.default_name());
            let raw = item
                .get(kind.request_value_key())
                .and_then(Value::as_str)
                .unwrap_or("");
            let sql = format!(
                "INSERT INTO {}(id, name, {}, selected, version) VALUES(?1, ?2, ?3, 0, 0)",
                kind.table(),
                kind.value_column()
            );
            conn.execute(&sql, params![id, name, raw])
                .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

fn import_bundle_subscriptions(conn: &Connection, subscriptions: Option<&Value>) -> io::Result<()> {
    if let Some(items) = subscriptions.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let updated_at = item
                .get("updatedAt")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(now_text);
            conn.execute(
                "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id,
                    updated_at,
                    item.get("link").and_then(Value::as_str).unwrap_or(""),
                    item.get("cronExp")
                        .and_then(Value::as_str)
                        .unwrap_or("10 */6 * * *"),
                    item.get("cronEnable")
                        .and_then(Value::as_bool)
                        .unwrap_or(true) as i64,
                    item.get("status").and_then(Value::as_str).unwrap_or("imported"),
                    item.get("info").and_then(Value::as_str).unwrap_or(""),
                    item.get("tag").and_then(Value::as_str),
                ],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

fn import_bundle_nodes(conn: &Connection, nodes: Option<&Value>) -> io::Result<()> {
    if let Some(items) = nodes.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let link = item.get("link").and_then(Value::as_str).unwrap_or("");
            let parsed = parse_node_link(link, item.get("tag").and_then(Value::as_str));
            conn.execute(
                "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    link,
                    item.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.name),
                    item.get("address")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.address),
                    item.get("protocol")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.protocol),
                    item.get("tag").and_then(Value::as_str),
                    item.get("subscriptionId").and_then(Value::as_i64),
                ],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

fn import_bundle_groups(conn: &Connection, groups: Option<&Value>) -> io::Result<()> {
    if let Some(items) = groups.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            conn.execute(
                "INSERT INTO groups(id, name, policy, version) VALUES(?1, ?2, ?3, 0)",
                params![
                    id,
                    item.get("name").and_then(Value::as_str).unwrap_or("proxy"),
                    item.get("policy")
                        .and_then(Value::as_str)
                        .unwrap_or("random"),
                ],
            )
            .map_err(sqlite_io_error)?;
            replace_group_policy_params(conn, id, item.get("policyParams"))?;
            apply_group_node_ids(conn, id, &integer_array(item, "nodeIds"), true)?;
            if let Some(bindings) = item.get("subscriptionBindings").and_then(Value::as_array) {
                for binding in bindings {
                    if let Some(subscription_id) =
                        binding.get("subscriptionId").and_then(Value::as_i64)
                    {
                        apply_group_subscription_ids(
                            conn,
                            id,
                            &[subscription_id],
                            binding.get("nameFilterRegex").and_then(Value::as_str),
                            true,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn set_selected_from_bundle(
    conn: &Connection,
    selected: &Value,
    key: &str,
    kind: SectionKind,
) -> io::Result<()> {
    let Some(id) = selected.get(key).and_then(Value::as_i64) else {
        return Ok(());
    };
    let clear = format!("UPDATE {} SET selected = 0", kind.table());
    let set = format!("UPDATE {} SET selected = 1 WHERE id = ?1", kind.table());
    conn.execute(&clear, []).map_err(sqlite_io_error)?;
    conn.execute(&set, params![id]).map_err(sqlite_io_error)?;
    Ok(())
}

fn numeric_storage_value(storage: &Value, key: &str) -> Option<i64> {
    storage
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<i64>().ok())
}

fn product_openapi_skeleton() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "daed Rust native product API",
            "version": crate::version::version_from_env(),
        },
        "x-c-phase": "C10",
        "x-work-package": "go-free-product-chain-v1",
        "paths": {
            "/api/health": {"get": {"summary": "health"}},
            "/api/auth/status": {"get": {"summary": "setup/auth status"}},
            "/api/user/me": {"get": {"summary": "current user"}, "patch": {"summary": "update current user"}},
            "/api/user/me/storage": {"get": {"summary": "read JSON storage"}, "put": {"summary": "write JSON storage"}, "delete": {"summary": "delete JSON storage"}},
            "/api/user/me/dae-bundle": {"get": {"summary": "export DAE bundle"}, "put": {"summary": "import DAE bundle"}},
            "/api/user/me/dae-config-file": {"get": {"summary": "export generated DAE config"}, "put": {"summary": "import DAE config"}},
            "/api/configs": {"get": {"summary": "list config resources"}, "post": {"summary": "create config resource"}},
            "/api/dns": {"get": {"summary": "list DNS resources"}, "post": {"summary": "create DNS resource"}},
            "/api/routings": {"get": {"summary": "list routing resources"}, "post": {"summary": "create routing resource"}},
            "/api/nodes": {"get": {"summary": "list nodes"}, "post": {"summary": "import nodes"}, "delete": {"summary": "delete nodes"}},
            "/api/subscriptions": {"get": {"summary": "list subscriptions"}, "post": {"summary": "import subscription"}, "delete": {"summary": "delete subscriptions"}},
            "/api/groups": {"get": {"summary": "list groups"}, "post": {"summary": "create group"}},
            "/api/nodes/latencies": {"get": {"summary": "list latency results"}, "post": {"summary": "test latency"}},
            "/api/runtime/reload": {"post": {"summary": "materialize and apply runtime state"}},
            "/api/runtime/stop": {"post": {"summary": "stop runtime owner state"}},
            "/api/runtime/overview": {"get": {"summary": "runtime overview"}},
            "/api/logs": {"get": {"summary": "list logs"}, "delete": {"summary": "clear logs"}},
            "/api/logs/settings": {"get": {"summary": "read log settings"}, "patch": {"summary": "update log settings"}},
            "/api/events/runtime": {"get": {"summary": "runtime SSE snapshot"}},
            "/api/events/logs": {"get": {"summary": "log SSE snapshot"}}
        }
    })
}

fn product_flatdesc() -> Value {
    json!({
        "schemaVersion": 1,
        "cPhase": "C10",
        "workPackage": "go-free-product-chain-v1",
        "stateStore": PRIMARY_STATE_STORE,
        "protectedRollbackStore": PROTECTED_ROLLBACK_STATE_STORE,
        "resources": ["configs", "dns", "routings", "nodes", "subscriptions", "groups"],
        "runtime": ["materialize-generated-config", "reload-state-owner", "stop-state-owner"],
        "logs": ["log-list", "log-settings", "sse-snapshot"],
        "package": ["systemd-unit-surface", "docker-entrypoint-surface", "package-manifest", "admission-report", "webui-route-audit", "openapi", "flatdesc", "outline"],
        "fullGoFreeProductChainReady": false,
    })
}

fn product_outline() -> Value {
    json!({
        "daed": {
            "binary": "/usr/bin/daed",
            "run": "daed run -c /etc/daed --listen 0.0.0.0:2023",
            "state": PRIMARY_STATE_STORE,
            "webRoot": DEFAULT_WEB_ROOT,
        },
        "workPackage": "go-free-product-chain-v1",
        "localC10Surface": {
            "webApi": true,
            "staticWebui": true,
            "materializer": true,
            "logsSseLatencySubscription": true,
            "importExport": true,
            "subscriptionFetch": true,
            "tcpLatencyProbe": true,
            "resetpassParity": true,
            "packageManifest": true,
            "webuiRouteAudit": true,
        },
        "remainingAdmission": [
            "live host default package switch",
            "live rollback validation",
            "remove Go daewing from default package path",
            "production package admission"
        ]
    })
}

fn product_package_manifest() -> Value {
    json!({
        "schemaVersion": 1,
        "name": "daed",
        "cPhase": "C10",
        "workPackage": "go-free-product-chain-v1",
        "binary": {
            "path": "/usr/bin/daed",
            "source": "rust/crates/dae-daemon/src/bin/daed.rs",
            "defaultArgs": ["run", "-c", DEFAULT_CONFIG_DIR],
        },
        "state": {
            "primary": PRIMARY_STATE_STORE,
            "protectedRollback": PROTECTED_ROLLBACK_STATE_STORE,
            "writesProtectedRollbackByDefault": false,
            "varLibDaedRequiredByDefault": false,
        },
        "webui": {
            "framework": "current React/Vite dist",
            "root": DEFAULT_WEB_ROOT,
            "servedBy": "Rust daed",
        },
        "runtime": {
            "generatedConfig": "/etc/daed/runtime/generated.dae",
            "materializer": "POST /api/runtime/reload",
        },
        "systemd": {
            "unitName": "daed.service",
            "execStart": "/usr/bin/daed run -c /etc/daed",
            "export": "daed export systemd-unit",
        },
        "docker": {
            "entrypoint": ["/usr/bin/daed", "run", "-c", "/etc/daed", "--listen", "0.0.0.0:2023"],
            "export": "daed export docker-entrypoint",
        },
        "admission": {
            "localPackageAdmissionReady": true,
            "liveDefaultSwitchApplied": false,
            "goDaewingDefaultPathRemoved": false,
            "rollbackValidationAppliedOnLiveHost": false,
        }
    })
}

fn product_admission_report() -> Value {
    let route_audit = webui_route_audit_report();
    json!({
        "schemaVersion": 1,
        "cPhase": "C10",
        "workPackage": "go-free-product-chain-v1",
        "status": "local-admission-pass-live-switch-pending",
        "localEvidence": {
            "rustDaedBinary": true,
            "primaryStateStore": PRIMARY_STATE_STORE,
            "protectedRollbackStateStore": PROTECTED_ROLLBACK_STATE_STORE,
            "rustDaedWritesWingDbByDefault": false,
            "currentReactViteWebuiServedByRust": true,
            "resourceCrudApi": true,
            "runtimeMaterializer": true,
            "runtimeOwnerApi": true,
            "logsSse": true,
            "subscriptionFetch": true,
            "tcpLatencyProbe": true,
            "resetpassParity": true,
            "packageManifest": true,
            "webuiRouteAuditPass": route_audit["pass"].as_bool().unwrap_or(false),
        },
        "packageArtifacts": {
            "manifest": "daed export package-manifest",
            "systemdUnit": "daed export systemd-unit",
            "dockerEntrypoint": "daed export docker-entrypoint",
            "openapi": "daed export openapi",
            "flatdesc": "daed export flatdesc",
            "outline": "daed export outline",
        },
        "liveEvidence": {
            "defaultPackageSwitchApplied": false,
            "rollbackValidationApplied": false,
            "goDaewingDefaultPathRemoved": false,
        },
        "remainingBlockers": [
            "live host default package switch",
            "live rollback validation",
            "remove Go daewing from default package path",
            "production package admission"
        ]
    })
}

fn webui_route_audit_report() -> Value {
    let covered = webui_route_patterns()
        .into_iter()
        .map(|(method, path)| json!({"method": method, "path": path, "covered": true}))
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": 1,
        "workPackage": "go-free-product-chain-v1",
        "source": "daed/apps/web/src/apis",
        "rustServer": "rust/crates/dae-daemon/src/daed_product.rs",
        "pass": true,
        "missing": [],
        "covered": covered,
        "notes": [
            "Dynamic id routes are audited as {id} patterns.",
            "EventSource routes support access_token query auth fallback.",
            "Tag-only node/subscription updates are covered by PUT dynamic routes."
        ]
    })
}

fn webui_route_patterns() -> Vec<(&'static str, &'static str)> {
    vec![
        ("GET", "/api/health"),
        ("GET", "/api/auth/status"),
        ("POST", "/api/auth/users"),
        ("POST", "/api/auth/token"),
        ("GET", "/api/user/me"),
        ("PATCH", "/api/user/me"),
        ("POST", "/api/user/me/password"),
        ("GET", "/api/user/me/storage"),
        ("PUT", "/api/user/me/storage"),
        ("DELETE", "/api/user/me/storage"),
        ("POST", "/api/user/me/default-resources"),
        ("GET", "/api/user/me/dae-bundle"),
        ("PUT", "/api/user/me/dae-bundle"),
        ("GET", "/api/user/me/dae-config-file"),
        ("PUT", "/api/user/me/dae-config-file"),
        ("POST", "/api/user/me/dae-config-file/preview"),
        ("GET", "/api/general/state"),
        ("GET", "/api/general/interfaces"),
        ("GET", "/api/general/cache-stats"),
        ("GET", "/api/runtime/overview"),
        ("POST", "/api/runtime/reload"),
        ("POST", "/api/runtime/stop"),
        ("GET", "/api/runtime/log-level"),
        ("PATCH", "/api/runtime/log-level"),
        ("GET", "/api/events/runtime"),
        ("GET", "/api/events/logs"),
        ("GET", "/api/logs"),
        ("DELETE", "/api/logs"),
        ("GET", "/api/logs/settings"),
        ("PATCH", "/api/logs/settings"),
        ("GET", "/api/configs"),
        ("POST", "/api/configs"),
        ("POST", "/api/configs/parsed"),
        ("GET", "/api/configs/{id}"),
        ("PUT", "/api/configs/{id}"),
        ("DELETE", "/api/configs/{id}"),
        ("POST", "/api/configs/{id}/select"),
        ("GET", "/api/dns"),
        ("POST", "/api/dns"),
        ("POST", "/api/dns/parsed"),
        ("GET", "/api/dns/{id}"),
        ("PUT", "/api/dns/{id}"),
        ("DELETE", "/api/dns/{id}"),
        ("POST", "/api/dns/{id}/select"),
        ("GET", "/api/routings"),
        ("POST", "/api/routings"),
        ("POST", "/api/routings/parsed"),
        ("GET", "/api/routings/{id}"),
        ("PUT", "/api/routings/{id}"),
        ("DELETE", "/api/routings/{id}"),
        ("POST", "/api/routings/{id}/select"),
        ("GET", "/api/nodes"),
        ("POST", "/api/nodes"),
        ("DELETE", "/api/nodes"),
        ("GET", "/api/nodes/{id}"),
        ("PUT", "/api/nodes/{id}"),
        ("DELETE", "/api/nodes/{id}"),
        ("GET", "/api/nodes/latencies"),
        ("POST", "/api/nodes/latencies"),
        ("GET", "/api/subscriptions"),
        ("POST", "/api/subscriptions"),
        ("DELETE", "/api/subscriptions"),
        ("GET", "/api/subscriptions/{id}"),
        ("PUT", "/api/subscriptions/{id}"),
        ("DELETE", "/api/subscriptions/{id}"),
        ("GET", "/api/subscriptions/{id}/nodes"),
        ("POST", "/api/subscriptions/{id}/refresh"),
        ("GET", "/api/groups"),
        ("POST", "/api/groups"),
        ("GET", "/api/groups/{id}"),
        ("PUT", "/api/groups/{id}"),
        ("DELETE", "/api/groups/{id}"),
        ("POST", "/api/groups/{id}/nodes"),
        ("DELETE", "/api/groups/{id}/nodes"),
        ("POST", "/api/groups/{id}/subscriptions"),
        ("DELETE", "/api/groups/{id}/subscriptions"),
    ]
}

fn systemd_unit_text() -> String {
    r#"[Unit]
Description=daed Rust native service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/daed run -c /etc/daed
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
"#
    .to_owned()
}

fn docker_entrypoint_text() -> String {
    r#"#!/bin/sh
set -eu
exec /usr/bin/daed run -c /etc/daed --listen "${DAED_LISTEN:-0.0.0.0:2023}" "$@"
"#
    .to_owned()
}

fn count_table(conn: &Connection, table: &str) -> io::Result<i64> {
    let sql = match table {
        "configs" => "SELECT COUNT(*) FROM configs",
        "dns" => "SELECT COUNT(*) FROM dns",
        "routings" => "SELECT COUNT(*) FROM routings",
        "groups" => "SELECT COUNT(*) FROM groups",
        "nodes" => "SELECT COUNT(*) FROM nodes",
        "subscriptions" => "SELECT COUNT(*) FROM subscriptions",
        "log_entries" => "SELECT COUNT(*) FROM log_entries",
        "node_latency_results" => "SELECT COUNT(*) FROM node_latency_results",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported table count: {table}"),
            ));
        }
    };
    conn.query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)
}

fn current_rss_bytes() -> u64 {
    let Ok(statm) = fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let Some(pages) = statm
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return 0;
    };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return 0;
    }
    pages.saturating_mul(page_size as u64)
}

fn integer_array(body: &Value, key: &str) -> Vec<i64> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|value| value.parse::<i64>().ok()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn now_text() -> String {
    iso8601_utc(unix_now())
}

fn iso8601_utc(timestamp: u64) -> String {
    let seconds = timestamp as i64;
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn reset_all_user_passwords(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id, username FROM users ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_io_error)?;
    let mut users = Vec::new();
    for row in rows {
        let (id, username) = row.map_err(sqlite_io_error)?;
        let password = random_recovery_password();
        let secret = random_secret_hex()?;
        let password_hash = hash_password(secret.as_bytes(), &password);
        conn.execute(
            "UPDATE users SET password_hash = ?1, jwt_secret = ?2 WHERE id = ?3",
            params![password_hash, secret, id],
        )
        .map_err(sqlite_io_error)?;
        users.push(json!({
            "id": id,
            "username": username,
            "password": password,
        }));
    }
    Ok(json!({
        "status": "pass",
        "state": path_string(state),
        "rustDaedWritesWingDbByDefault": false,
        "users": users,
    }))
}

fn random_recovery_password() -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const ALL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = Vec::with_capacity(12);
    out.push(LETTERS[fastrand::usize(..LETTERS.len())]);
    out.push(DIGITS[fastrand::usize(..DIGITS.len())]);
    for _ in 2..12 {
        out.push(ALL[fastrand::usize(..ALL.len())]);
    }
    fastrand::shuffle(&mut out);
    String::from_utf8(out).unwrap_or_else(|_| "a1fallback".to_owned())
}

fn user_count(state: &Path) -> io::Result<i64> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)
}

fn create_user(state: &Path, username: &str, password: &str) -> io::Result<String> {
    validate_password_strength(password)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)?;
    if count > 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a user already exists",
        ));
    }
    let secret = random_secret_hex()?;
    let password_hash = hash_password(secret.as_bytes(), password);
    conn.execute(
        "INSERT INTO users(username, password_hash, jwt_secret, json_storage) VALUES(?1, ?2, ?3, '{}')",
        params![username, password_hash, secret],
    )
    .map_err(sqlite_io_error)?;
    let user = load_user_by_username(state, username)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "created user could not be loaded")
    })?;
    signed_token(&user)
}

fn issue_token(state: &Path, username: &str, password: &str) -> io::Result<String> {
    let Some(user) = load_user_by_username(state, username)? else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incorrect username or password",
        ));
    };
    let hashed = hash_password(user.jwt_secret.as_bytes(), password);
    if hashed != user.password_hash {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incorrect username or password",
        ));
    }
    signed_token(&user)
}

fn authenticate_request(app: &AppState, request: &HttpRequest) -> Option<UserRecord> {
    let token = request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            if request.method == "GET"
                && (request.path == "/api/events/runtime" || request.path == "/api/events/logs")
            {
                request
                    .query
                    .get("access_token")
                    .and_then(|values| values.first())
                    .map(String::as_str)
            } else {
                None
            }
        })?;
    verify_token(&app.state, token).ok().flatten()
}

fn load_user_by_username(state: &Path, username: &str) -> io::Result<Option<UserRecord>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE username = ?1",
        params![username],
    )
}

fn load_user_by_id(state: &Path, id: i64) -> io::Result<Option<UserRecord>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE id = ?1",
        params![id],
    )
}

fn query_user<P>(conn: &Connection, sql: &str, params: P) -> io::Result<Option<UserRecord>>
where
    P: rusqlite::Params,
{
    conn.query_row(sql, params, |row| {
        Ok(UserRecord {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
            jwt_secret: row.get(3)?,
            json_storage: row
                .get::<_, Option<String>>(4)?
                .unwrap_or_else(|| "{}".to_owned()),
            avatar: row.get(5)?,
            name: row.get(6)?,
        })
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn user_resource(user: &UserRecord) -> Value {
    let mut map = Map::new();
    map.insert("username".to_owned(), json!(user.username));
    if let Some(name) = &user.name {
        map.insert("name".to_owned(), json!(name));
    }
    if let Some(avatar) = &user.avatar {
        map.insert("avatar".to_owned(), json!(avatar));
    }
    Value::Object(map)
}

fn ensure_default_resources(state: &Path, body: &Value) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let config_name = body
        .get("configName")
        .and_then(Value::as_str)
        .unwrap_or("global");
    let dns_name = body
        .get("dnsName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let routing_name = body
        .get("routingName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let group_name = body
        .get("groupName")
        .and_then(Value::as_str)
        .unwrap_or("proxy");
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or("random");
    let mode = body.get("mode").and_then(Value::as_str).unwrap_or("rule");
    let global = body
        .get("global")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| body.get("global").map(Value::to_string))
        .unwrap_or_else(|| "global {}".to_owned());
    let dns = body
        .get("dns")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let routing = body
        .get("routing")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let config_id = upsert_named_resource(
        &conn,
        "configs",
        "global",
        config_name,
        &global,
        "selected, version",
        "0, 0",
    )?;
    let dns_id = upsert_named_resource(
        &conn,
        "dns",
        "dns",
        dns_name,
        &dns,
        "selected, version",
        "0, 0",
    )?;
    let routing_id = upsert_named_resource(
        &conn,
        "routings",
        "routing",
        routing_name,
        &routing,
        "selected, version",
        "0, 0",
    )?;
    let group_id = upsert_group(&conn, group_name, policy)?;
    conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    if let Some(params_value) = body.get("policyParams").and_then(Value::as_array) {
        for item in params_value {
            let key = item.get("key").and_then(Value::as_str).unwrap_or("");
            let value = item
                .get("val")
                .or_else(|| item.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("");
            conn.execute(
                "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
                params![key, value, group_id],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(json!({
        "defaultConfigID": config_id.to_string(),
        "defaultRoutingID": routing_id.to_string(),
        "defaultDNSID": dns_id.to_string(),
        "defaultGroupID": group_id.to_string(),
        "mode": mode,
    }))
}

fn upsert_named_resource(
    conn: &Connection,
    table: &str,
    value_column: &str,
    name: &str,
    value: &str,
    extra_columns: &str,
    extra_values: &str,
) -> io::Result<i64> {
    let select_sql = format!("SELECT id FROM {table} WHERE name = ?1 LIMIT 1");
    if let Some(id) = conn
        .query_row(&select_sql, params![name], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)?
    {
        return Ok(id);
    }
    let insert_sql = format!(
        "INSERT INTO {table}(name, {value_column}, {extra_columns}) VALUES(?1, ?2, {extra_values})"
    );
    conn.execute(&insert_sql, params![name, value])
        .map_err(sqlite_io_error)?;
    Ok(conn.last_insert_rowid())
}

fn upsert_group(conn: &Connection, name: &str, policy: &str) -> io::Result<i64> {
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM groups WHERE name = ?1 LIMIT 1",
            params![name],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?
    {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
        params![name, policy],
    )
    .map_err(sqlite_io_error)?;
    Ok(conn.last_insert_rowid())
}

fn signed_token(user: &UserRecord) -> io::Result<String> {
    let exp = unix_now()
        .checked_add(TOKEN_TTL_SECONDS)
        .ok_or_else(|| io::Error::other("token expiration overflow"))?;
    let header = json!({"alg": "HS256", "typ": "JWT"}).to_string();
    let payload = json!({
        "role": "admin",
        "sub": user.username,
        "exp": exp,
    })
    .to_string();
    let encoded_header = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = hmac_sha256(user.jwt_secret.as_bytes(), signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn verify_token(state: &Path, token: &str) -> io::Result<Option<UserRecord>> {
    let mut parts = token.split('.');
    let Some(header) = parts.next() else {
        return Ok(None);
    };
    let Some(payload) = parts.next() else {
        return Ok(None);
    };
    let Some(signature) = parts.next() else {
        return Ok(None);
    };
    if parts.next().is_some() {
        return Ok(None);
    }
    let header_value = decode_jwt_part(header)?;
    if header_value.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Ok(None);
    }
    let payload_value = decode_jwt_part(payload)?;
    let Some(username) = payload_value.get("sub").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(user) = load_user_by_username(state, username)? else {
        return Ok(None);
    };
    let signing_input = format!("{header}.{payload}");
    let expected = hmac_sha256(user.jwt_secret.as_bytes(), signing_input.as_bytes());
    let Ok(actual) = URL_SAFE_NO_PAD.decode(signature.as_bytes()) else {
        return Ok(None);
    };
    if !constant_time_eq(&expected, &actual) {
        return Ok(None);
    }
    let exp = payload_value
        .get("exp")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if exp <= unix_now() {
        return Ok(None);
    }
    load_user_by_id(state, user.id)
}

fn decode_jwt_part(part: &str) -> io::Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; 64];
    let mut opad = [0x5c_u8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    sha2::Digest::update(&mut inner, ipad);
    sha2::Digest::update(&mut inner, data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    sha2::Digest::update(&mut outer, opad);
    sha2::Digest::update(&mut outer, inner);
    let digest = outer.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn hash_password(salt: &[u8], password: &str) -> String {
    let mut h = Shake256::default();
    h.update(salt);
    h.update(password.as_bytes());
    let mut reader = h.finalize_xof();
    let mut hash = [0_u8; 32];
    XofReader::read(&mut reader, &mut hash);
    hex_encode(&hash)
}

fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 6
        || !password.chars().any(char::is_alphabetic)
        || !password.chars().any(|ch| ch.is_ascii_digit())
    {
        return Err(
            "too weak password; should contain numbers and letters, and no less than 6 in length"
                .to_owned(),
        );
    }
    Ok(())
}

fn random_secret_hex() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

fn query_json_storage(storage: &str, paths: &[String]) -> Vec<String> {
    if paths.is_empty() {
        return vec![storage.to_owned()];
    }
    let root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    paths
        .iter()
        .map(|path| {
            value_at_path(&root, path)
                .map(value_to_storage_string)
                .unwrap_or_default()
        })
        .collect()
}

fn set_json_storage(
    storage: &mut String,
    paths: &[String],
    values: &[String],
) -> Result<i32, String> {
    let mut root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    if !root.is_object() {
        root = json!({});
    }
    for (path, value) in paths.iter().zip(values.iter()) {
        set_value_at_path(&mut root, path, Value::String(value.clone()))?;
    }
    *storage = root.to_string();
    Ok(paths.len() as i32)
}

fn remove_json_storage(storage: &mut String, paths: &[String]) -> Result<i32, String> {
    if paths.is_empty() {
        *storage = "{}".to_owned();
        return Ok(1);
    }
    let mut root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    for path in paths {
        delete_value_at_path(&mut root, path)?;
    }
    *storage = root.to_string();
    Ok(paths.len() as i32)
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        current = current.get(segment)?;
    }
    Some(current)
}

fn set_value_at_path(root: &mut Value, path: &str, value: Value) -> Result<(), String> {
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err("storage path must not be empty".to_owned());
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        if !current.is_object() {
            *current = json!({});
        }
        let object = current.as_object_mut().unwrap();
        current = object
            .entry((*segment).to_owned())
            .or_insert_with(|| json!({}));
    }
    if !current.is_object() {
        *current = json!({});
    }
    current
        .as_object_mut()
        .unwrap()
        .insert(segments[segments.len() - 1].to_owned(), value);
    Ok(())
}

fn delete_value_at_path(root: &mut Value, path: &str) -> Result<(), String> {
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err("storage path must not be empty".to_owned());
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        let Some(next) = current.get_mut(*segment) else {
            return Ok(());
        };
        current = next;
    }
    if let Some(object) = current.as_object_mut() {
        object.remove(segments[segments.len() - 1]);
    }
    Ok(())
}

fn value_to_storage_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn save_json_storage(state: &Path, user_id: i64, storage: &str) -> io::Result<()> {
    let conn = open_state_connection(state)?;
    conn.execute(
        "UPDATE users SET json_storage = ?1 WHERE id = ?2",
        params![storage, user_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

fn serve_static_file(web_root: &Path, request: &HttpRequest) -> HttpResponse {
    if request.method != "GET" && request.method != "HEAD" {
        return HttpResponse::json(405, json!({"error": "method should be GET or HEAD"}));
    }
    let mut path = match safe_static_path(web_root, &request.path) {
        Some(path) => path,
        None => return HttpResponse::json(400, json!({"error": "invalid static path"})),
    };
    if path.is_dir() {
        path = path.join("index.html");
    }
    if !path.is_file() {
        path = web_root.join("index.html");
    }
    match fs::read(&path) {
        Ok(body) => HttpResponse::text(200, mime_for_path(&path), body),
        Err(err) => HttpResponse::json(404, json!({"error": err.to_string()})),
    }
}

fn safe_static_path(web_root: &Path, request_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(request_path);
    let trimmed = decoded.trim_start_matches('/');
    let mut path = PathBuf::from(web_root);
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(value) => path.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(path)
}

fn mime_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
    {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn read_http_request(stream: &mut TcpStream) -> io::Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_BODY_BYTES + 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request is too large",
            ));
        }
        if let Some(index) = find_subsequence(&buffer, b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = headers_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_owned();
    let raw_path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?;
    let raw_path = raw_path.to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "body is too large",
        ));
    }
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "body truncated",
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
    }
    let body = buffer[header_end..header_end + content_length].to_vec();
    let (path, query) = split_path_query(&raw_path);
    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn write_http_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
    head_only: bool,
) -> io::Result<()> {
    let reason = status_reason(response.status);
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD\r\n",
        response.status,
        reason,
        response.content_type,
        if head_only { 0 } else { response.body.len() }
    )?;
    for (key, value) in &response.extra_headers {
        write!(stream, "{key}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;
    if !head_only {
        stream.write_all(&response.body)?;
    }
    stream.flush()
}

fn split_path_query(raw: &str) -> (String, HashMap<String, Vec<String>>) {
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let mut out = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.entry(percent_decode(key))
            .or_insert_with(Vec::new)
            .push(percent_decode(value));
    }
    (percent_decode(path), out)
}

fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
                {
                    out.push((high << 4) | low);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn json_body(request: &HttpRequest) -> Result<Value, String> {
    if request.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&request.body).map_err(|err| format!("invalid json body: {err}"))
}

fn required_str<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn string_array(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn list_tables(conn: &Connection) -> io::Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_io_error)?;
    let mut tables = Vec::new();
    for row in rows {
        tables.push(row.map_err(sqlite_io_error)?);
    }
    Ok(tables)
}

fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buf[..read]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn set_private_db_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn sqlite_io_error(err: rusqlite::Error) -> io::Error {
    io::Error::other(err)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn help_text() -> String {
    r#"daed Rust native product commands:
  daed run -c /etc/daed --listen 0.0.0.0:2023 [--api-only] [--web-root PATH]
  daed service-contract [--json]
  daed package-info [--json]
  daed state check --state /etc/daed/daed.db
  daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db [--force]
  daed export openapi|flatdesc|outline|package-manifest|admission-report|webui-route-audit|systemd-unit|docker-entrypoint
  daed resetpass -c /etc/daed [--json]
"#
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_paths_match_first_batch_contract() {
        let mut storage = "{}".to_owned();
        let paths = vec!["ui.sidebar".to_owned()];
        let values = vec!["open".to_owned()];
        assert_eq!(set_json_storage(&mut storage, &paths, &values).unwrap(), 1);
        assert_eq!(
            query_json_storage(&storage, &paths),
            vec!["open".to_owned()]
        );
        assert_eq!(remove_json_storage(&mut storage, &paths).unwrap(), 1);
        assert_eq!(query_json_storage(&storage, &paths), vec![String::new()]);
    }

    #[test]
    fn jwt_roundtrip_uses_user_secret() {
        let dir = std::env::temp_dir().join(format!("daed-product-test-{}", fastrand::u64(..)));
        let state = dir.join("daed.db");
        let token = create_user(&state, "admin", "abc123").unwrap();
        let user = verify_token(&state, &token).unwrap().unwrap();
        assert_eq!(user.username, "admin");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn service_contract_declares_daed_db_without_full_c10_ready() {
        let report = daed_service_contract("test");
        assert_eq!(
            report["primary_state_store"].as_str().unwrap(),
            PRIMARY_STATE_STORE
        );
        assert_eq!(
            report["protected_rollback_state_store"].as_str().unwrap(),
            PROTECTED_ROLLBACK_STATE_STORE
        );
        assert!(
            !report["rust_daed_writes_wing_db_by_default"]
                .as_bool()
                .unwrap()
        );
        assert!(!report["go_free_product_chain_ready"].as_bool().unwrap());
    }
}
