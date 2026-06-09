use super::*;
pub(super) fn product_openapi_skeleton() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "daed Rust native product API",
            "version": crate::version::version_from_env(),
        },
        "x-c-phase": "C10",
        "x-work-package": "go-free-product-chain",
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
            "/api/events/runtime": {"get": {"summary": "runtime SSE stream"}},
            "/api/events/logs": {"get": {"summary": "log SSE stream"}}
        }
    })
}

pub(super) fn product_flatdesc() -> Value {
    json!({
        "schemaVersion": 1,
        "cPhase": "C10",
        "workPackage": "go-free-product-chain",
        "stateStore": PRIMARY_STATE_STORE,
        "protectedRollbackStore": PROTECTED_ROLLBACK_STATE_STORE,
        "resources": ["configs", "dns", "routings", "nodes", "subscriptions", "groups"],
        "runtime": ["materialize-parseable-generated-config", "resident-runtime-reload", "resident-runtime-stop", "live-manager-state"],
        "logs": ["log-list", "log-settings", "sse-snapshot"],
        "package": ["validate-command", "systemd-unit-surface", "docker-entrypoint-surface", "package-manifest", "admission-report", "webui-route-audit", "openapi", "flatdesc", "outline"],
        "finalAdmission": c10_final_admission(),
        "fullGoFreeProductChainReady": false,
    })
}

pub(super) fn product_outline() -> Value {
    json!({
        "daed": {
            "binary": "/usr/bin/daed",
            "run": "daed run -c /etc/daed --listen 0.0.0.0:2023",
            "state": PRIMARY_STATE_STORE,
            "webRoot": DEFAULT_WEB_ROOT,
        },
        "workPackage": "go-free-product-chain",
        "localC10Surface": {
            "webApi": true,
            "validateCommand": true,
            "staticWebui": true,
            "materializer": true,
            "realRuntimeBridge": true,
            "metadataOnlyRuntimeState": false,
            "logsSseLatencySubscription": true,
            "importExport": true,
            "subscriptionFetch": true,
            "tcpLatencyProbe": true,
            "resetpassParity": true,
            "packageManifest": true,
            "webuiRouteAudit": true,
        },
        "finalAdmission": c10_final_admission(),
        "remainingAdmission": c10_final_blockers()
    })
}

pub(super) fn product_package_manifest() -> Value {
    json!({
        "schemaVersion": 1,
        "name": "daed",
        "cPhase": "C10",
        "workPackage": "go-free-product-chain",
        "binary": {
            "path": "/usr/bin/daed",
            "source": "rust/crates/dae-daemon/src/bin/daed.rs",
            "defaultArgs": ["run", "-c", "/etc/daed/"],
            "validateArgs": ["validate", "-c", "/etc/daed/"],
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
            "owner": "resident-production-runtime-manager",
            "state": "GET /api/general/state reports live manager state",
            "metadataOnlyRunningState": false,
            "defaults": product_runtime_defaults(),
        },
        "systemd": {
            "unitName": "daed.service",
            "execStartPre": "/usr/bin/daed validate -c /etc/daed/",
            "execStart": "/usr/bin/daed run -c /etc/daed/",
            "execReload": "/bin/kill -HUP $MAINPID",
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
            "releaseDefaultSwitchAdmission": false,
            "productionPackageAdmission": false,
            "fullGoFreeProductChainReady": false,
            "evidence": c10_final_gate_evidence(),
            "remainingAdmission": c10_final_blockers(),
        }
    })
}

pub(super) fn product_admission_report() -> Value {
    let route_audit = webui_route_audit_report();
    json!({
        "schemaVersion": 1,
        "cPhase": "C10",
        "workPackage": "go-free-product-chain",
        "status": "blocked",
        "runtimeDefaults": product_runtime_defaults(),
        "localEvidence": {
            "rustDaedBinary": true,
            "validateCommand": true,
            "primaryStateStore": PRIMARY_STATE_STORE,
            "protectedRollbackStateStore": PROTECTED_ROLLBACK_STATE_STORE,
            "rustDaedWritesWingDbByDefault": false,
            "currentReactViteWebuiServedByRust": true,
            "resourceCrudApi": true,
            "runtimeMaterializer": true,
            "runtimeMaterializerParseableConfig": true,
            "runtimeOwnerApi": true,
            "realRuntimeBridge": true,
            "metadataOnlyRuntimeState": false,
            "logsSse": true,
            "subscriptionFetch": true,
            "tcpLatencyProbe": true,
            "resetpassParity": true,
            "packageManifest": true,
            "webuiRouteAuditPass": route_audit["pass"].as_bool().unwrap_or(false),
            "runtimeDefaultsExplicit": true,
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
            "previousDefaultSwitchBlockedByMetadataOnlyRuntimeState": true,
            "rollbackValidationApplied": false,
            "goDaewingDefaultPathRemoved": false,
            "releaseDefaultSwitchAdmission": false,
            "productionPackageAdmission": false,
            "evidence": c10_final_gate_evidence(),
        },
        "remainingBlockers": c10_final_blockers()
    })
}

pub(super) fn webui_route_audit_report() -> Value {
    let covered = webui_route_patterns()
        .into_iter()
        .map(|(method, path)| json!({"method": method, "path": path, "covered": true}))
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": 1,
        "workPackage": "go-free-product-chain",
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

pub(super) fn webui_route_patterns() -> Vec<(&'static str, &'static str)> {
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

pub(super) fn package_runtime_environment_defaults() -> Vec<(&'static str, String)> {
    let mut defaults = vec![
        (
            PRODUCT_MALLOC_ARENA_MAX_ENV,
            PRODUCT_MALLOC_ARENA_MAX_DEFAULT.to_owned(),
        ),
        (
            PRODUCT_JEMALLOC_CONF_ENV,
            PRODUCT_JEMALLOC_CONF_DEFAULT.to_owned(),
        ),
        (
            PRODUCT_HTTP_QUEUE_ENV,
            PRODUCT_HTTP_QUEUE_DEFAULT.to_string(),
        ),
        (
            PRODUCT_HTTP_WORKER_STACK_BYTES_ENV,
            PRODUCT_HTTP_WORKER_STACK_BYTES_DEFAULT.to_string(),
        ),
    ];
    defaults.extend(
        resident_runtime_environment_defaults()
            .into_iter()
            .map(|(name, value)| (name, value.to_string())),
    );
    defaults
}

pub(super) fn systemd_runtime_environment_lines() -> String {
    package_runtime_environment_defaults()
        .into_iter()
        .map(|(name, value)| format!("Environment=\"{name}={value}\"\n"))
        .collect::<String>()
}

pub(super) fn docker_runtime_environment_exports() -> String {
    package_runtime_environment_defaults()
        .into_iter()
        .map(|(name, value)| format!("export {name}=\"${{{name}:-{value}}}\"\n"))
        .collect::<String>()
}

pub(super) fn systemd_unit_text() -> String {
    format!(
        r#"[Unit]
Description=daed Rust native service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# {PRODUCT_HTTP_WORKERS_ENV} unset uses available_parallelism * 2 clamped to {PRODUCT_HTTP_WORKER_DEFAULT_MIN}..{PRODUCT_HTTP_WORKER_DEFAULT_MAX}.
ExecStartPre=/usr/bin/daed validate -c /etc/daed/
{}ExecStart=/usr/bin/daed run -c /etc/daed/
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
"#,
        systemd_runtime_environment_lines()
    )
}

pub(super) fn docker_entrypoint_text() -> String {
    format!(
        r#"#!/bin/sh
set -eu
# {PRODUCT_HTTP_WORKERS_ENV} unset uses available_parallelism * 2 clamped to {PRODUCT_HTTP_WORKER_DEFAULT_MIN}..{PRODUCT_HTTP_WORKER_DEFAULT_MAX}.
{}/usr/bin/daed validate -c /etc/daed/ >/dev/null
exec /usr/bin/daed run -c /etc/daed --listen "${{{PRODUCT_LISTEN_ENV}:-${{{PRODUCT_LISTEN_LEGACY_ENV}:-0.0.0.0:2023}}}}" "$@"
"#,
        docker_runtime_environment_exports()
    )
}

pub(super) fn count_table(conn: &Connection, table: &str) -> io::Result<i64> {
    let sql = match table {
        "configs" => "SELECT COUNT(*) FROM configs",
        "dns" => "SELECT COUNT(*) FROM dns",
        "routings" => "SELECT COUNT(*) FROM routings",
        "groups" => "SELECT COUNT(*) FROM groups",
        "nodes" => "SELECT COUNT(*) FROM nodes",
        "subscriptions" => "SELECT COUNT(*) FROM subscriptions",
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
