use super::*;
pub(super) fn product_openapi_skeleton() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "daed Rust native product API",
            "version": crate::version::version_from_env(),
        },
        "x-runtime-surface": "native-product",
        "x-runtime-state": "runtime-state",
        "paths": {
            "/api/health": {"get": {"summary": "health"}},
            "/api/auth/status": {"get": {"summary": "setup/auth status"}},
            "/api/user/me": {"get": {"summary": "current user"}, "patch": {"summary": "update current user"}},
            "/api/user/me/storage": {"get": {"summary": "read JSON storage"}, "put": {"summary": "write JSON storage"}, "delete": {"summary": "delete JSON storage"}},
            "/api/user/me/dae-bundle": {"get": {"summary": "export DAE bundle"}, "put": {"summary": "import DAE bundle"}},
            "/api/profiles/select": {"post": {"summary": "atomically select config, DNS, and routing resources"}},
            "/api/user/me/dae-config-file": {"get": {"summary": "export generated DAE config"}, "put": {"summary": "import DAE config"}},
            "/api/configs": {"get": {"summary": "list config resources"}, "post": {"summary": "create config resource"}},
            "/api/dns": {"get": {"summary": "list DNS resources"}, "post": {"summary": "create DNS resource"}},
            "/api/routings": {"get": {"summary": "list routing resources"}, "post": {"summary": "create routing resource"}},
            "/api/nodes": {"get": {"summary": "list nodes"}, "post": {"summary": "import nodes"}, "delete": {"summary": "delete nodes"}},
            "/api/subscriptions": {"get": {"summary": "list subscriptions"}, "post": {"summary": "import subscription"}, "delete": {"summary": "delete subscriptions"}},
            "/api/groups": {"get": {"summary": "list groups"}, "post": {"summary": "create group"}},
            "/api/groups/subscription-preview": {"post": {"summary": "preview subscription node-name filtering"}},
            "/api/groups/{id}/nodes": {"post": {"summary": "add group nodes"}, "put": {"summary": "atomically replace group nodes"}, "delete": {"summary": "delete group nodes"}},
            "/api/nodes/latencies": {"get": {"summary": "list latency results"}, "post": {"summary": "enqueue latency test"}},
            "/api/nodes/latencies/job": {"get": {"summary": "current latency test job"}, "delete": {"summary": "cancel latency test job"}},
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
        "productSurface": "native-product",
        "runtimeState": "runtime-state",
        "stateStore": PRIMARY_STATE_STORE,
        "legacyImportStore": LEGACY_IMPORT_STATE_STORE,
        "resources": ["configs", "dns", "routings", "nodes", "subscriptions", "groups"],
        "runtime": ["materialize-parseable-generated-config", "resident-runtime-reload", "resident-runtime-stop", "live-manager-state"],
        "logs": ["log-list", "log-settings", "sse-snapshot"],
        "package": ["validate-command", "systemd-unit-surface", "docker-entrypoint-surface", "package-manifest", "admission-report", "webui-route-audit", "openapi", "flatdesc", "outline"],
        "productionAdmission": production_admission(),
        "runtimeStateReady": false,
        "finalAdmission": production_admission(),
        "fullRuntimeStateReady": false,
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
        "runtimeState": "runtime-state",
        "localProductSurface": {
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
        "productionAdmission": production_admission(),
        "remainingAdmission": runtime_state_blockers(),
        "finalAdmission": production_admission()
    })
}

pub(super) fn product_package_manifest() -> Value {
    json!({
        "schemaVersion": 1,
        "name": "daed",
        "productSurface": "native-product",
        "workPackage": "runtime-state",
        "binary": {
            "path": "/usr/bin/daed",
            "source": "crates/dae-daemon/src/bin/daed.rs",
            "defaultArgs": ["run", "-c", "/etc/daed/"],
            "validateArgs": ["validate", "-c", "/etc/daed/"],
        },
        "state": {
            "primary": PRIMARY_STATE_STORE,
            "legacyImport": LEGACY_IMPORT_STATE_STORE,
            "writesLegacyImportByDefault": false,
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
            "execReload": "/usr/bin/daed reload --timeout 60s",
            "export": "daed export systemd-unit",
        },
        "docker": {
            "entrypoint": ["/usr/bin/daed", "run", "-c", "/etc/daed", "--listen", "0.0.0.0:2023"],
            "export": "daed export docker-entrypoint",
        },
        "admission": {
            "localPackageAdmissionReady": true,
            "liveHostReplacementApplied": false,
            "finalStateValidationAppliedOnLiveHost": false,
            "productPackageReady": false,
            "nativeProductShellReady": false,
            "nativeOutboundDependencyReady": false,
            "userlandNativeAbiReady": false,
            "runtimeStateReady": false,
            "fullRuntimeStateReady": false,
            "evidence": runtime_state_gate_evidence(),
            "remainingAdmission": runtime_state_blockers(),
        }
    })
}

pub(super) fn product_admission_report() -> Value {
    let route_audit = webui_route_audit_report();
    json!({
        "schemaVersion": 1,
        "productSurface": "native-product",
        "workPackage": "runtime-state",
        "status": "blocked",
        "runtimeDefaults": product_runtime_defaults(),
        "localEvidence": {
            "rustDaedBinary": true,
            "validateCommand": true,
            "primaryStateStore": PRIMARY_STATE_STORE,
            "legacyImportStateStore": LEGACY_IMPORT_STATE_STORE,
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
            "liveHostReplacementApplied": false,
            "finalStateValidationApplied": false,
            "productPackageReady": false,
            "nativeProductShellReady": false,
            "nativeOutboundDependencyReady": false,
            "userlandNativeAbiReady": false,
            "evidence": runtime_state_gate_evidence(),
        },
        "remainingBlockers": runtime_state_blockers()
    })
}

pub(super) fn systemd_unit_text() -> String {
    r#"[Unit]
Description=daed is a integration solution of dae, API and UI.
Documentation=https://github.com/ksong008/DaeNext
After=network-online.target docker.service systemd-sysctl.service
Wants=network-online.target
Conflicts=dae.service

[Service]
Type=simple
User=root
LimitNPROC=512
LimitNOFILE=1048576
RuntimeDirectory=daed
RuntimeDirectoryMode=0700
ExecStartPre=/usr/bin/daed validate -c /etc/daed/
ExecStart=/usr/bin/daed run -c /etc/daed/
ExecReload=/usr/bin/daed reload --timeout 60s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
"#
    .to_owned()
}

pub(super) fn docker_entrypoint_text() -> String {
    format!(
        r#"#!/bin/sh
set -eu
# Runtime defaults are owned by the binary; user-provided environment remains optional.
/usr/bin/daed validate -c /etc/daed/ >/dev/null
exec /usr/bin/daed run -c /etc/daed --listen "${{{PRODUCT_LISTEN_ENV}:-${{{PRODUCT_LISTEN_LEGACY_ENV}:-0.0.0.0:2023}}}}" "$@"
"#
    )
}
