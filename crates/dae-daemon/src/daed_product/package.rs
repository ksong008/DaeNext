use super::*;
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
