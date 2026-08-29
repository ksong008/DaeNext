use serde_json::{Value, json};

#[derive(Clone, Debug)]
pub struct ProductPackageContext {
    primary_state_store: String,
    legacy_import_state_store: String,
    web_root: String,
    production_admission: Value,
    runtime_defaults: Value,
    runtime_state_gate_evidence: Value,
    remaining_admission: Vec<String>,
    route_audit: Value,
}

impl ProductPackageContext {
    pub fn new(
        primary_state_store: impl Into<String>,
        legacy_import_state_store: impl Into<String>,
        web_root: impl Into<String>,
        production_admission: Value,
        runtime_defaults: Value,
        runtime_state_gate_evidence: Value,
        remaining_admission: Vec<String>,
        route_audit: Value,
    ) -> Self {
        Self {
            primary_state_store: primary_state_store.into(),
            legacy_import_state_store: legacy_import_state_store.into(),
            web_root: web_root.into(),
            production_admission,
            runtime_defaults,
            runtime_state_gate_evidence,
            remaining_admission,
            route_audit,
        }
    }

    pub fn flatdesc(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "productSurface": "native-product",
            "runtimeState": "runtime-state",
            "stateStore": self.primary_state_store,
            "legacyImportStore": self.legacy_import_state_store,
            "resources": ["configs", "dns", "routings", "nodes", "subscriptions", "groups"],
            "runtime": ["materialize-parseable-generated-config", "resident-runtime-reload", "resident-runtime-stop", "live-manager-state"],
            "logs": ["log-list", "log-settings", "sse-snapshot"],
            "package": ["validate-command", "systemd-unit-surface", "docker-entrypoint-surface", "package-manifest", "admission-report", "webui-route-audit", "openapi", "flatdesc", "outline"],
            "productionAdmission": self.production_admission,
            "runtimeStateReady": false,
            "finalAdmission": self.production_admission,
            "fullRuntimeStateReady": false,
        })
    }

    pub fn outline(&self) -> Value {
        json!({
            "daed": {
                "binary": "/usr/bin/daed",
                "run": "daed run -c /etc/daed --listen 0.0.0.0:2023",
                "state": self.primary_state_store,
                "webRoot": self.web_root,
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
            "productionAdmission": self.production_admission,
            "remainingAdmission": self.remaining_admission,
            "finalAdmission": self.production_admission
        })
    }

    pub fn package_manifest(&self) -> Value {
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
                "primary": self.primary_state_store,
                "legacyImport": self.legacy_import_state_store,
                "writesLegacyImportByDefault": false,
                "varLibDaedRequiredByDefault": false,
            },
            "webui": {
                "framework": "current React/Vite dist",
                "root": self.web_root,
                "servedBy": "Rust daed",
            },
            "runtime": {
                "generatedConfig": "/etc/daed/runtime/generated.dae",
                "materializer": "POST /api/runtime/reload",
                "owner": "resident-production-runtime-manager",
                "state": "GET /api/general/state reports live manager state",
                "metadataOnlyRunningState": false,
                "defaults": self.runtime_defaults,
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
                "evidence": self.runtime_state_gate_evidence,
                "remainingAdmission": self.remaining_admission,
            }
        })
    }

    pub fn admission_report(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "productSurface": "native-product",
            "workPackage": "runtime-state",
            "status": "blocked",
            "runtimeDefaults": self.runtime_defaults,
            "localEvidence": {
                "rustDaedBinary": true,
                "validateCommand": true,
                "primaryStateStore": self.primary_state_store,
                "legacyImportStateStore": self.legacy_import_state_store,
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
                "webuiRouteAuditPass": self.route_audit["pass"].as_bool().unwrap_or(false),
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
                "evidence": self.runtime_state_gate_evidence,
            },
            "remainingBlockers": self.remaining_admission
        })
    }
}
