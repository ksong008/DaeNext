use super::*;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DATAPATH_POSTFLIGHT_INTERVAL_ENV: &str = "RESIDENT_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS";
const DATAPATH_POSTFLIGHT_INTERVAL_MIN_SECONDS: u64 = 1;
const DATAPATH_POSTFLIGHT_INTERVAL_MAX_SECONDS: u64 = 3_600;
const DATAPATH_BINDING_DRIFT_REASON: &str = "datapath-binding-postflight-failed";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatapathPostflightIntervalSource {
    Profile,
    Environment,
}

impl DatapathPostflightIntervalSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "runtime-profile",
            Self::Environment => "env",
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::production_runtime_owner::resident) struct ResidentDatapathBindingMonitor {
    registry: ResidentDatapathBindingRegistry,
    interval: Duration,
    interval_default_seconds: u64,
    interval_source: DatapathPostflightIntervalSource,
    report: Value,
    last_checked: Instant,
    checked_at_unix: u64,
    checks_completed: u64,
}

impl ResidentDatapathBindingMonitor {
    pub(in crate::production_runtime_owner::resident) fn new(
        registry: &ResidentDatapathBindingRegistry,
        initial_report: &Value,
    ) -> Option<Self> {
        if registry.is_empty() {
            return None;
        }
        let interval_default_seconds = resident_datapath_postflight_interval_seconds_default();
        let (interval_seconds, interval_source) = std::env::var(DATAPATH_POSTFLIGHT_INTERVAL_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .map(|seconds| {
                (
                    seconds.clamp(
                        DATAPATH_POSTFLIGHT_INTERVAL_MIN_SECONDS,
                        DATAPATH_POSTFLIGHT_INTERVAL_MAX_SECONDS,
                    ),
                    DatapathPostflightIntervalSource::Environment,
                )
            })
            .unwrap_or((
                interval_default_seconds,
                DatapathPostflightIntervalSource::Profile,
            ));
        Some(Self {
            registry: registry.clone(),
            interval: Duration::from_secs(interval_seconds),
            interval_default_seconds,
            interval_source,
            report: initial_report.clone(),
            last_checked: Instant::now(),
            checked_at_unix: unix_now_secs(),
            checks_completed: 1,
        })
    }

    pub(in crate::production_runtime_owner::resident) fn observe_if_due(&mut self) {
        if self.last_checked.elapsed() < self.interval {
            return;
        }
        self.report = self.registry.active_postflight();
        self.last_checked = Instant::now();
        self.checked_at_unix = unix_now_secs();
        self.checks_completed = self.checks_completed.saturating_add(1);
    }

    pub(in crate::production_runtime_owner::resident) fn merge_snapshot(
        &self,
        snapshot: &mut Value,
    ) {
        let status = self.report["status"].as_str().unwrap_or("fail");
        snapshot["datapathBindingMonitor"] = json!({
            "schemaVersion": 1,
            "status": status,
            "intervalSeconds": self.interval.as_secs(),
            "intervalDefaultSeconds": self.interval_default_seconds,
            "intervalMinSeconds": DATAPATH_POSTFLIGHT_INTERVAL_MIN_SECONDS,
            "intervalMaxSeconds": DATAPATH_POSTFLIGHT_INTERVAL_MAX_SECONDS,
            "intervalSource": self.interval_source.as_str(),
            "intervalEnv": DATAPATH_POSTFLIGHT_INTERVAL_ENV,
            "checkedAtUnix": self.checked_at_unix,
            "checksCompleted": self.checks_completed,
            "report": self.report,
            "repairPolicy": "coordinated-generation-rebuild-with-complete-postflight",
        });
        if status == "pass" {
            return;
        }

        snapshot["status"] = json!(MONITOR_STATUS_DEGRADED);
        snapshot["reattachRequired"] = json!(true);
        let structurally_ready = snapshot
            .pointer("/recoveryDebounce/structurallyReady")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| {
                snapshot["interfaces"].as_array().is_none_or(|interfaces| {
                    interfaces.iter().all(|interface| {
                        interface["exists"].as_bool().unwrap_or(false)
                            && interface
                                .pointer("/current/errors")
                                .and_then(Value::as_array)
                                .is_none_or(Vec::is_empty)
                    })
                })
            });
        snapshot["reattachReady"] = json!(structurally_ready);
        let reasons = snapshot
            .get_mut("reattachReasons")
            .and_then(Value::as_array_mut);
        if let Some(reasons) = reasons
            && !reasons
                .iter()
                .any(|reason| reason.as_str() == Some(DATAPATH_BINDING_DRIFT_REASON))
        {
            reasons.push(json!(DATAPATH_BINDING_DRIFT_REASON));
        }
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ResidentDatapathBindingRegistry {
        ResidentDatapathBindingRegistry {
            generation: 7,
            owner_process_id: 11,
            tc: vec![ResidentTcBinding {
                role: ResidentDatapathBindingRole::WanIngress,
                backend: ResidentTcBindingBackend::Tcx,
                interface: "wan-fixture0".to_owned(),
                ifindex: 17,
                netns: None,
                direction: dae_ebpf_support::TcAttachDirection::Ingress,
                program_id: 42,
                program_name: "fixture_ingress".to_owned(),
                program_tag: "0011223344556677".to_owned(),
                priority: 1,
                handle: 0x2023_0002,
                tcx_order: "first".to_owned(),
                tcx_anchor_relation: None,
                tcx_anchor_program_id: None,
                foreign_program_order_before: Vec::new(),
            }],
            cgroup: Vec::new(),
        }
    }

    fn interface_snapshot() -> Value {
        json!({
            "status": "pass",
            "reattachRequired": false,
            "reattachReady": false,
            "reattachReasons": [],
            "recoveryDebounce": { "structurallyReady": true },
            "interfaces": [],
        })
    }

    #[test]
    fn failed_binding_postflight_arms_coordinated_recovery() {
        let report = json!({"status": "fail", "failedCount": 1});
        let monitor = ResidentDatapathBindingMonitor::new(&registry(), &report).unwrap();
        let mut snapshot = interface_snapshot();

        monitor.merge_snapshot(&mut snapshot);

        assert_eq!(snapshot["status"], "degraded");
        assert_eq!(snapshot["reattachRequired"], true);
        assert_eq!(snapshot["reattachReady"], true);
        assert_eq!(
            snapshot["reattachReasons"],
            json!([DATAPATH_BINDING_DRIFT_REASON])
        );
        assert_eq!(
            snapshot
                .pointer("/datapathBindingMonitor/status")
                .and_then(Value::as_str),
            Some("fail")
        );
    }

    #[test]
    fn passing_binding_postflight_does_not_manufacture_interface_recovery() {
        let report = json!({"status": "pass", "failedCount": 0});
        let monitor = ResidentDatapathBindingMonitor::new(&registry(), &report).unwrap();
        let mut snapshot = interface_snapshot();

        monitor.merge_snapshot(&mut snapshot);

        assert_eq!(snapshot["status"], "pass");
        assert_eq!(snapshot["reattachRequired"], false);
        assert_eq!(snapshot["reattachReady"], false);
        assert_eq!(snapshot["reattachReasons"], json!([]));
    }
}
