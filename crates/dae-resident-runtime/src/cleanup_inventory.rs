use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct ResidentRuntimeCleanupInventory {
    reports: Arc<Mutex<BTreeMap<&'static str, Value>>>,
}

pub struct ResidentRuntimeCleanupReporter {
    owner: &'static str,
    reports: Arc<Mutex<BTreeMap<&'static str, Value>>>,
    finished: bool,
}

impl ResidentRuntimeCleanupInventory {
    pub fn reporter(&self, owner: &'static str) -> ResidentRuntimeCleanupReporter {
        if let Ok(mut reports) = self.reports.lock() {
            reports.insert(owner, json!({"status": "pending"}));
        }
        ResidentRuntimeCleanupReporter {
            owner,
            reports: Arc::clone(&self.reports),
            finished: false,
        }
    }

    pub fn snapshot(&self) -> Value {
        let reports = self
            .reports
            .lock()
            .map(|reports| reports.clone())
            .unwrap_or_else(|_| {
                BTreeMap::from([(
                    "cleanup-inventory",
                    json!({"status": "fail", "error": "cleanup inventory lock poisoned"}),
                )])
            });
        let passed = reports
            .values()
            .all(|report| report["status"].as_str() == Some("pass"));
        let forced = reports
            .values()
            .any(|report| report["completionMode"].as_str() == Some("forced-bounded"));
        let graceful = passed
            && reports
                .values()
                .all(|report| report["graceful"].as_bool().unwrap_or(true));
        let completion_mode = if !passed {
            "incomplete"
        } else if forced {
            "forced-bounded"
        } else if graceful {
            "graceful"
        } else {
            "completed-degraded"
        };
        json!({
            "status": if passed { "pass" } else { "fail" },
            "safetyStatus": if passed { "pass" } else { "fail" },
            "graceful": graceful,
            "completionMode": completion_mode,
            "owners": reports,
        })
    }
}

impl ResidentRuntimeCleanupReporter {
    pub fn finish(mut self, report: Value) {
        if let Ok(mut reports) = self.reports.lock() {
            reports.insert(self.owner, report);
        }
        self.finished = true;
    }
}

impl Drop for ResidentRuntimeCleanupReporter {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut reports) = self.reports.lock() {
            reports.insert(
                self.owner,
                json!({
                    "status": "fail",
                    "error": "runtime owner exited before publishing cleanup report",
                }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_and_dropped_reporters_fail_the_inventory() {
        let inventory = ResidentRuntimeCleanupInventory::default();
        let reporter = inventory.reporter("udp");
        assert_eq!(inventory.snapshot()["status"], "fail");
        drop(reporter);
        assert_eq!(inventory.snapshot()["status"], "fail");
        assert_eq!(
            inventory.snapshot()["owners"]["udp"]["error"],
            "runtime owner exited before publishing cleanup report"
        );
    }

    #[test]
    fn completed_reporter_publishes_a_passing_owner_report() {
        let inventory = ResidentRuntimeCleanupInventory::default();
        inventory
            .reporter("udp")
            .finish(json!({"status": "pass", "sessions": 0}));
        assert_eq!(inventory.snapshot()["status"], "pass");
    }

    #[test]
    fn forced_owner_cleanup_is_safe_but_not_graceful() {
        let inventory = ResidentRuntimeCleanupInventory::default();
        inventory.reporter("udp").finish(json!({
            "status": "pass",
            "safetyStatus": "pass",
            "graceful": false,
            "completionMode": "forced-bounded",
        }));

        let snapshot = inventory.snapshot();
        assert_eq!(snapshot["status"], "pass");
        assert_eq!(snapshot["safetyStatus"], "pass");
        assert_eq!(snapshot["graceful"], false);
        assert_eq!(snapshot["completionMode"], "forced-bounded");
    }
}
