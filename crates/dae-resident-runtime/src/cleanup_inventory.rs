use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct ResidentRuntimeCleanupInventory {
    reports: Arc<Mutex<BTreeMap<&'static str, Value>>>,
    concurrent: Arc<Mutex<BTreeMap<&'static str, ConcurrentCleanup>>>,
}

#[derive(Debug, Default)]
struct ConcurrentCleanup {
    active: usize,
    completed: u64,
    failed: u64,
}

pub struct ResidentConcurrentCleanupReporter {
    owner: &'static str,
    groups: Arc<Mutex<BTreeMap<&'static str, ConcurrentCleanup>>>,
    finished: bool,
}

pub struct ResidentRuntimeCleanupReporter {
    owner: &'static str,
    reports: Arc<Mutex<BTreeMap<&'static str, Value>>>,
    finished: bool,
}

impl ResidentRuntimeCleanupInventory {
    /// Aggregate concurrent resource owners without storing one entry per reload.
    pub fn concurrent_reporter(&self, owner: &'static str) -> ResidentConcurrentCleanupReporter {
        self.concurrent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(owner)
            .or_default()
            .active += 1;
        ResidentConcurrentCleanupReporter {
            owner,
            groups: Arc::clone(&self.concurrent),
            finished: false,
        }
    }
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
        let mut reports = self
            .reports
            .lock()
            .map(|reports| reports.clone())
            .unwrap_or_else(|_| {
                BTreeMap::from([(
                    "cleanup-inventory",
                    json!({"status": "fail", "error": "cleanup inventory lock poisoned"}),
                )])
            });
        for (owner, group) in self
            .concurrent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            reports.insert(owner, json!({
                "status": if group.active == 0 && group.failed == 0 { "pass" } else { "fail" },
                "active": group.active, "completedTotal": group.completed, "failedTotal": group.failed,
            }));
        }
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

impl ResidentConcurrentCleanupReporter {
    pub fn finish(mut self, report: &Value) {
        self.complete(report["status"].as_str() == Some("pass"));
    }

    fn complete(&mut self, passed: bool) {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let group = groups.entry(self.owner).or_default();
        group.active -= 1;
        group.completed += 1;
        group.failed += u64::from(!passed);
        self.finished = true;
    }
}

impl Drop for ResidentConcurrentCleanupReporter {
    fn drop(&mut self) {
        if !self.finished {
            self.complete(false);
        }
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
    fn concurrent_cleanup_preserves_pending_and_failure_evidence_without_per_generation_keys() {
        let inventory = ResidentRuntimeCleanupInventory::default();
        let first = inventory.concurrent_reporter("dns");
        let second = inventory.concurrent_reporter("dns");
        first.finish(&json!({"status":"pass"}));
        assert_eq!(inventory.snapshot()["owners"]["dns"]["active"], 1);
        assert_eq!(inventory.snapshot()["status"], "fail");
        drop(second);
        for _ in 0..32 {
            inventory
                .concurrent_reporter("dns")
                .finish(&json!({"status":"pass"}));
        }
        let report = inventory.snapshot();
        assert_eq!(report["owners"].as_object().unwrap().len(), 1);
        assert_eq!(report["owners"]["dns"]["active"], 0);
        assert_eq!(report["owners"]["dns"]["completedTotal"], 34);
        assert_eq!(report["owners"]["dns"]["failedTotal"], 1);
        assert_eq!(report["status"], "fail");
    }

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
