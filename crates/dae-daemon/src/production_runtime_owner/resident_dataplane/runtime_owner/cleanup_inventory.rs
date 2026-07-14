use super::*;

#[derive(Clone, Debug, Default)]
pub(super) struct ResidentRuntimeCleanupInventory {
    reports: Arc<Mutex<BTreeMap<&'static str, Value>>>,
}

pub(crate) struct ResidentRuntimeCleanupReporter {
    owner: &'static str,
    reports: Arc<Mutex<BTreeMap<&'static str, Value>>>,
    finished: bool,
}

impl ResidentRuntimeCleanupInventory {
    pub(super) fn reporter(&self, owner: &'static str) -> ResidentRuntimeCleanupReporter {
        if let Ok(mut reports) = self.reports.lock() {
            reports.insert(owner, json!({"status": "pending"}));
        }
        ResidentRuntimeCleanupReporter {
            owner,
            reports: Arc::clone(&self.reports),
            finished: false,
        }
    }

    pub(super) fn snapshot(&self) -> Value {
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
        json!({
            "status": if passed { "pass" } else { "fail" },
            "owners": reports,
        })
    }
}

impl ResidentRuntimeCleanupReporter {
    pub(crate) fn finish(mut self, report: Value) {
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
}
