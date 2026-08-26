use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionRefreshOutcome {
    pub fetched: bool,
    pub runtime_input_changed: bool,
}

impl SubscriptionRefreshOutcome {
    pub fn from_report(report: &Value) -> Self {
        Self {
            fetched: report
                .get("fetched")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            runtime_input_changed: report
                .get("runtimeInputChanged")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    }

    pub fn requests_runtime_apply(self) -> bool {
        self.fetched && self.runtime_input_changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_fetched_runtime_change_requests_apply() {
        for (report, expected) in [
            (
                json!({"fetched": false, "runtimeInputChanged": false}),
                false,
            ),
            (
                json!({"fetched": false, "runtimeInputChanged": true}),
                false,
            ),
            (
                json!({"fetched": true, "runtimeInputChanged": false}),
                false,
            ),
            (json!({"fetched": true, "runtimeInputChanged": true}), true),
            (json!({}), false),
        ] {
            assert_eq!(
                SubscriptionRefreshOutcome::from_report(&report).requests_runtime_apply(),
                expected,
                "{report}"
            );
        }
    }
}
