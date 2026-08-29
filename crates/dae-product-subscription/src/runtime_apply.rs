use serde_json::{Value, json};

#[derive(Debug, Default)]
pub struct SubscriptionRuntimeApplyResult {
    pub requested: bool,
    pub applied: bool,
    pub report: Option<Value>,
    pub error: Option<String>,
}

impl SubscriptionRuntimeApplyResult {
    pub fn insert_into(self, value: &mut Value) {
        let Value::Object(map) = value else {
            return;
        };
        map.insert("runtimeApplyRequested".to_owned(), json!(self.requested));
        map.insert("runtimeReloaded".to_owned(), json!(self.applied));
        map.insert(
            "runtimeReload".to_owned(),
            self.report.unwrap_or(Value::Null),
        );
        map.insert("runtimeReloadError".to_owned(), json!(self.error));
    }
}
