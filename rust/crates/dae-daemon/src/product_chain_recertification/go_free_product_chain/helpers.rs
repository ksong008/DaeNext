use super::*;
pub(crate) fn read_text(path: &std::path::Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

pub(crate) fn makefile_rule(text: &str, target: &str) -> String {
    let prefix = format!("{target}:");
    text.lines()
        .filter(|line| !line.contains(":="))
        .find(|line| line.trim_start().starts_with(&prefix))
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

pub(crate) fn upsert_go_free_product_chain_gate(report: &mut Value, gate: Value) {
    let Some(report_object) = report.as_object_mut() else {
        return;
    };
    let ready = gate["go_free_product_chain_ready"]
        .as_bool()
        .unwrap_or(false);
    let admission_ready = gate["go_free_product_chain_admission_ready"]
        .as_bool()
        .unwrap_or(false);
    report_object.insert("go_free_product_chain_ready".to_owned(), json!(ready));
    report_object.insert(
        "go_free_product_chain_admission_ready".to_owned(),
        json!(admission_ready),
    );
    report_object.insert("go_free_product_chain_gate".to_owned(), gate.clone());
    report_object.insert("c10_go_free_product_chain".to_owned(), gate);
    if let Some(typed_report) = report_object
        .get_mut("typed_report")
        .and_then(Value::as_object_mut)
    {
        typed_report.insert("go_free_product_chain_ready".to_owned(), json!(ready));
        typed_report.insert(
            "go_free_product_chain_admission_ready".to_owned(),
            json!(admission_ready),
        );
    }
}
