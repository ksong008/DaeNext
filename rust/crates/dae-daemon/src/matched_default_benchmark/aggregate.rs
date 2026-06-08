use super::*;
pub(super) fn aggregate(iterations: &[Value]) -> Value {
    let go_values = iterations
        .iter()
        .filter_map(|item| item["go"]["ready_elapsed_ns"].as_u64())
        .collect::<Vec<_>>();
    let rust_values = iterations
        .iter()
        .filter_map(|item| item["rust"]["ready_elapsed_ns"].as_u64())
        .collect::<Vec<_>>();
    json!({
        "iterations": iterations.len(),
        "go_ready_elapsed_ns": stats(&go_values),
        "rust_ready_elapsed_ns": stats(&rust_values),
        "rust_vs_go_ready_elapsed_ratio": ratio(avg(&rust_values), avg(&go_values)),
    })
}

pub(super) fn stats(values: &[u64]) -> Value {
    json!({
        "count": values.len(),
        "min": values.iter().min().copied(),
        "max": values.iter().max().copied(),
        "avg": avg(values),
    })
}

pub(super) fn avg(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let sum = values.iter().map(|value| *value as f64).sum::<f64>();
    Some(sum / values.len() as f64)
}

pub(super) fn ratio(numerator: Option<f64>, denominator: Option<f64>) -> Option<f64> {
    let denominator = denominator?;
    if denominator == 0.0 {
        return None;
    }
    Some(numerator? / denominator)
}
