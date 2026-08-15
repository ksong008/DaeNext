use super::*;

pub(super) fn fixture_config() -> Config {
    Config {
        global: Default::default(),
        subscription: Vec::new(),
        node: Vec::new(),
        group: Vec::new(),
        routing: Default::default(),
        dns: Default::default(),
    }
}

pub(super) fn candidate_occurrences(rows: &[Value], node_tag: &str) -> usize {
    rows.iter()
        .filter(|row| {
            row["candidates"].as_array().is_some_and(|candidates| {
                candidates
                    .iter()
                    .any(|candidate| candidate["node_tag"].as_str() == Some(node_tag))
            })
        })
        .count()
}

pub(super) fn row<'a>(rows: &'a [Value], shape_id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row["shapeId"].as_str() == Some(shape_id))
        .unwrap_or_else(|| panic!("missing expanded source matrix row {shape_id}"))
}

pub(super) fn assert_no_candidates(row: &Value) {
    assert_eq!(row["candidate_count"], 0);
    assert_eq!(row["admitted_count"], 0);
    assert_eq!(row["blocked_count"], 0);
    assert!(row["candidates"].as_array().is_some_and(Vec::is_empty));
}

pub(super) fn assert_no_classified_candidates(row: &Value) {
    assert_eq!(row["classifiedCandidateCount"], 0);
    assert_eq!(row["classifiedCurrentConfigStatus"], "not-present");
    assert!(
        row["classifiedCandidates"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
}
