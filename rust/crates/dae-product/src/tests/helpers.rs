use super::*;

pub(super) fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

pub(super) fn assert_string_vec(actual: &[&str], fixture: &Value) {
    let expected = fixture
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected.as_slice());
}

pub(super) fn assert_contains_text(values: &[&str], needle: &str) {
    assert!(
        values.iter().any(|value| value.contains(needle)),
        "expected one of {values:?} to contain {needle:?}"
    );
}
