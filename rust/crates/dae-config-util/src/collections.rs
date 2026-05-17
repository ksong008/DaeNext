use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub fn clone_strings(input: Option<&[String]>) -> Vec<String> {
    input.map_or_else(Vec::new, <[String]>::to_vec)
}

pub fn a_range_u32(n: u32) -> Vec<u32> {
    (0..n).collect()
}

pub fn deduplicate_strings(input: Option<&[String]>) -> Option<Vec<String>> {
    let input = input?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(input.len());
    for value in input {
        if seen.insert(value.clone()) {
            out.push(value.clone());
        }
    }
    Some(out)
}

pub fn string_set(input: &[String]) -> BTreeSet<String> {
    input.iter().cloned().collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapKeysError;

impl fmt::Display for MapKeysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapKeys requires map[string]*")
    }
}

impl std::error::Error for MapKeysError {}

pub fn map_keys<T>(map: &BTreeMap<String, T>) -> Vec<String> {
    map.keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn collection_helpers_match_golden_fixture() {
        let fixture = dae_golden::load_json("config/utils/common.json").unwrap();
        let collections = &fixture["collections"];

        assert_clone_strings(&collections["clone_strings"]);
        assert_a_range(&collections["a_range_u32"]);
        assert_deduplicate(&collections["deduplicate"]);
        assert_string_set(&collections["string_set"]);
        assert_map_keys(&fixture["map_keys"]);
    }

    fn assert_clone_strings(cases: &Value) {
        for case in cases.as_array().unwrap() {
            let input = string_vec_opt(&case["input"]);
            let got = clone_strings(input.as_deref());
            assert_eq!(got, string_vec(&case["want"]));
        }
    }

    fn assert_a_range(cases: &Value) {
        for case in cases.as_array().unwrap() {
            let n = case["n"].as_u64().unwrap() as u32;
            let want: Vec<_> = case["want"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(a_range_u32(n), want);
        }
    }

    fn assert_deduplicate(cases: &Value) {
        for case in cases.as_array().unwrap() {
            let input = string_vec_opt(&case["input"]);
            let got = deduplicate_strings(input.as_deref());
            let want = string_vec_opt(&case["want"]);
            assert_eq!(got, want);
        }
    }

    fn assert_string_set(case: &Value) {
        let input = string_vec(&case["input"]);
        let got: Vec<_> = string_set(&input).into_iter().collect();
        assert_eq!(got, string_vec(&case["keys"]));
    }

    fn assert_map_keys(cases: &Value) {
        for case in cases.as_array().unwrap() {
            match case["name"].as_str().unwrap() {
                "string-map" => {
                    let map = BTreeMap::from([("a".to_owned(), 1), ("b".to_owned(), 2)]);
                    assert_eq!(map_keys(&map), string_vec(&case["keys_sorted"]));
                }
                "non-map" | "non-string-key" => {
                    assert_eq!(MapKeysError.to_string(), case["error"].as_str().unwrap());
                }
                other => panic!("unhandled MapKeys fixture case {other}"),
            }
        }
    }

    fn string_vec(value: &Value) -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    }

    fn string_vec_opt(value: &Value) -> Option<Vec<String>> {
        if value.is_null() {
            return None;
        }
        Some(string_vec(value))
    }
}
