use super::*;
use sha2::Sha256;

pub(in crate::daed_product) const RUNTIME_GROUP_SELECTION_EVENT: &str = "runtime.group-selection";

#[derive(Default)]
pub(super) struct RuntimeGroupSelectionEventTracker {
    previous: Option<BTreeMap<String, Value>>,
}

impl RuntimeGroupSelectionEventTracker {
    pub(super) fn observe_app(&mut self, app: &AppState) -> Option<Value> {
        self.observe(app.runtime.group_selector_snapshot_map())
    }

    fn observe(&mut self, snapshot: BTreeMap<String, Value>) -> Option<Value> {
        if self.previous.as_ref() == Some(&snapshot) {
            return None;
        }
        let generation = group_selection_generation(&snapshot);
        self.previous = Some(snapshot);
        Some(json!({"generation": generation}))
    }
}

pub(in crate::daed_product) fn initial_group_selection_event(app: &AppState) -> Value {
    let snapshot = app.runtime.group_selector_snapshot_map();
    json!({"generation": group_selection_generation(&snapshot)})
}

fn group_selection_generation(snapshot: &BTreeMap<String, Value>) -> String {
    let mut hasher = Sha256::default();
    for (group_name, selection) in snapshot {
        update_length_prefixed(&mut hasher, group_name.as_bytes());
        let selection = selection.to_string();
        update_length_prefixed(&mut hasher, selection.as_bytes());
    }
    format!("sha256:{}", hex_encode(&sha2::Digest::finalize(hasher)))
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    sha2::Digest::update(hasher, (value.len() as u64).to_be_bytes());
    sha2::Digest::update(hasher, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_selection_event_is_initially_emitted_and_then_only_on_change() {
        let mut tracker = RuntimeGroupSelectionEventTracker::default();
        let initial = BTreeMap::from([(
            "proxy".to_owned(),
            json!({
                "selectedNodeTag": "node-a",
                "selectedLatencyMs": 40,
                "aliveCandidateCount": 2,
            }),
        )]);

        let first = tracker.observe(initial.clone()).unwrap();
        assert!(
            first["generation"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        assert_eq!(first.as_object().map(serde_json::Map::len), Some(1));
        assert!(tracker.observe(initial.clone()).is_none());

        let changed = BTreeMap::from([(
            "proxy".to_owned(),
            json!({
                "selectedNodeTag": "node-b",
                "selectedLatencyMs": 20,
                "aliveCandidateCount": 2,
            }),
        )]);
        let second = tracker.observe(changed).unwrap();
        assert_ne!(second["generation"], first["generation"]);
        assert!(tracker.observe(initial).is_some());
    }

    #[test]
    fn group_selection_generation_is_stable_for_group_map_order() {
        let first = BTreeMap::from([
            ("alpha".to_owned(), json!({"selectedNodeTag": "node-a"})),
            ("beta".to_owned(), json!({"selectedNodeTag": "node-b"})),
        ]);
        let mut second = BTreeMap::new();
        second.insert("beta".to_owned(), json!({"selectedNodeTag": "node-b"}));
        second.insert("alpha".to_owned(), json!({"selectedNodeTag": "node-a"}));

        assert_eq!(
            group_selection_generation(&first),
            group_selection_generation(&second)
        );
    }
}
