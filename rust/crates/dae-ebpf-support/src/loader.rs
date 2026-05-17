#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinnedMapAction {
    DeleteAndRetry { map_name: String },
    ReturnError,
}

pub fn pinned_map_action(error: &str) -> PinnedMapAction {
    let Some(after_prefix) = error.split_once("use pinned map ").map(|(_, after)| after) else {
        return PinnedMapAction::ReturnError;
    };
    let map_name = after_prefix
        .split_once(':')
        .map(|(name, _)| name)
        .unwrap_or(after_prefix)
        .trim();
    if map_name.is_empty() {
        return PinnedMapAction::ReturnError;
    }
    PinnedMapAction::DeleteAndRetry {
        map_name: map_name.to_owned(),
    }
}
