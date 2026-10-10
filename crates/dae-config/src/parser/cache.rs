use super::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
type Entry = (String, Arc<[Section]>);
static CACHE: OnceLock<Mutex<VecDeque<Entry>>> = OnceLock::new();

/// Bounded reuse for rendering and repeated control-plane reads of exact text.
/// Invalid input still follows the full parser and is never cached.
pub fn parse_config_cached(input: &str) -> Result<Arc<[Section]>, ConfigError> {
    if input.len() > 256 * 1024 {
        return parse_config(input).map(Arc::from);
    }
    let cache = CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
    {
        let mut entries = cache.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(index) = entries.iter().position(|(text, _)| text == input) {
            let entry = entries.remove(index).expect("parse cache index");
            let result = Arc::clone(&entry.1);
            entries.push_back(entry);
            return Ok(result);
        }
    }
    let parsed: Arc<[Section]> = parse_config(input)?.into();
    let mut entries = cache.lock().unwrap_or_else(|error| error.into_inner());
    // At most 16 x 256 KiB source text plus its parser-bounded AST.
    if entries.len() >= 16 {
        entries.pop_front();
    }
    entries.push_back((input.to_owned(), Arc::clone(&parsed)));
    Ok(parsed)
}
