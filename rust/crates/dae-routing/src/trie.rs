use std::collections::BTreeSet;

use crate::RoutingError;

#[derive(Clone, Debug)]
pub struct ValidChars {
    valid: [bool; 256],
}

impl ValidChars {
    pub fn new(chars: &[u8]) -> Self {
        let mut valid = [false; 256];
        for ch in chars {
            valid[*ch as usize] = true;
        }
        Self { valid }
    }

    pub fn is_valid_char(&self, ch: u8) -> bool {
        self.valid[ch as usize]
    }
}

#[derive(Clone, Debug)]
pub struct Trie {
    keys: Vec<String>,
    valid_chars: ValidChars,
}

impl Trie {
    pub fn new(
        keys: impl IntoIterator<Item = impl Into<String>>,
        valid_chars: ValidChars,
    ) -> Result<Self, RoutingError> {
        let mut dedup = BTreeSet::new();
        for key in keys {
            let key = key.into();
            if let Some(ch) = key.bytes().find(|ch| !valid_chars.is_valid_char(*ch)) {
                return Err(RoutingError::InvalidFixture(format!(
                    "trie key contains invalid char: {}",
                    ch as char
                )));
            }
            dedup.insert(key);
        }

        Ok(Self {
            keys: dedup.into_iter().collect(),
            valid_chars,
        })
    }

    pub fn has_prefix(&self, word: &str) -> bool {
        if word.bytes().any(|ch| !self.valid_chars.is_valid_char(ch)) {
            return false;
        }
        self.keys.iter().any(|key| word.starts_with(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversed_domain_prefix_matches_golden_fixture() {
        let fixture = dae_golden::load_json("routing/trie/reversed_domain_prefix.json").unwrap();
        let keys = fixture["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned());
        let trie = Trie::new(
            keys,
            ValidChars::new(b"0123456789abcdefghijklmnopqrstuvwxyz-.^_"),
        )
        .unwrap();

        for case in fixture["queries"].as_array().unwrap() {
            let query = case["query"].as_str().unwrap();
            assert_eq!(
                trie.has_prefix(query),
                case["hit"].as_bool().unwrap(),
                "{query}"
            );
        }
    }
}
