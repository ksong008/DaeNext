use regex::Regex;

use crate::RoutingError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainKey {
    Full,
    Keyword,
    Suffix,
    Regex,
}

impl TryFrom<&str> for DomainKey {
    type Error = RoutingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "full" => Ok(Self::Full),
            "keyword" => Ok(Self::Keyword),
            "suffix" => Ok(Self::Suffix),
            "regex" => Ok(Self::Regex),
            _ => Err(RoutingError::InvalidDomainKey(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DomainMatcher {
    bit_length: usize,
    sets: Vec<DomainSet>,
}

#[derive(Clone, Debug)]
struct DomainSet {
    bit_index: usize,
    key: DomainKey,
    patterns: Vec<String>,
    regex: Vec<Regex>,
}

impl DomainMatcher {
    pub fn new(bit_length: usize) -> Self {
        Self {
            bit_length,
            sets: Vec::new(),
        }
    }

    pub fn add_set(
        &mut self,
        bit_index: usize,
        patterns: impl IntoIterator<Item = impl Into<String>>,
        key: DomainKey,
    ) -> Result<(), RoutingError> {
        let raw_patterns: Vec<String> = patterns.into_iter().map(Into::into).collect();
        let regex = if key == DomainKey::Regex {
            raw_patterns
                .iter()
                .map(|pattern| {
                    Regex::new(pattern).map_err(|_| RoutingError::InvalidRegex(pattern.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        let patterns = normalize_patterns(raw_patterns, key);
        self.sets.push(DomainSet {
            bit_index,
            key,
            patterns,
            regex,
        });
        Ok(())
    }

    pub fn match_domain_bitmap(&self, domain: &str) -> Vec<u32> {
        let mut bitmap = vec![0; self.bitmap_words()];
        self.fill_bitmap(domain, &mut bitmap);
        bitmap
    }

    pub fn match_domain_bitmap_into(&self, domain: &str, bitmap: &mut [u32]) -> Vec<u32> {
        let words = self.bitmap_words();
        if bitmap.len() < words {
            return self.match_domain_bitmap(domain);
        }
        let bitmap = &mut bitmap[..words];
        bitmap.fill(0);
        self.fill_bitmap(domain, bitmap);
        bitmap.to_vec()
    }

    fn bitmap_words(&self) -> usize {
        self.bit_length.div_ceil(32)
    }

    fn fill_bitmap(&self, domain: &str, bitmap: &mut [u32]) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        for set in &self.sets {
            if set.bit_index >= self.bit_length || bitmap_has(bitmap, set.bit_index) {
                continue;
            }
            if set.matches(&domain) {
                bitmap[set.bit_index / 32] |= 1 << (set.bit_index % 32);
            }
        }
    }
}

impl DomainSet {
    fn matches(&self, domain: &str) -> bool {
        match self.key {
            DomainKey::Full => self
                .patterns
                .iter()
                .any(|pattern| domain.eq_ignore_ascii_case(pattern.trim_end_matches('.'))),
            DomainKey::Keyword => self.patterns.iter().any(|pattern| domain.contains(pattern)),
            DomainKey::Suffix => self
                .patterns
                .iter()
                .any(|pattern| suffix_matches(domain, pattern)),
            DomainKey::Regex => self.regex.iter().any(|regex| regex.is_match(domain)),
        }
    }
}

fn suffix_matches(domain: &str, pattern: &str) -> bool {
    if let Some(stripped) = pattern.strip_prefix('.') {
        has_label_suffix(domain, stripped)
    } else {
        domain == pattern || has_label_suffix(domain, pattern)
    }
}

fn has_label_suffix(domain: &str, suffix: &str) -> bool {
    domain.len() > suffix.len()
        && domain.ends_with(suffix)
        && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
}

fn normalize_patterns(patterns: Vec<String>, key: DomainKey) -> Vec<String> {
    match key {
        DomainKey::Full => patterns
            .into_iter()
            .map(|pattern| pattern.trim_end_matches('.').to_owned())
            .collect(),
        DomainKey::Suffix => patterns
            .into_iter()
            .map(|pattern| pattern.trim_end_matches('.').to_ascii_lowercase())
            .collect(),
        DomainKey::Keyword | DomainKey::Regex => patterns,
    }
}

fn bitmap_has(bitmap: &[u32], bit: usize) -> bool {
    bitmap
        .get(bit / 32)
        .map(|word| ((word >> (bit % 32)) & 1) != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matcher_bitmap_matches_golden_fixture() {
        let fixture = dae_golden::load_json("routing/domain_matcher/basic_bitmap.json").unwrap();
        let bit_length = fixture["bit_length"].as_u64().unwrap() as usize;
        let mut matcher = DomainMatcher::new(bit_length);

        for set in fixture["sets"].as_array().unwrap() {
            let bit = set["bit"].as_u64().unwrap() as usize;
            let key = DomainKey::try_from(set["key"].as_str().unwrap()).unwrap();
            let patterns = set["patterns"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned());
            matcher.add_set(bit, patterns, key).unwrap();
        }

        for case in fixture["queries"].as_array().unwrap() {
            let domain = case["domain"].as_str().unwrap();
            let want = u32_array(&case["bitmap"]);
            let allocated = matcher.match_domain_bitmap(domain);
            let mut reuse = vec![0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc];
            let reused = matcher.match_domain_bitmap_into(domain, &mut reuse);

            assert_eq!(allocated, want, "{domain}");
            assert_eq!(reused, want, "{domain}");
            assert_eq!(
                allocated == reused,
                case["reuse_same_bits"].as_bool().unwrap(),
                "{domain}"
            );
        }
    }

    fn u32_array(value: &serde_json::Value) -> Vec<u32> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u32)
            .collect()
    }
}
