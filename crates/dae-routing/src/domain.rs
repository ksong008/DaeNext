use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::{Arc, Weak};

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};

use crate::RoutingError;

const DOMAIN_SET_INDEX_MIN_PATTERNS: usize = 32;

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
    data: SharedDomainSet,
}

#[derive(Clone, Debug)]
pub struct SharedDomainSet {
    inner: Arc<SharedDomainSetInner>,
}

#[derive(Clone, Debug)]
pub struct WeakSharedDomainSet {
    inner: Weak<SharedDomainSetInner>,
}

#[derive(Debug)]
struct SharedDomainSetInner {
    key: DomainKey,
    patterns: Arc<[String]>,
    regex: Arc<[Regex]>,
    index: Option<SharedDomainSetIndex>,
}

#[derive(Debug)]
enum SharedDomainSetIndex {
    Full(HashSet<String>),
    Keyword(AhoCorasick),
    Suffix(SuffixDomainSetIndex),
    Regex(RegexSet),
}

#[derive(Debug)]
struct SuffixDomainSetIndex {
    exact_or_subdomain: HashSet<String>,
    subdomain_only: HashSet<String>,
}

impl SharedDomainSet {
    pub fn new(
        patterns: impl IntoIterator<Item = impl Into<String>>,
        key: DomainKey,
    ) -> Result<Self, RoutingError> {
        Self::from_vec(patterns.into_iter().map(Into::into).collect(), key)
    }

    pub fn from_vec(raw_patterns: Vec<String>, key: DomainKey) -> Result<Self, RoutingError> {
        let patterns = normalize_patterns(raw_patterns, key);
        let regex = if key == DomainKey::Regex {
            regex_vec(&patterns)?
        } else {
            Vec::new()
        };
        let index = SharedDomainSetIndex::new(key, &patterns)?;
        Ok(Self {
            inner: Arc::new(SharedDomainSetInner {
                key,
                patterns: Arc::from(patterns),
                regex: Arc::from(regex),
                index,
            }),
        })
    }

    pub fn key(&self) -> DomainKey {
        self.inner.key
    }

    pub fn patterns(&self) -> &[String] {
        &self.inner.patterns
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub fn downgrade(&self) -> WeakSharedDomainSet {
        WeakSharedDomainSet {
            inner: Arc::downgrade(&self.inner),
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = normalize_query_domain(domain);
        if let Some(index) = self.inner.index.as_ref() {
            return index.matches(domain.as_ref());
        }
        linear_domain_set_matches(
            self.key(),
            domain.as_ref(),
            self.patterns(),
            self.inner.regex.as_ref(),
        )
    }
}

impl WeakSharedDomainSet {
    pub fn upgrade(&self) -> Option<SharedDomainSet> {
        self.inner.upgrade().map(|inner| SharedDomainSet { inner })
    }
}

impl PartialEq for SharedDomainSet {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key() && self.patterns() == other.patterns()
    }
}

impl Eq for SharedDomainSet {}

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
        self.add_shared_set(bit_index, SharedDomainSet::new(patterns, key)?);
        Ok(())
    }

    pub fn add_shared_set(&mut self, bit_index: usize, data: SharedDomainSet) {
        self.sets.push(DomainSet { bit_index, data });
    }

    pub fn match_domain_bitmap(&self, domain: &str) -> Vec<u32> {
        let mut bitmap = vec![0; self.bitmap_words()];
        self.fill_bitmap(domain, &mut bitmap);
        bitmap
    }

    pub fn match_domain_bitmap_into(&self, domain: &str, bitmap: &mut [u32]) -> Vec<u32> {
        match self.fill_domain_bitmap(domain, bitmap) {
            Ok(words) => bitmap[..words].to_vec(),
            Err(_) => self.match_domain_bitmap(domain),
        }
    }

    pub fn fill_domain_bitmap(
        &self,
        domain: &str,
        bitmap: &mut [u32],
    ) -> Result<usize, RoutingError> {
        let words = self.bitmap_words();
        if bitmap.len() < words {
            return Err(RoutingError::InvalidFixture(format!(
                "domain bitmap buffer too short: got {}, want {words}",
                bitmap.len()
            )));
        }
        let bitmap = &mut bitmap[..words];
        bitmap.fill(0);
        self.fill_bitmap(domain, bitmap);
        Ok(words)
    }

    pub const fn bit_length(&self) -> usize {
        self.bit_length
    }

    pub fn bitmap_words(&self) -> usize {
        self.bit_length.div_ceil(32)
    }

    fn fill_bitmap(&self, domain: &str, bitmap: &mut [u32]) {
        let domain = normalize_query_domain(domain);
        for set in &self.sets {
            if set.bit_index >= self.bit_length || bitmap_has(bitmap, set.bit_index) {
                continue;
            }
            if set.matches(domain.as_ref()) {
                bitmap[set.bit_index / 32] |= 1 << (set.bit_index % 32);
            }
        }
    }
}

impl DomainSet {
    fn matches(&self, domain: &str) -> bool {
        self.data.matches(domain)
    }
}

impl SharedDomainSetIndex {
    fn new(key: DomainKey, patterns: &[String]) -> Result<Option<Self>, RoutingError> {
        if patterns.len() < DOMAIN_SET_INDEX_MIN_PATTERNS {
            return Ok(None);
        }
        match key {
            DomainKey::Full => Ok(Some(Self::Full(
                patterns
                    .iter()
                    .map(|pattern| pattern.trim_end_matches('.').to_ascii_lowercase())
                    .collect(),
            ))),
            DomainKey::Keyword => {
                if patterns.iter().any(String::is_empty) {
                    return Ok(None);
                }
                AhoCorasick::new(patterns.iter().map(String::as_str))
                    .map(Self::Keyword)
                    .map(Some)
                    .map_err(|err| {
                        RoutingError::InvalidFixture(format!(
                            "invalid keyword domain set index: {err}"
                        ))
                    })
            }
            DomainKey::Suffix => Ok(Some(Self::Suffix(SuffixDomainSetIndex::new(patterns)))),
            DomainKey::Regex => Ok(Some(Self::Regex(regex_set(patterns)?))),
        }
    }

    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Full(index) => index.contains(domain),
            Self::Keyword(index) => index.is_match(domain),
            Self::Suffix(index) => index.matches(domain),
            Self::Regex(regex) => regex.is_match(domain),
        }
    }
}

impl SuffixDomainSetIndex {
    fn new(patterns: &[String]) -> Self {
        let mut exact_or_subdomain = HashSet::with_capacity(patterns.len());
        let mut subdomain_only = HashSet::new();
        for pattern in patterns {
            if let Some(stripped) = pattern.strip_prefix('.') {
                subdomain_only.insert(stripped.to_owned());
            } else {
                exact_or_subdomain.insert(pattern.to_owned());
            }
        }
        Self {
            exact_or_subdomain,
            subdomain_only,
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let mut candidate = domain;
        let mut parent_suffix = false;
        loop {
            if self.exact_or_subdomain.contains(candidate)
                || (parent_suffix && self.subdomain_only.contains(candidate))
            {
                return true;
            }
            let Some((_, next)) = candidate.split_once('.') else {
                return false;
            };
            candidate = next;
            parent_suffix = true;
        }
    }
}

fn regex_set(patterns: &[String]) -> Result<RegexSet, RoutingError> {
    RegexSet::new(patterns).map_err(|_| {
        patterns
            .iter()
            .find(|pattern| Regex::new(pattern).is_err())
            .cloned()
            .map(RoutingError::InvalidRegex)
            .unwrap_or_else(|| RoutingError::InvalidFixture("invalid regex set".to_owned()))
    })
}

fn regex_vec(patterns: &[String]) -> Result<Vec<Regex>, RoutingError> {
    patterns
        .iter()
        .map(|pattern| Regex::new(pattern).map_err(|_| RoutingError::InvalidRegex(pattern.clone())))
        .collect()
}

fn linear_domain_set_matches(
    key: DomainKey,
    domain: &str,
    patterns: &[String],
    regex: &[Regex],
) -> bool {
    match key {
        DomainKey::Full => patterns
            .iter()
            .any(|pattern| domain.eq_ignore_ascii_case(pattern.trim_end_matches('.'))),
        DomainKey::Keyword => patterns.iter().any(|pattern| domain.contains(pattern)),
        DomainKey::Suffix => patterns
            .iter()
            .any(|pattern| suffix_matches(domain, pattern)),
        DomainKey::Regex => regex.iter().any(|regex| regex.is_match(domain)),
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
        DomainKey::Full | DomainKey::Keyword => patterns
            .into_iter()
            .map(|pattern| pattern.trim_end_matches('.').to_ascii_lowercase())
            .collect(),
        DomainKey::Suffix => patterns
            .into_iter()
            .map(|pattern| pattern.trim_end_matches('.').to_ascii_lowercase())
            .collect(),
        DomainKey::Regex => patterns,
    }
}

fn normalize_query_domain(domain: &str) -> Cow<'_, str> {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.bytes().any(|ch| ch.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else if trimmed.len() == domain.len() {
        Cow::Borrowed(domain)
    } else {
        Cow::Borrowed(trimmed)
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
            let mut native = vec![0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc];
            let words = matcher.fill_domain_bitmap(domain, &mut native).unwrap();

            assert_eq!(allocated, want, "{domain}");
            assert_eq!(reused, want, "{domain}");
            assert_eq!(&native[..words], want.as_slice(), "{domain}");
            assert_eq!(
                allocated == reused,
                case["reuse_same_bits"].as_bool().unwrap(),
                "{domain}"
            );
        }

        let mut too_short = [0_u32; 1];
        let err = matcher
            .fill_domain_bitmap("example.com", &mut too_short)
            .unwrap_err();
        assert!(err.to_string().contains("domain bitmap buffer too short"));
    }

    #[test]
    fn domain_set_indexes_preserve_full_and_suffix_semantics() {
        let full = SharedDomainSet::new(["Example.COM."], DomainKey::Full).unwrap();
        let mut matcher = DomainMatcher::new(1);
        matcher.add_shared_set(0, full.clone());
        assert_eq!(matcher.match_domain_bitmap("EXAMPLE.COM."), vec![1]);

        assert!(full.matches("example.com"));
        assert!(!full.matches("www.example.com"));

        let suffix = SharedDomainSet::new(["example.com"], DomainKey::Suffix).unwrap();
        assert!(suffix.matches("example.com"));
        assert!(suffix.matches("www.example.com"));

        let subdomain_only =
            SharedDomainSet::new([".child.example.com"], DomainKey::Suffix).unwrap();
        assert!(!subdomain_only.matches("child.example.com"));
        assert!(subdomain_only.matches("www.child.example.com"));
    }

    #[test]
    fn domain_matcher_normalizes_queries_and_preserves_regex_semantics() {
        let mut matcher = DomainMatcher::new(4);
        matcher
            .add_set(0, ["example.com"], DomainKey::Suffix)
            .unwrap();
        matcher
            .add_set(1, [".child.example.com"], DomainKey::Suffix)
            .unwrap();
        matcher
            .add_set(2, ["streaming"], DomainKey::Keyword)
            .unwrap();
        matcher
            .add_set(3, [r"^api[0-9]+\.service\.example\.com$"], DomainKey::Regex)
            .unwrap();

        assert_eq!(matcher.match_domain_bitmap("WWW.EXAMPLE.COM."), vec![0x1]);
        assert_eq!(matcher.match_domain_bitmap("child.example.com"), vec![0x1]);
        assert_eq!(
            matcher.match_domain_bitmap("edge.child.example.com."),
            vec![0x3]
        );
        assert_eq!(
            matcher.match_domain_bitmap("cdn.streaming.example.com"),
            vec![0x5]
        );
        assert_eq!(
            matcher.match_domain_bitmap("api42.service.example.com."),
            vec![0x9]
        );

        let regex = SharedDomainSet::new([r"^api[0-9]+\.service\.example\.com$"], DomainKey::Regex)
            .unwrap();
        assert_eq!(regex.inner.regex.len(), 1);
        assert!(regex.matches("api42.service.example.com"));
        assert!(!regex.matches("www.service.example.com"));
        assert!(SharedDomainSet::new(["("], DomainKey::Regex).is_err());
    }

    #[test]
    fn domain_set_keyword_index_preserves_contains_semantics() {
        let mut patterns = (0..DOMAIN_SET_INDEX_MIN_PATTERNS)
            .map(|index| format!("keyword-{index}"))
            .collect::<Vec<_>>();
        patterns.push("video".to_owned());
        let keyword = SharedDomainSet::from_vec(patterns, DomainKey::Keyword).unwrap();
        assert!(matches!(
            keyword.inner.index,
            Some(SharedDomainSetIndex::Keyword(_))
        ));
        assert!(keyword.matches("cdn.video.example"));
        assert!(!keyword.matches("cdn.audio.example"));

        let mut case_insensitive_patterns = (0..DOMAIN_SET_INDEX_MIN_PATTERNS)
            .map(|index| format!("case-keyword-{index}"))
            .collect::<Vec<_>>();
        case_insensitive_patterns.push("Video".to_owned());
        let case_insensitive =
            SharedDomainSet::from_vec(case_insensitive_patterns, DomainKey::Keyword).unwrap();
        assert!(case_insensitive.matches("cdn.video.example"));
        assert!(case_insensitive.matches("cdn.Video.example"));

        let mut empty_patterns = (0..DOMAIN_SET_INDEX_MIN_PATTERNS)
            .map(|index| format!("empty-keyword-{index}"))
            .collect::<Vec<_>>();
        empty_patterns.push(String::new());
        let empty_keyword = SharedDomainSet::from_vec(empty_patterns, DomainKey::Keyword).unwrap();
        assert!(empty_keyword.inner.index.is_none());
        assert!(empty_keyword.matches("anything.example"));
    }

    fn u32_array(value: &serde_json::Value) -> Vec<u32> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|value| u32::try_from(value.as_u64().unwrap()).unwrap())
            .collect()
    }
}
