use std::fmt;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DnsCacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsCacheKey {
    pub fn new(qname: impl AsRef<str>, qtype: u16, qclass: u16) -> Self {
        Self {
            qname: canonical_name(qname.as_ref()).to_ascii_lowercase(),
            qtype,
            qclass,
        }
    }
}

impl fmt::Display for DnsCacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}|{}|{}", self.qname, self.qtype, self.qclass)
    }
}

pub fn canonical_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.ends_with('.') {
        trimmed.to_owned()
    } else {
        format!("{trimmed}.")
    }
}

pub fn parse_dns_cache_key(raw: &str) -> Option<DnsCacheKey> {
    if let Some(last_sep) = raw.rfind('|') {
        let before_class = &raw[..last_sep];
        let class_raw = &raw[last_sep + 1..];
        if let Some(prev_sep) = before_class.rfind('|') {
            let qtype = before_class[prev_sep + 1..].parse::<u16>().ok()?;
            let qclass = class_raw.parse::<u16>().ok()?;
            return Some(DnsCacheKey::new(&before_class[..prev_sep], qtype, qclass));
        }
    }

    let last_dot = raw.rfind('.')?;
    if last_dot == raw.len() - 1 {
        return None;
    }
    let qtype = raw[last_dot + 1..].parse::<u16>().ok()?;
    Some(DnsCacheKey::new(&raw[..last_dot], qtype, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_cache_key_matches_golden_fixture() {
        let fixture = dae_golden::load_json("dns/cache_key/basic.json").unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        for case in cases {
            let key = DnsCacheKey::new(
                case["qname"].as_str().unwrap(),
                case["qtype"].as_u64().unwrap() as u16,
                case["qclass"].as_u64().unwrap() as u16,
            );
            assert_eq!(key.qname, case["key"]["qname"].as_str().unwrap());
            assert_eq!(key.qtype, case["key"]["qtype"].as_u64().unwrap() as u16);
            assert_eq!(key.qclass, case["key"]["qclass"].as_u64().unwrap() as u16);
            assert_eq!(key.to_string(), case["key"]["string"].as_str().unwrap());
        }

        let inet = &cases[0];
        assert_eq!(
            parse_dns_cache_key(inet["legacy"].as_str().unwrap()).unwrap(),
            DnsCacheKey::new("example.com.", 1, 1)
        );
        assert_eq!(
            parse_dns_cache_key(inet["structured"].as_str().unwrap()).unwrap(),
            DnsCacheKey::new("example.com.", 1, 1)
        );
    }
}
