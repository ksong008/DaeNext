use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DnsCacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsCacheKeyView<'a> {
    pub qname: &'a str,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsCacheKey {
    pub fn new(qname: impl AsRef<str>, qtype: u16, qclass: u16) -> Self {
        Self {
            qname: canonical_name_lowercase(qname.as_ref()),
            qtype,
            qclass,
        }
    }

    pub fn matches_view(&self, view: DnsCacheKeyView<'_>) -> bool {
        self.qtype == view.qtype
            && self.qclass == view.qclass
            && canonical_name_eq_ignore_ascii_case(&self.qname, view.qname)
    }
}

impl Hash for DnsCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_dns_cache_key_parts(&self.qname, self.qtype, self.qclass, state);
    }
}

impl Hash for DnsCacheKeyView<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_dns_cache_key_parts(self.qname, self.qtype, self.qclass, state);
    }
}

impl fmt::Display for DnsCacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}|{}|{}", self.qname, self.qtype, self.qclass)
    }
}

pub(crate) fn hash_dns_cache_key_parts<H: Hasher>(
    qname: &str,
    qtype: u16,
    qclass: u16,
    state: &mut H,
) {
    hash_canonical_name_into(qname, state);
    qtype.hash(state);
    qclass.hash(state);
}

pub(crate) fn hash_dns_cache_key_wire_parts<H: Hasher>(
    qname_wire: &[u8],
    qtype: u16,
    qclass: u16,
    state: &mut H,
) {
    hash_canonical_wire_name_into(qname_wire, state);
    qtype.hash(state);
    qclass.hash(state);
}

fn hash_canonical_name_into<H: Hasher>(name: &str, state: &mut H) {
    let trimmed = name.trim();
    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() {
        state.write_u8(b'.');
    } else {
        for byte in without_trailing_dot.bytes() {
            state.write_u8(byte.to_ascii_lowercase());
        }
        state.write_u8(b'.');
    }
    state.write_u8(0);
}

fn hash_canonical_wire_name_into<H: Hasher>(wire: &[u8], state: &mut H) {
    let mut offset = 0;
    let mut wrote_label = false;
    let mut wrote_terminal = false;
    while let Some(&len) = wire.get(offset) {
        offset += 1;
        if len == 0 || len & 0xc0 != 0 || len > 63 {
            state.write_u8(b'.');
            wrote_terminal = true;
            break;
        }
        let end = offset + len as usize;
        if end > wire.len() {
            state.write_u8(b'.');
            wrote_terminal = true;
            break;
        }
        if wrote_label {
            state.write_u8(b'.');
        }
        for byte in &wire[offset..end] {
            state.write_u8(byte.to_ascii_lowercase());
        }
        wrote_label = true;
        offset = end;
    }
    if !wrote_label && !wrote_terminal {
        state.write_u8(b'.');
    }
    state.write_u8(0);
}

pub fn canonical_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.ends_with('.') {
        trimmed.to_owned()
    } else {
        format!("{trimmed}.")
    }
}

pub fn canonical_name_lowercase(name: &str) -> String {
    let trimmed = name.trim();
    let needs_dot = !trimmed.ends_with('.');
    if !needs_dot && !trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return trimmed.to_owned();
    }
    let mut out = String::with_capacity(trimmed.len() + usize::from(needs_dot));
    for ch in trimmed.chars() {
        out.push(ch.to_ascii_lowercase());
    }
    if needs_dot {
        out.push('.');
    }
    out
}

pub fn canonical_name_eq_ignore_ascii_case(canonical: &str, candidate: &str) -> bool {
    let candidate = candidate.trim();
    if candidate.ends_with('.') {
        canonical.eq_ignore_ascii_case(candidate)
    } else {
        canonical.len() == candidate.len() + 1
            && canonical.as_bytes().last() == Some(&b'.')
            && canonical[..candidate.len()].eq_ignore_ascii_case(candidate)
    }
}

pub fn parse_dns_cache_key(raw: &str) -> Option<DnsCacheKey> {
    let view = parse_dns_cache_key_view(raw)?;
    Some(DnsCacheKey::new(view.qname, view.qtype, view.qclass))
}

pub fn parse_dns_cache_key_view(raw: &str) -> Option<DnsCacheKeyView<'_>> {
    if let Some(last_sep) = raw.rfind('|') {
        let before_class = &raw[..last_sep];
        let class_raw = &raw[last_sep + 1..];
        if let Some(prev_sep) = before_class.rfind('|') {
            let qtype = before_class[prev_sep + 1..].parse::<u16>().ok()?;
            let qclass = class_raw.parse::<u16>().ok()?;
            return Some(DnsCacheKeyView {
                qname: &before_class[..prev_sep],
                qtype,
                qclass,
            });
        }
    }

    let last_dot = raw.rfind('.')?;
    if last_dot == raw.len() - 1 {
        return None;
    }
    let qtype = raw[last_dot + 1..].parse::<u16>().ok()?;
    Some(DnsCacheKeyView {
        qname: &raw[..last_dot],
        qtype,
        qclass: 1,
    })
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
