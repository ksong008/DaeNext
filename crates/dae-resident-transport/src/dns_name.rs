pub fn encode_dns_qname(out: &mut Vec<u8>, lookup_host: &str) -> Result<(), String> {
    let lookup_host = lookup_host.trim_end_matches('.');
    if lookup_host.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in lookup_host.split('.') {
        if label.is_empty() {
            return Err(format!(
                "invalid DNS lookup host {lookup_host}: empty label"
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "invalid DNS lookup host {lookup_host}: label exceeds 63 bytes"
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qname_encoding_preserves_root_and_trailing_dot() {
        let mut root = Vec::new();
        encode_dns_qname(&mut root, ".").unwrap();
        assert_eq!(root, [0]);

        let mut domain = Vec::new();
        encode_dns_qname(&mut domain, "www.example.com.").unwrap();
        assert_eq!(
            domain,
            [
                3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );
    }

    #[test]
    fn qname_encoding_rejects_empty_and_oversized_labels() {
        let mut encoded = Vec::new();
        assert!(encode_dns_qname(&mut encoded, "a..b").is_err());
        assert!(encode_dns_qname(&mut encoded, &"a".repeat(64)).is_err());
    }
}
