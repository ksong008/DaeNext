pub fn encode_dns_qname(out: &mut Vec<u8>, lookup_host: &str) -> Result<(), String> {
    dae_dns::encode_dns_name_into(out, lookup_host)
        .map_err(|error| format!("invalid DNS lookup host: {error}"))
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
    fn qname_encoding_enforces_expanded_wire_length() {
        for last in [61, 62, 63] {
            let host = [
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(last),
            ]
            .join(".");
            assert_eq!(encode_dns_qname(&mut Vec::new(), &host).is_ok(), last == 61);
        }
    }

    #[test]
    fn qname_encoding_rejects_empty_and_oversized_labels() {
        let mut encoded = Vec::new();
        assert!(encode_dns_qname(&mut encoded, "a..b").is_err());
        assert!(encode_dns_qname(&mut encoded, &"a".repeat(64)).is_err());
    }
}
