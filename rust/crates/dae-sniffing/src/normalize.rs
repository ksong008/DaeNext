pub fn normalize_domain(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    if host.ends_with(']') {
        return host.trim_matches(['[', ']']).to_owned();
    }

    if let Some(domain) = split_host_port(&host) {
        return domain.to_owned();
    }
    host.trim_end_matches('.').to_owned()
}

fn split_host_port(host: &str) -> Option<&str> {
    let (domain, port) = host.rsplit_once(':')?;
    if domain.is_empty() || port.is_empty() || !port.bytes().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_matches_go_edges() {
        assert_eq!(normalize_domain(" Example.COM:443 "), "example.com");
        assert_eq!(normalize_domain("example.com."), "example.com");
        assert_eq!(
            normalize_domain("[2606:4700:20::681a:d1f]"),
            "2606:4700:20::681a:d1f"
        );
    }
}
