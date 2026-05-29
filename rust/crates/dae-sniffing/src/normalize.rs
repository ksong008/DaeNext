use std::borrow::Cow;

pub fn normalize_domain(host: &str) -> String {
    normalize_domain_cow(host).into_owned()
}

pub fn normalize_domain_cow(input: &str) -> Cow<'_, str> {
    let trimmed = input.trim();
    let mut host = trimmed;
    let mut needs_owned = host.len() != input.len();

    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
        needs_owned = true;
    } else if let Some(domain) = split_host_port(host) {
        host = domain;
        needs_owned = true;
    }

    if let Some(stripped) = host.strip_suffix('.') {
        host = stripped;
        needs_owned = true;
    }

    if host.bytes().any(|ch| ch.is_ascii_uppercase()) {
        Cow::Owned(host.to_ascii_lowercase())
    } else if needs_owned {
        Cow::Owned(host.to_owned())
    } else {
        Cow::Borrowed(host)
    }
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
    use std::borrow::Cow;

    #[test]
    fn normalize_domain_matches_go_edges() {
        assert_eq!(normalize_domain(" Example.COM:443 "), "example.com");
        assert_eq!(normalize_domain("example.com."), "example.com");
        assert_eq!(
            normalize_domain("[2606:4700:20::681a:d1f]"),
            "2606:4700:20::681a:d1f"
        );
        assert!(matches!(
            normalize_domain_cow("example.com"),
            Cow::Borrowed("example.com")
        ));
    }
}
