use std::borrow::Cow;

pub const ALLOW_INSECURE_ALIASES: &[&str] = &[
    "allowInsecure",
    "allow_insecure",
    "allowinsecure",
    "insecure",
    "skipVerify",
];

/// Preserve absence so that an explicit false can override a global true.
pub fn parse_allow_insecure(
    query: &[(Cow<'_, str>, Cow<'_, str>)],
) -> Result<Option<bool>, &'static str> {
    let mut configured = None;
    for (key, value) in query {
        if !ALLOW_INSECURE_ALIASES.contains(&key.as_ref()) || value.is_empty() {
            continue;
        }
        let value = parse_bool(value).ok_or("invalid certificate verification boolean")?;
        if configured.is_some_and(|previous| previous != value) {
            return Err("conflicting certificate verification parameters");
        }
        configured = Some(value);
    }
    Ok(configured)
}

pub fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_preserve_unset_false_and_true() {
        for key in ALLOW_INSECURE_ALIASES {
            for (value, expected) in [
                ("", None),
                ("0", Some(false)),
                ("false", Some(false)),
                ("1", Some(true)),
                ("True", Some(true)),
            ] {
                let query = vec![(Cow::Borrowed(*key), Cow::Borrowed(value))];
                assert_eq!(parse_allow_insecure(&query).unwrap(), expected);
            }
        }
        assert_eq!(parse_allow_insecure(&[]).unwrap(), None);
    }

    #[test]
    fn malformed_and_conflicting_overrides_are_rejected() {
        for raw in [
            "insecure=invalid",
            "insecure=0&allowInsecure=1",
            "insecure=1&insecure=0",
        ] {
            let query = url::form_urlencoded::parse(raw.as_bytes()).collect::<Vec<_>>();
            assert!(parse_allow_insecure(&query).is_err());
        }
    }
}
