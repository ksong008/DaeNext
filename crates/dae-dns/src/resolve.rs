use crate::error::DnsError;

pub fn guard_synthetic_asis_lookup(request_fallback: &str) -> Result<(), DnsError> {
    if request_fallback == "asis" {
        Err(DnsError::SyntheticAsisOriginalTarget)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_asis_guard_matches_golden_fixture() {
        let fixture =
            dae_golden::load_json("dns/resolve_ip46/asis_original_target_guard.json").unwrap();
        let err =
            guard_synthetic_asis_lookup(fixture["request_fallback"].as_str().unwrap()).unwrap_err();
        assert_eq!(err.to_string(), fixture["error"].as_str().unwrap());
    }
}
