use super::*;

const MAP_PROFILE_ENV: &str = "RESIDENT_EBPF_MAP_PROFILE";
const MAP_PROFILE_LEGACY_ENV: &str = "DAE_EBPF_MAP_PROFILE";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NativeMapProfileSelection {
    pub(super) profile: RuntimeMapProfile,
    pub(super) source: &'static str,
    pub(super) invalid_value: Option<String>,
}

pub(super) fn selected_native_map_profile() -> NativeMapProfileSelection {
    select_native_map_profile(
        std::env::var(MAP_PROFILE_ENV).ok().as_deref(),
        std::env::var(MAP_PROFILE_LEGACY_ENV).ok().as_deref(),
    )
}

fn select_native_map_profile(
    configured: Option<&str>,
    legacy_configured: Option<&str>,
) -> NativeMapProfileSelection {
    if let Some(value) = configured {
        return parsed_selection(value, "env");
    }
    if let Some(value) = legacy_configured {
        return parsed_selection(value, "compatibility-env");
    }
    NativeMapProfileSelection {
        profile: RuntimeMapProfile::default(),
        source: "default",
        invalid_value: None,
    }
}

fn parsed_selection(value: &str, source: &'static str) -> NativeMapProfileSelection {
    match RuntimeMapProfile::parse(value) {
        Some(profile) => NativeMapProfileSelection {
            profile,
            source,
            invalid_value: None,
        },
        None => NativeMapProfileSelection {
            profile: RuntimeMapProfile::default(),
            source: "invalid-env-fallback",
            invalid_value: Some(value.to_owned()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_profile_selection_prefers_primary_and_reports_invalid_values() {
        let selected = select_native_map_profile(Some("low_memory"), Some("high"));
        assert_eq!(selected.profile, RuntimeMapProfile::LowMemory);
        assert_eq!(selected.source, "env");
        assert!(selected.invalid_value.is_none());

        let invalid = select_native_map_profile(Some("unknown"), None);
        assert_eq!(invalid.profile, RuntimeMapProfile::Balanced);
        assert_eq!(invalid.source, "invalid-env-fallback");
        assert_eq!(invalid.invalid_value.as_deref(), Some("unknown"));
    }

    #[test]
    fn map_profile_selection_uses_legacy_only_when_primary_is_absent() {
        let selected = select_native_map_profile(None, Some("high-performance"));
        assert_eq!(selected.profile, RuntimeMapProfile::HighPerformance);
        assert_eq!(selected.source, "compatibility-env");

        let default = select_native_map_profile(None, None);
        assert_eq!(default.profile, RuntimeMapProfile::Balanced);
        assert_eq!(default.source, "default");
    }
}
