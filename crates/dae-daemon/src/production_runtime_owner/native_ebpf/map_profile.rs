use super::*;
use crate::production_runtime_owner::resident_dataplane::facade::selected_resident_runtime_profile_name;

const MAP_PROFILE_ENV: &str = "RESIDENT_EBPF_MAP_PROFILE";
const MAP_PROFILE_LEGACY_ENV: &str = "DAE_EBPF_MAP_PROFILE";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NativeMapProfileSelection {
    pub(super) profile: RuntimeMapProfile,
    pub(super) source: &'static str,
    pub(super) invalid_value: Option<String>,
}

pub(super) fn selected_native_map_profile() -> NativeMapProfileSelection {
    let runtime_profile =
        RuntimeMapProfile::parse(selected_resident_runtime_profile_name()).unwrap_or_default();
    select_native_map_profile(
        std::env::var(MAP_PROFILE_ENV).ok().as_deref(),
        std::env::var(MAP_PROFILE_LEGACY_ENV).ok().as_deref(),
        runtime_profile,
    )
}

fn select_native_map_profile(
    configured: Option<&str>,
    legacy_configured: Option<&str>,
    runtime_profile: RuntimeMapProfile,
) -> NativeMapProfileSelection {
    if let Some(value) = configured {
        return parsed_selection(value, "env", runtime_profile);
    }
    if let Some(value) = legacy_configured {
        return parsed_selection(value, "compatibility-env", runtime_profile);
    }
    NativeMapProfileSelection {
        profile: runtime_profile,
        source: "runtime-profile",
        invalid_value: None,
    }
}

fn parsed_selection(
    value: &str,
    source: &'static str,
    runtime_profile: RuntimeMapProfile,
) -> NativeMapProfileSelection {
    match RuntimeMapProfile::parse(value) {
        Some(profile) => NativeMapProfileSelection {
            profile,
            source,
            invalid_value: None,
        },
        None => NativeMapProfileSelection {
            profile: runtime_profile,
            source: "invalid-env-runtime-profile",
            invalid_value: Some(value.to_owned()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_profile_selection_prefers_primary_and_reports_invalid_values() {
        let selected = select_native_map_profile(
            Some("low_memory"),
            Some("high"),
            RuntimeMapProfile::Balanced,
        );
        assert_eq!(selected.profile, RuntimeMapProfile::LowMemory);
        assert_eq!(selected.source, "env");
        assert!(selected.invalid_value.is_none());

        let invalid =
            select_native_map_profile(Some("unknown"), None, RuntimeMapProfile::LowMemory);
        assert_eq!(invalid.profile, RuntimeMapProfile::LowMemory);
        assert_eq!(invalid.source, "invalid-env-runtime-profile");
        assert_eq!(invalid.invalid_value.as_deref(), Some("unknown"));
    }

    #[test]
    fn map_profile_selection_uses_legacy_only_when_primary_is_absent() {
        let selected =
            select_native_map_profile(None, Some("high-performance"), RuntimeMapProfile::LowMemory);
        assert_eq!(selected.profile, RuntimeMapProfile::HighPerformance);
        assert_eq!(selected.source, "compatibility-env");

        let automatic = select_native_map_profile(None, None, RuntimeMapProfile::HighPerformance);
        assert_eq!(automatic.profile, RuntimeMapProfile::HighPerformance);
        assert_eq!(automatic.source, "runtime-profile");
    }
}
