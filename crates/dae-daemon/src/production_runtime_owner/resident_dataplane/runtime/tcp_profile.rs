use super::*;

pub(crate) const RESIDENT_TCP_RUNTIME_PROFILE_ENV: &str = "RESIDENT_TCP_RUNTIME_PROFILE";
const RESIDENT_TCP_RUNTIME_PROFILE_LOW_MEMORY: &str = "low-memory";
const RESIDENT_TCP_RUNTIME_PROFILE_BALANCED: &str = "balanced";
const RESIDENT_TCP_RUNTIME_PROFILE_HIGH_PERFORMANCE: &str = "high-performance";

const LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX: usize = 2;
const BALANCED_TCP_RUNTIME_WORKERS_MAX: usize = 4;
const HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX: usize = 8;
const LOW_MEMORY_TCP_CONNECTION_LIMIT: usize = 256;
const BALANCED_TCP_CONNECTION_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentTcpRuntimeProfile {
    LowMemory,
    Balanced,
    HighPerformance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTcpRuntimeProfileSelection {
    pub(crate) profile: ResidentTcpRuntimeProfile,
    source: &'static str,
    invalid_value: Option<String>,
}

impl ResidentTcpRuntimeProfile {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" | "low_memory" | RESIDENT_TCP_RUNTIME_PROFILE_LOW_MEMORY => Some(Self::LowMemory),
            "" | "standard" | RESIDENT_TCP_RUNTIME_PROFILE_BALANCED => Some(Self::Balanced),
            "high" | "high_performance" | RESIDENT_TCP_RUNTIME_PROFILE_HIGH_PERFORMANCE => {
                Some(Self::HighPerformance)
            }
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::LowMemory => RESIDENT_TCP_RUNTIME_PROFILE_LOW_MEMORY,
            Self::Balanced => RESIDENT_TCP_RUNTIME_PROFILE_BALANCED,
            Self::HighPerformance => RESIDENT_TCP_RUNTIME_PROFILE_HIGH_PERFORMANCE,
        }
    }

    pub(crate) fn tcp_runtime_workers_default(self, available_parallelism: usize) -> usize {
        let profile_max = match self {
            Self::LowMemory => LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX,
            Self::Balanced => BALANCED_TCP_RUNTIME_WORKERS_MAX,
            Self::HighPerformance => HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX,
        };
        available_parallelism.max(1).min(profile_max)
    }

    pub(crate) fn tcp_connection_limit_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_TCP_CONNECTION_LIMIT,
            Self::Balanced => BALANCED_TCP_CONNECTION_LIMIT,
            Self::HighPerformance => HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT,
        }
    }
}

impl ResidentTcpRuntimeProfileSelection {
    pub(crate) fn selected() -> Self {
        select_resident_tcp_runtime_profile(
            std::env::var(RESIDENT_TCP_RUNTIME_PROFILE_ENV)
                .ok()
                .as_deref(),
        )
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "name": self.profile.name(),
            "source": self.source,
            "env": RESIDENT_TCP_RUNTIME_PROFILE_ENV,
            "invalidValue": self.invalid_value,
        })
    }
}

pub(crate) fn resident_tcp_runtime_profile_contract() -> Value {
    json!({
        "env": RESIDENT_TCP_RUNTIME_PROFILE_ENV,
        "default": RESIDENT_TCP_RUNTIME_PROFILE_BALANCED,
        "supported": [
            RESIDENT_TCP_RUNTIME_PROFILE_LOW_MEMORY,
            RESIDENT_TCP_RUNTIME_PROFILE_BALANCED,
            RESIDENT_TCP_RUNTIME_PROFILE_HIGH_PERFORMANCE,
        ],
        "profiles": [
            {
                "name": RESIDENT_TCP_RUNTIME_PROFILE_LOW_MEMORY,
                "tcpRuntimeWorkersMax": LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": LOW_MEMORY_TCP_CONNECTION_LIMIT,
            },
            {
                "name": RESIDENT_TCP_RUNTIME_PROFILE_BALANCED,
                "tcpRuntimeWorkersMax": BALANCED_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": BALANCED_TCP_CONNECTION_LIMIT,
            },
            {
                "name": RESIDENT_TCP_RUNTIME_PROFILE_HIGH_PERFORMANCE,
                "tcpRuntimeWorkersMax": HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT,
            },
        ],
    })
}

fn select_resident_tcp_runtime_profile(
    configured: Option<&str>,
) -> ResidentTcpRuntimeProfileSelection {
    if let Some(value) = configured {
        return parsed_profile_selection(value, "env");
    }
    ResidentTcpRuntimeProfileSelection {
        profile: ResidentTcpRuntimeProfile::Balanced,
        source: "default",
        invalid_value: None,
    }
}

fn parsed_profile_selection(
    value: &str,
    source: &'static str,
) -> ResidentTcpRuntimeProfileSelection {
    match ResidentTcpRuntimeProfile::parse(value) {
        Some(profile) => ResidentTcpRuntimeProfileSelection {
            profile,
            source,
            invalid_value: None,
        },
        None => ResidentTcpRuntimeProfileSelection {
            profile: ResidentTcpRuntimeProfile::Balanced,
            source: "invalid-env-fallback",
            invalid_value: Some(value.to_owned()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_tcp_runtime_profiles_bound_workers_and_connections() {
        assert_eq!(
            ResidentTcpRuntimeProfile::LowMemory.tcp_runtime_workers_default(64),
            LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX
        );
        assert_eq!(
            ResidentTcpRuntimeProfile::Balanced.tcp_runtime_workers_default(64),
            BALANCED_TCP_RUNTIME_WORKERS_MAX
        );
        assert_eq!(
            ResidentTcpRuntimeProfile::HighPerformance.tcp_runtime_workers_default(64),
            HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX
        );
        assert_eq!(
            ResidentTcpRuntimeProfile::Balanced.tcp_runtime_workers_default(1),
            1
        );
        assert!(
            ResidentTcpRuntimeProfile::LowMemory.tcp_connection_limit_default()
                < ResidentTcpRuntimeProfile::Balanced.tcp_connection_limit_default()
        );
        assert!(
            ResidentTcpRuntimeProfile::Balanced.tcp_connection_limit_default()
                < ResidentTcpRuntimeProfile::HighPerformance.tcp_connection_limit_default()
        );
    }

    #[test]
    fn resident_tcp_runtime_profile_reports_invalid_values() {
        let selected = select_resident_tcp_runtime_profile(Some("high"));
        assert_eq!(selected.profile, ResidentTcpRuntimeProfile::HighPerformance);
        assert_eq!(selected.source, "env");

        let invalid = select_resident_tcp_runtime_profile(Some("unknown"));
        assert_eq!(invalid.profile, ResidentTcpRuntimeProfile::Balanced);
        assert_eq!(invalid.source, "invalid-env-fallback");
        assert_eq!(invalid.invalid_value.as_deref(), Some("unknown"));
    }
}
