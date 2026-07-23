use super::*;

const LOW_MEMORY_MAXIMUM_RETIRED_GENERATIONS: usize = 1;
const BALANCED_MAXIMUM_RETIRED_GENERATIONS: usize = 2;
const HIGH_PERFORMANCE_MAXIMUM_RETIRED_GENERATIONS: usize = 4;

const LOW_MEMORY_GENERATION_MAXIMUM_AGE_SECONDS: u64 =
    RESIDENT_UDP_SESSION_IDLE_TIMEOUT.as_secs() * 3;
const BALANCED_GENERATION_MAXIMUM_AGE_SECONDS: u64 =
    RESIDENT_UDP_SESSION_IDLE_TIMEOUT.as_secs() * 6;
const HIGH_PERFORMANCE_GENERATION_MAXIMUM_AGE_SECONDS: u64 =
    RESIDENT_UDP_SESSION_IDLE_TIMEOUT.as_secs() * 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResidentGenerationDrainPolicy {
    pub(super) maximum_age: Duration,
    pub(super) maximum_retired: usize,
    pub(super) source: &'static str,
}

impl ResidentGenerationDrainPolicy {
    pub(super) fn selected() -> Self {
        Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
    }

    pub(super) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        let (maximum_age_seconds, maximum_retired) = match profile {
            ResidentRuntimeProfile::LowMemory => (
                LOW_MEMORY_GENERATION_MAXIMUM_AGE_SECONDS,
                LOW_MEMORY_MAXIMUM_RETIRED_GENERATIONS,
            ),
            ResidentRuntimeProfile::Balanced => (
                BALANCED_GENERATION_MAXIMUM_AGE_SECONDS,
                BALANCED_MAXIMUM_RETIRED_GENERATIONS,
            ),
            ResidentRuntimeProfile::HighPerformance => (
                HIGH_PERFORMANCE_GENERATION_MAXIMUM_AGE_SECONDS,
                HIGH_PERFORMANCE_MAXIMUM_RETIRED_GENERATIONS,
            ),
        };
        Self {
            maximum_age: Duration::from_secs(maximum_age_seconds),
            maximum_retired,
            source: "runtime-profile",
        }
    }

    #[cfg(test)]
    pub(super) const fn for_test(maximum_age: Duration, maximum_retired: usize) -> Self {
        Self {
            maximum_age,
            maximum_retired,
            source: "test",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_profiles_cover_existing_flow_and_session_idle_contracts() {
        for profile in [
            ResidentRuntimeProfile::LowMemory,
            ResidentRuntimeProfile::Balanced,
            ResidentRuntimeProfile::HighPerformance,
        ] {
            let policy = ResidentGenerationDrainPolicy::from_runtime_profile(profile);
            assert!(policy.maximum_age >= RESIDENT_TCP_IDLE_TIMEOUT);
            assert!(policy.maximum_age >= RESIDENT_UDP_SESSION_IDLE_TIMEOUT);
            assert!(policy.maximum_retired > 0);
        }
    }

    #[test]
    fn higher_capacity_profiles_allow_more_retired_generations() {
        let low =
            ResidentGenerationDrainPolicy::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let balanced =
            ResidentGenerationDrainPolicy::from_runtime_profile(ResidentRuntimeProfile::Balanced);
        let high = ResidentGenerationDrainPolicy::from_runtime_profile(
            ResidentRuntimeProfile::HighPerformance,
        );

        assert!(low.maximum_retired < balanced.maximum_retired);
        assert!(balanced.maximum_retired < high.maximum_retired);
        assert!(low.maximum_age < balanced.maximum_age);
        assert!(balanced.maximum_age < high.maximum_age);
    }
}
