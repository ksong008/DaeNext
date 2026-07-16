use crate::production_runtime_owner::resident_dataplane::{
    ResidentRuntimeProfile, ResidentRuntimeProfileSelection,
};

const LOW_MEMORY_XHTTP_PHYSICAL_CONNECTION_LIMIT: usize = 1;
const BALANCED_XHTTP_PHYSICAL_CONNECTION_LIMIT: usize = 2;
const HIGH_PERFORMANCE_XHTTP_PHYSICAL_CONNECTION_LIMIT: usize = 4;

pub(super) fn selected_xhttp_physical_connection_limit() -> usize {
    xhttp_physical_connection_limit(ResidentRuntimeProfileSelection::selected().profile)
}

fn xhttp_physical_connection_limit(profile: ResidentRuntimeProfile) -> usize {
    match profile {
        ResidentRuntimeProfile::LowMemory => LOW_MEMORY_XHTTP_PHYSICAL_CONNECTION_LIMIT,
        ResidentRuntimeProfile::Balanced => BALANCED_XHTTP_PHYSICAL_CONNECTION_LIMIT,
        ResidentRuntimeProfile::HighPerformance => HIGH_PERFORMANCE_XHTTP_PHYSICAL_CONNECTION_LIMIT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_profiles_keep_xhttp_physical_connections_bounded_and_monotonic() {
        let low = xhttp_physical_connection_limit(ResidentRuntimeProfile::LowMemory);
        let balanced = xhttp_physical_connection_limit(ResidentRuntimeProfile::Balanced);
        let high = xhttp_physical_connection_limit(ResidentRuntimeProfile::HighPerformance);

        assert!(low > 0);
        assert!(low <= balanced);
        assert!(balanced <= high);
    }
}
