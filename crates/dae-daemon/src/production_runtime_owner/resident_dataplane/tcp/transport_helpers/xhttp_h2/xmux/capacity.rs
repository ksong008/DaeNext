use super::ResidentXhttpXmuxPlan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct XhttpXmuxConnectionCapacity {
    preferred: usize,
    limit: usize,
}

impl XhttpXmuxConnectionCapacity {
    pub(super) fn from_plan(plan: &ResidentXhttpXmuxPlan) -> Self {
        Self {
            preferred: plan.sampled_connection_target(),
            limit: plan.physical_connection_limit(),
        }
    }

    pub(super) fn should_fill_preferred(self, live: usize, opening: usize) -> bool {
        self.preferred > 0 && live.saturating_add(opening) < self.preferred
    }

    pub(super) fn can_open(self, live: usize, opening: usize) -> bool {
        live.saturating_add(opening) < self.limit
    }

    pub(super) fn can_start_opening(self, live: usize, opening: usize) -> bool {
        self.can_open(live, opening) && (opening == 0 || self.preferred > 0)
    }
}

pub(super) fn can_release_retiring_owner(open_usage: i32) -> bool {
    open_usage <= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(limit: usize, requested: Option<(i32, i32)>) -> ResidentXhttpXmuxPlan {
        ResidentXhttpXmuxPlan {
            runtime_generation: 1,
            physical_connection_limit: limit,
            max_concurrency: Some((1, 1)),
            max_connections: requested,
            c_max_reuse_times: None,
            h_max_request_times: None,
            h_max_reusable_secs: None,
            h_keep_alive_period: 0,
        }
    }

    #[test]
    fn configured_target_is_clamped_by_the_physical_limit() {
        let capacity = XhttpXmuxConnectionCapacity::from_plan(&plan(2, Some((8, 8))));

        assert!(capacity.should_fill_preferred(1, 0));
        assert!(!capacity.should_fill_preferred(2, 0));
        assert!(!capacity.can_open(2, 0));
    }

    #[test]
    fn live_retiring_and_opening_owners_all_consume_capacity() {
        let capacity = XhttpXmuxConnectionCapacity::from_plan(&plan(3, None));

        assert!(capacity.can_open(1, 1));
        assert!(!capacity.can_open(2, 1));
        assert!(!capacity.can_open(3, 0));
    }

    #[test]
    fn omitted_connection_target_does_not_eagerly_fill_the_hard_limit() {
        let capacity = XhttpXmuxConnectionCapacity::from_plan(&plan(4, None));

        assert!(!capacity.should_fill_preferred(1, 0));
        assert!(capacity.can_open(1, 0));
        assert!(!capacity.can_start_opening(1, 1));
    }

    #[test]
    fn retiring_owner_remains_charged_until_its_last_lease_closes() {
        assert!(!can_release_retiring_owner(2));
        assert!(!can_release_retiring_owner(1));
        assert!(can_release_retiring_owner(0));
    }
}
