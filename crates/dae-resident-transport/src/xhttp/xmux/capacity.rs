use super::ResidentXhttpXmuxPlan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XhttpXmuxConnectionCapacity {
    preferred: usize,
    limit: usize,
}

impl XhttpXmuxConnectionCapacity {
    pub fn from_plan(plan: &ResidentXhttpXmuxPlan) -> Self {
        Self {
            preferred: plan.sampled_connection_target(),
            limit: plan.physical_connection_limit(),
        }
    }

    pub fn should_fill_preferred(self, reusable: usize, opening: usize) -> bool {
        self.preferred > 0 && reusable.saturating_add(opening) < self.preferred
    }

    pub fn can_open(self, reusable: usize, opening: usize) -> bool {
        reusable.saturating_add(opening) < self.limit
    }

    pub fn can_start_opening(self, reusable: usize, opening: usize) -> bool {
        self.can_open(reusable, opening) && (opening == 0 || self.preferred > 0)
    }
}

pub fn can_release_retiring_owner(open_usage: i32) -> bool {
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
    fn reusable_and_opening_owners_consume_capacity() {
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
