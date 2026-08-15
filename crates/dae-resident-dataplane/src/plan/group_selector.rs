use super::*;
pub(super) fn build_resident_group_selector(
    group_name: &str,
    group_policy: &ResidentGroupPolicyPlan,
    candidates: &[ResidentProxyCandidatePlan],
    check_tolerance_ms: i64,
) -> DialerGroup {
    let selector_policy = match group_policy {
        ResidentGroupPolicyPlan::Fixed { .. } => SelectionPolicy::Fixed { index: 0 },
        ResidentGroupPolicyPlan::Random => SelectionPolicy::Random,
        ResidentGroupPolicyPlan::MinLastLatency => SelectionPolicy::MinLastLatency,
        ResidentGroupPolicyPlan::MinAverage10 => SelectionPolicy::MinAverage10,
        ResidentGroupPolicyPlan::MinMovingAverage => SelectionPolicy::MinMovingAverage,
    };
    DialerGroup::new(
        group_name,
        candidates
            .iter()
            .map(|candidate| {
                Dialer::new(candidate.binding.plan().node_tag.clone(), "")
                    .with_link(candidate.link.clone())
            })
            .collect(),
        candidates
            .iter()
            .map(|candidate| Annotation {
                add_latency_ms: candidate.annotation_add_latency_ms,
            })
            .collect(),
        selector_policy,
        true,
        check_tolerance_ms,
    )
}
