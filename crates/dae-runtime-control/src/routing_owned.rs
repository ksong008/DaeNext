use std::io;

use dae_ebpf_support::apply_routing_maps_with_lpm_build_by_id;

use crate::routing_native::{
    LpmMapTemplate, RoutingNativeBuildPlan, RoutingNativeFallback, RoutingNativePlanError,
    RoutingNativeRule, build_routing_native_plan,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutingMapOwner {
    routing_map_id: Option<u32>,
    lpm_array_map_id: Option<u32>,
    checksum: Option<blake3::Hash>,
    plan: RoutingNativeBuildPlan,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutingMapOwnerApplyReport {
    pub routing_map_id: u32,
    pub lpm_array_map_id: u32,
    pub map_changed: bool,
    pub plan_changed: bool,
    pub skipped: bool,
    pub checksum: u64,
    pub routing_entries_updated: usize,
    pub lpm_maps_created: usize,
}

impl RoutingMapOwner {
    pub fn routing_map_id(&self) -> Option<u32> {
        self.routing_map_id
    }

    pub fn lpm_array_map_id(&self) -> Option<u32> {
        self.lpm_array_map_id
    }

    pub fn checksum(&self) -> Option<blake3::Hash> {
        self.checksum
    }

    pub fn plan(&self) -> &RoutingNativeBuildPlan {
        &self.plan
    }

    pub fn apply_snapshot_by_id(
        &mut self,
        routing_map_id: u32,
        lpm_array_map_id: u32,
        plan: RoutingNativeBuildPlan,
    ) -> io::Result<RoutingMapOwnerApplyReport> {
        self.apply_snapshot_with(
            routing_map_id,
            lpm_array_map_id,
            plan,
            |routing, lpm, plan| {
                apply_routing_maps_with_lpm_build_by_id(
                    routing,
                    lpm,
                    &plan.routing_entries,
                    &[],
                    &plan.lpm_maps,
                )
                .map(|_| ())
            },
        )
    }

    pub fn apply_snapshot_with(
        &mut self,
        routing_map_id: u32,
        lpm_array_map_id: u32,
        plan: RoutingNativeBuildPlan,
        apply: impl FnOnce(u32, u32, &RoutingNativeBuildPlan) -> io::Result<()>,
    ) -> io::Result<RoutingMapOwnerApplyReport> {
        plan.validate()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let checksum = plan.checksum();
        let map_changed = self.routing_map_id != Some(routing_map_id)
            || self.lpm_array_map_id != Some(lpm_array_map_id);
        let plan_changed = self.checksum != Some(checksum);
        if !map_changed && !plan_changed {
            return Ok(RoutingMapOwnerApplyReport {
                routing_map_id,
                lpm_array_map_id,
                map_changed: false,
                plan_changed: false,
                skipped: true,
                checksum: checksum_digest_u64(&checksum),
                routing_entries_updated: 0,
                lpm_maps_created: 0,
            });
        }

        apply(routing_map_id, lpm_array_map_id, &plan)?;
        let routing_entries_updated = plan.routing_entries.len();
        let lpm_maps_created = plan.lpm_maps.len();
        self.routing_map_id = Some(routing_map_id);
        self.lpm_array_map_id = Some(lpm_array_map_id);
        self.checksum = Some(checksum);
        self.plan = plan;
        Ok(RoutingMapOwnerApplyReport {
            routing_map_id,
            lpm_array_map_id,
            map_changed,
            plan_changed,
            skipped: false,
            checksum: checksum_digest_u64(&checksum),
            routing_entries_updated,
            lpm_maps_created,
        })
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingRuleState {
    pub rules: Vec<RoutingNativeRule>,
    pub fallback: RoutingNativeFallback,
    pub lpm_template: LpmMapTemplate,
}

impl RoutingRuleState {
    pub fn new(
        rules: Vec<RoutingNativeRule>,
        fallback: RoutingNativeFallback,
        lpm_template: LpmMapTemplate,
    ) -> Self {
        Self {
            rules,
            fallback,
            lpm_template,
        }
    }

    pub fn build_plan(&self) -> Result<RoutingNativeBuildPlan, RoutingNativePlanError> {
        build_routing_native_plan(&self.rules, self.fallback, self.lpm_template)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutingRuleOwner {
    state: Option<RoutingRuleState>,
    map_owner: RoutingMapOwner,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutingRuleOwnerApplyReport {
    pub map: RoutingMapOwnerApplyReport,
    pub rule_count: usize,
    pub lpm_rule_count: usize,
}

impl RoutingRuleOwner {
    pub fn state(&self) -> Option<&RoutingRuleState> {
        self.state.as_ref()
    }

    pub fn map_owner(&self) -> &RoutingMapOwner {
        &self.map_owner
    }

    pub fn apply_rules_with(
        &mut self,
        routing_map_id: u32,
        lpm_array_map_id: u32,
        state: RoutingRuleState,
        apply: impl FnOnce(u32, u32, &RoutingNativeBuildPlan) -> io::Result<()>,
    ) -> io::Result<RoutingRuleOwnerApplyReport> {
        let plan = state
            .build_plan()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let lpm_rule_count = state
            .rules
            .iter()
            .filter(|rule| {
                matches!(
                    &rule.matcher,
                    crate::routing_native::RoutingNativeMatch::IpSet(_)
                        | crate::routing_native::RoutingNativeMatch::SourceIpSet(_)
                        | crate::routing_native::RoutingNativeMatch::Mac(_)
                )
            })
            .count();
        let rule_count = state.rules.len();
        let report =
            self.map_owner
                .apply_snapshot_with(routing_map_id, lpm_array_map_id, plan, apply)?;
        if !report.skipped || self.state.is_none() {
            self.state = Some(state);
        }
        Ok(RoutingRuleOwnerApplyReport {
            map: report,
            rule_count,
            lpm_rule_count,
        })
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Truncated digest for reports: the first 8 bytes (little-endian) of the
/// full BLAKE3 digest.  Reports are diagnostic only; change detection uses
/// the full `blake3::Hash`.
fn checksum_digest_u64(hash: &blake3::Hash) -> u64 {
    let bytes: [u8; 8] = hash.as_bytes()[..8].try_into().expect("8-byte slice");
    u64::from_le_bytes(bytes)
}
