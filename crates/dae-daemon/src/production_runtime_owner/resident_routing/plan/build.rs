use super::*;
pub(crate) fn build_routing_plan(config: &Config) -> Result<ResidentRoutingPlan, String> {
    build_routing_plan_with_asset_dirs(config, Vec::<PathBuf>::new())
}

pub(crate) fn build_routing_plan_with_asset_dirs(
    config: &Config,
    asset_dirs: impl IntoIterator<Item = impl Into<PathBuf>>,
) -> Result<ResidentRoutingPlan, String> {
    let groups = outbound_groups(config)?;
    let resolver = GeodataResolver::new(asset_dirs);
    let mut geodata_report = GeodataResolutionReport::default();
    let rules = optimize_routing_rules(&config.routing.rules, &resolver, &mut geodata_report)?;
    let mut plan = ResidentRoutingPlan {
        matches: Vec::new(),
        lpm_sets: Vec::new(),
        domain_sets: Vec::new(),
        geodata_report,
        skipped_rules: Vec::new(),
    };
    for (index, rule) in rules.iter().enumerate() {
        if let Err(err) = compile_rule(&mut plan, &groups, rule) {
            return Err(format!(
                "resident routing rule {index} failed after generic optimization: {err}; rule={}",
                rule.to_config_string(false, false, true)
            ));
        }
    }
    let fallback = dynamic_to_single_function(&config.routing.fallback)?;
    let fallback = parse_outbound(&fallback, &groups)?;
    plan.matches.push(match_set(
        [0; 16],
        false,
        MATCH_TYPE_FALLBACK,
        fallback,
        "Fallback",
    ));
    if plan.matches.len() > MAX_MATCH_SET_LEN {
        return Err(format!(
            "resident routing_map match set overflow: {} > {}",
            plan.matches.len(),
            MAX_MATCH_SET_LEN
        ));
    }
    Ok(plan)
}
