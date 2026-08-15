use super::*;
pub(crate) struct ResidentPreparedGeneration {
    pub(super) config: Arc<Config>,
    pub(super) geodata_asset_dirs: Vec<PathBuf>,
    pub(super) geodata: ResidentGeodataStore,
    pub(super) dataplane: ResidentPreparedDataplane,
}

pub(crate) fn prepare_resident_production_generation(
    config: Arc<Config>,
    geodata_asset_dirs: impl IntoIterator<Item = impl Into<PathBuf>>,
) -> Result<ResidentPreparedGeneration, String> {
    super::super::resident_allocator::install_resident_allocator_hooks();
    let geodata_asset_dirs = geodata_asset_dirs
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();
    let geodata = ResidentGeodataStore::new(geodata_asset_dirs.clone());
    let plan = build_resident_dataplane_plan_with_geodata(&config, &geodata)?;
    let protocol_owner_specs = plan.protocol_owner_specs();
    let routing_matcher = build_resident_userspace_routing_matcher_with_geodata(&config, &geodata)?;
    Ok(ResidentPreparedGeneration {
        config,
        geodata_asset_dirs,
        geodata,
        dataplane: ResidentPreparedDataplane {
            plan,
            routing_matcher,
            protocol_owner_specs,
        },
    })
}
