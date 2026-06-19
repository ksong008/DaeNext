use super::*;
#[cfg(feature = "native-ebpf")]
pub(super) fn truncated_bpf_name(name: &str) -> String {
    const BPF_OBJ_NAME_MAX_VISIBLE_LEN: usize = 15;
    name.chars().take(BPF_OBJ_NAME_MAX_VISIBLE_LEN).collect()
}

#[cfg(feature = "native-ebpf")]
pub(super) fn collect_loaded_map_ids(
    before_map_ids: &[u32],
) -> Result<BTreeMap<String, u32>, String> {
    use std::os::fd::AsRawFd;

    let before_map_ids = before_map_ids.iter().copied().collect::<BTreeSet<_>>();
    let current = dae_ebpf_support::map_ids()
        .map_err(|err| format!("native eBPF after-load map snapshot failed: {err}"))?;
    let mut loaded_map_ids = BTreeMap::new();
    for id in current
        .into_iter()
        .filter(|id| !before_map_ids.contains(id))
    {
        let fd = match dae_ebpf_support::open_map_fd(id) {
            Ok(fd) => fd,
            Err(err) if is_transient_missing_map_id(&err) => continue,
            Err(err) => {
                return Err(format!("native eBPF open loaded map id {id} failed: {err}"));
            }
        };
        let info = match dae_ebpf_support::map_info(fd.as_raw_fd()) {
            Ok(info) => info,
            Err(err) if is_transient_missing_map_id(&err) => continue,
            Err(err) => {
                return Err(format!(
                    "native eBPF inspect loaded map id {id} failed: {err}"
                ));
            }
        };
        loaded_map_ids.entry(info.name).or_insert(info.id);
    }
    Ok(loaded_map_ids)
}

#[cfg(any(feature = "native-ebpf", test))]
pub(super) fn is_transient_missing_map_id(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound
}

impl Drop for NativeEbpfRuntimeState {
    fn drop(&mut self) {
        self.reset();
    }
}
