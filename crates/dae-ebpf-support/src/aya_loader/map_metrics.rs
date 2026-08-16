use super::*;

const UDP_STATE_METRICS_MAP_NAME: &str = "udp_state_metrics";
const UDP_STATE_METRICS_KEY: u32 = 0;

pub fn read_aya_udp_state_metrics(
    loaded: &AyaUserspaceLoadedObject,
) -> Result<BpfUdpStateMetrics, String> {
    let map = loaded
        .ebpf
        .map(UDP_STATE_METRICS_MAP_NAME)
        .ok_or_else(|| format!("loaded object is missing {UDP_STATE_METRICS_MAP_NAME}"))?;
    let array = aya::maps::PerCpuArray::<_, BpfUdpStateMetrics>::try_from(map)
        .map_err(|err| format!("open {UDP_STATE_METRICS_MAP_NAME}: {err:?}"))?;
    let values = array
        .get(&UDP_STATE_METRICS_KEY, 0)
        .map_err(|err| format!("read {UDP_STATE_METRICS_MAP_NAME}: {err:?}"))?;
    Ok(sum_udp_state_metrics(values.iter()))
}

pub fn read_aya_udp_state_metrics_by_id(map_id: u32) -> Result<BpfUdpStateMetrics, String> {
    let fd = crate::open_map_fd(map_id)
        .map_err(|err| format!("open {UDP_STATE_METRICS_MAP_NAME} map id {map_id}: {err}"))?;
    let data = aya::maps::MapData::from_fd(fd)
        .map_err(|err| format!("open {UDP_STATE_METRICS_MAP_NAME}: {err:?}"))?;
    let map = aya::maps::Map::PerCpuArray(data);
    let array = aya::maps::PerCpuArray::<_, BpfUdpStateMetrics>::try_from(map)
        .map_err(|err| format!("open {UDP_STATE_METRICS_MAP_NAME}: {err:?}"))?;
    let values = array
        .get(&UDP_STATE_METRICS_KEY, 0)
        .map_err(|err| format!("read {UDP_STATE_METRICS_MAP_NAME}: {err:?}"))?;
    Ok(sum_udp_state_metrics(values.iter()))
}

fn sum_udp_state_metrics<'a>(
    values: impl IntoIterator<Item = &'a BpfUdpStateMetrics>,
) -> BpfUdpStateMetrics {
    values
        .into_iter()
        .fold(BpfUdpStateMetrics::default(), |mut total, value| {
            total.state_created_total = total
                .state_created_total
                .saturating_add(value.state_created_total);
            total.state_refresh_total = total
                .state_refresh_total
                .saturating_add(value.state_refresh_total);
            total.insert_failure_total = total
                .insert_failure_total
                .saturating_add(value.insert_failure_total);
            total.post_insert_lookup_failure_total = total
                .post_insert_lookup_failure_total
                .saturating_add(value.post_insert_lookup_failure_total);
            total.timer_init_failure_total = total
                .timer_init_failure_total
                .saturating_add(value.timer_init_failure_total);
            total.timer_callback_failure_total = total
                .timer_callback_failure_total
                .saturating_add(value.timer_callback_failure_total);
            total.timer_start_failure_total = total
                .timer_start_failure_total
                .saturating_add(value.timer_start_failure_total);
            total
        })
}

const TPROXY_METRICS_MAP_NAME: &str = "tproxy_metrics";
const TPROXY_METRICS_KEY: u32 = 0;

/// Read the summed tproxy redirect failure counters (sk_assign /
/// skb_store_bytes) from the loaded object's `tproxy_metrics` per-CPU array.
pub fn read_aya_tproxy_metrics(
    loaded: &AyaUserspaceLoadedObject,
) -> Result<BpfTproxyMetrics, String> {
    let map = loaded
        .ebpf
        .map(TPROXY_METRICS_MAP_NAME)
        .ok_or_else(|| format!("loaded object is missing {TPROXY_METRICS_MAP_NAME}"))?;
    let array = aya::maps::PerCpuArray::<_, BpfTproxyMetrics>::try_from(map)
        .map_err(|err| format!("open {TPROXY_METRICS_MAP_NAME}: {err:?}"))?;
    let values = array
        .get(&TPROXY_METRICS_KEY, 0)
        .map_err(|err| format!("read {TPROXY_METRICS_MAP_NAME}: {err:?}"))?;
    Ok(sum_tproxy_metrics(values.iter()))
}

/// Read the summed tproxy redirect failure counters by map id (used by the
/// daemon's runtime metrics view after the object is loaded and pinned).
pub fn read_aya_tproxy_metrics_by_id(map_id: u32) -> Result<BpfTproxyMetrics, String> {
    let fd = crate::open_map_fd(map_id)
        .map_err(|err| format!("open {TPROXY_METRICS_MAP_NAME} map id {map_id}: {err}"))?;
    let data = aya::maps::MapData::from_fd(fd)
        .map_err(|err| format!("open {TPROXY_METRICS_MAP_NAME}: {err:?}"))?;
    let map = aya::maps::Map::PerCpuArray(data);
    let array = aya::maps::PerCpuArray::<_, BpfTproxyMetrics>::try_from(map)
        .map_err(|err| format!("open {TPROXY_METRICS_MAP_NAME}: {err:?}"))?;
    let values = array
        .get(&TPROXY_METRICS_KEY, 0)
        .map_err(|err| format!("read {TPROXY_METRICS_MAP_NAME}: {err:?}"))?;
    Ok(sum_tproxy_metrics(values.iter()))
}

fn sum_tproxy_metrics<'a>(
    values: impl IntoIterator<Item = &'a BpfTproxyMetrics>,
) -> BpfTproxyMetrics {
    values
        .into_iter()
        .fold(BpfTproxyMetrics::default(), |mut total, value| {
            total.sk_assign_failure_total = total
                .sk_assign_failure_total
                .saturating_add(value.sk_assign_failure_total);
            total.redirect_prep_store_failure_total = total
                .redirect_prep_store_failure_total
                .saturating_add(value.redirect_prep_store_failure_total);
            total.redirect_restore_store_failure_total = total
                .redirect_restore_store_failure_total
                .saturating_add(value.redirect_restore_store_failure_total);
            total
        })
}
