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
    Ok(values
        .iter()
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
        }))
}
