use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use crate::production_runtime_owner::resident_dataplane::ResidentDnsTcpUdpHedgeProfile;
#[cfg(test)]
use crate::production_runtime_owner::resident_dataplane::{
    ResidentDnsResourceProfile, ResidentRuntimeProfile,
};

const DNS_TCP_UDP_HEDGE_ENTRY_COUNT: usize = (u8::MAX as usize) + 1;
const DNS_TCP_UDP_HEDGE_SMOOTHING_SHIFT: u32 = 3;
const DNS_TCP_UDP_HEDGE_NORMAL_DEVIATIONS: u64 = 2;
const DNS_TCP_UDP_HEDGE_IMMEDIATE_FAILURES: u32 = 2;

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsTcpUdpHedgeRegistry
{
    entries: Box<[ResidentDnsTcpUdpHedgeState]>,
}

struct ResidentDnsTcpUdpHedgeState {
    latency: AtomicU64,
    samples: AtomicU32,
    degraded_hedges: AtomicU32,
}

impl Default for ResidentDnsTcpUdpHedgeRegistry {
    fn default() -> Self {
        let entries = (0..DNS_TCP_UDP_HEDGE_ENTRY_COUNT)
            .map(|_| ResidentDnsTcpUdpHedgeState::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { entries }
    }
}

impl Default for ResidentDnsTcpUdpHedgeState {
    fn default() -> Self {
        Self {
            latency: AtomicU64::new(0),
            samples: AtomicU32::new(0),
            degraded_hedges: AtomicU32::new(0),
        }
    }
}

impl ResidentDnsTcpUdpHedgeRegistry {
    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn delay(
        &self,
        upstream_index: u8,
        profile: ResidentDnsTcpUdpHedgeProfile,
    ) -> Duration {
        self.entries[usize::from(upstream_index)].delay(profile)
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn record_udp_success(
        &self,
        upstream_index: u8,
        elapsed: Duration,
        profile: ResidentDnsTcpUdpHedgeProfile,
    ) {
        self.entries[usize::from(upstream_index)].record_udp_success(elapsed, profile);
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) fn record_udp_failure(
        &self,
        upstream_index: u8,
    ) {
        self.entries[usize::from(upstream_index)].record_udp_failure();
    }
}

impl ResidentDnsTcpUdpHedgeState {
    fn delay(&self, profile: ResidentDnsTcpUdpHedgeProfile) -> Duration {
        let degraded_hedges = self
            .degraded_hedges
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                Some(remaining.saturating_sub(1))
            })
            .unwrap_or_default();
        match degraded_hedges {
            DNS_TCP_UDP_HEDGE_IMMEDIATE_FAILURES.. => return Duration::ZERO,
            1 => return profile.minimum_delay(),
            _ => {}
        }
        if self.samples.load(Ordering::Relaxed) < profile.learning_samples() {
            return profile.initial_delay();
        }
        let latency = self.latency.load(Ordering::Relaxed);
        let (mean_micros, deviation_micros) = unpack_latency(latency);
        if mean_micros == 0 {
            return profile.initial_delay();
        }
        let normal_upper_micros = u64::from(mean_micros).saturating_add(
            u64::from(deviation_micros).saturating_mul(DNS_TCP_UDP_HEDGE_NORMAL_DEVIATIONS),
        );
        Duration::from_micros(normal_upper_micros)
            .clamp(profile.minimum_delay(), profile.maximum_delay())
    }

    fn record_udp_success(&self, elapsed: Duration, profile: ResidentDnsTcpUdpHedgeProfile) {
        if elapsed > profile.maximum_delay() {
            self.record_udp_failure();
            return;
        }
        self.degraded_hedges.store(0, Ordering::Relaxed);
        let sample_micros = elapsed.as_micros().clamp(1, u128::from(u32::MAX)) as u32;
        let mut current = self.latency.load(Ordering::Relaxed);
        loop {
            let (mean_micros, deviation_micros) = unpack_latency(current);
            let (next_mean_micros, next_deviation_micros) = if mean_micros == 0 {
                (sample_micros, 0)
            } else {
                let sample_deviation = mean_micros.abs_diff(sample_micros);
                (
                    smooth_value(mean_micros, sample_micros),
                    smooth_value(deviation_micros, sample_deviation),
                )
            };
            let next = pack_latency(next_mean_micros, next_deviation_micros);
            match self.latency.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        let learning_samples = profile.learning_samples();
        let _ = self
            .samples
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |samples| {
                Some(samples.saturating_add(1).min(learning_samples))
            });
    }

    fn record_udp_failure(&self) {
        let _ =
            self.degraded_hedges
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |failures| {
                    Some(
                        failures
                            .saturating_add(1)
                            .min(DNS_TCP_UDP_HEDGE_IMMEDIATE_FAILURES),
                    )
                });
    }
}

fn smooth_value(current: u32, sample: u32) -> u32 {
    let delta = current.abs_diff(sample);
    let rounding = (1_u32 << DNS_TCP_UDP_HEDGE_SMOOTHING_SHIFT) - 1;
    let step = delta.saturating_add(rounding) >> DNS_TCP_UDP_HEDGE_SMOOTHING_SHIFT;
    if sample >= current {
        current.saturating_add(step)
    } else {
        current.saturating_sub(step)
    }
}

fn pack_latency(mean_micros: u32, deviation_micros: u32) -> u64 {
    (u64::from(mean_micros) << u32::BITS) | u64::from(deviation_micros)
}

fn unpack_latency(value: u64) -> (u32, u32) {
    ((value >> u32::BITS) as u32, value as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn balanced_profile() -> ResidentDnsTcpUdpHedgeProfile {
        ResidentDnsResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced)
            .tcp_udp_hedge()
    }

    #[test]
    fn tcp_udp_hedge_uses_profile_initial_delay_until_learning_is_bounded() {
        let registry = ResidentDnsTcpUdpHedgeRegistry::default();
        let profile = balanced_profile();

        assert_eq!(registry.delay(7, profile), Duration::from_millis(400));
        for _ in 0..profile.learning_samples() {
            registry.record_udp_success(7, Duration::from_millis(10), profile);
        }
        assert_eq!(registry.delay(7, profile), Duration::from_millis(300));
    }

    #[test]
    fn tcp_udp_hedge_tracks_the_upper_normal_latency_without_exceeding_profile_bounds() {
        let registry = ResidentDnsTcpUdpHedgeRegistry::default();
        let profile = balanced_profile();

        for sample_millis in [320, 350, 380, 410].into_iter().cycle().take(32) {
            registry.record_udp_success(11, Duration::from_millis(sample_millis), profile);
        }
        let delay = registry.delay(11, profile);
        assert!(delay >= Duration::from_millis(350), "{delay:?}");
        assert!(delay <= profile.maximum_delay(), "{delay:?}");
    }

    #[test]
    fn tcp_udp_hedge_does_not_train_on_retry_scale_successes() {
        let registry = ResidentDnsTcpUdpHedgeRegistry::default();
        let profile = balanced_profile();

        for _ in 0..profile.learning_samples() {
            registry.record_udp_success(19, Duration::from_millis(350), profile);
        }
        registry.record_udp_success(19, Duration::from_secs(2), profile);
        registry.record_udp_success(19, Duration::from_secs(2), profile);
        assert_eq!(registry.delay(19, profile), Duration::ZERO);
        assert_eq!(registry.delay(19, profile), profile.minimum_delay());
        assert!(registry.delay(19, profile) >= Duration::from_millis(350));
    }
}
