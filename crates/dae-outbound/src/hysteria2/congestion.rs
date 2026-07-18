use std::any::Any;
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use quinn::congestion::{
    Bbr, BbrConfig, Controller, ControllerFactory, ControllerMetrics, NewReno, NewRenoConfig,
};
use quinn_proto::RttEstimator;

use crate::error::OutboundError;

const BRUTAL_SAMPLE_SECONDS: usize = 5;
const BRUTAL_MINIMUM_SAMPLE_PACKETS: u64 = 50;
const BRUTAL_MINIMUM_ACK_RATE: f64 = 0.8;
const BRUTAL_INITIAL_WINDOW_BYTES: u64 = 10_240;
const QUINN_PACING_NUMERATOR: u64 = 5;
const QUINN_PACING_DENOMINATOR: u64 = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Hysteria2CongestionController {
    #[default]
    Bbr,
    Reno,
}

impl Hysteria2CongestionController {
    pub fn parse(value: &str) -> Result<Self, OutboundError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "bbr" => Ok(Self::Bbr),
            "reno" => Ok(Self::Reno),
            _ => Err(bad_congestion(
                "unsupported Hysteria2 congestion controller",
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Reno => "reno",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Hysteria2BbrProfile {
    #[default]
    Standard,
    Conservative,
    Aggressive,
}

impl Hysteria2BbrProfile {
    pub fn parse(value: &str) -> Result<Self, OutboundError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "standard" => Ok(Self::Standard),
            "conservative" => Ok(Self::Conservative),
            "aggressive" => Ok(Self::Aggressive),
            _ => Err(bad_congestion("unsupported Hysteria2 BBR profile")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Conservative => "conservative",
            Self::Aggressive => "aggressive",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hysteria2CongestionConfig {
    pub controller: Hysteria2CongestionController,
    pub bbr_profile: Hysteria2BbrProfile,
    pub disable_loss_compensation: bool,
}

impl Hysteria2CongestionConfig {
    pub fn new(
        controller: &str,
        bbr_profile: &str,
        disable_loss_compensation: bool,
    ) -> Result<Self, OutboundError> {
        let controller = Hysteria2CongestionController::parse(controller)?;
        let bbr_profile = Hysteria2BbrProfile::parse(bbr_profile)?;
        if controller == Hysteria2CongestionController::Reno
            && bbr_profile != Hysteria2BbrProfile::Standard
        {
            return Err(bad_congestion(
                "Hysteria2 BBR profile cannot be combined with Reno",
            ));
        }
        Ok(Self {
            controller,
            bbr_profile,
            disable_loss_compensation,
        })
    }

    pub fn validate_quinn(self) -> Result<Self, OutboundError> {
        if self.controller == Hysteria2CongestionController::Bbr
            && self.bbr_profile != Hysteria2BbrProfile::Standard
        {
            return Err(bad_congestion(
                "the Quinn Hysteria2 provider supports only the standard BBR profile",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Hysteria2ServerBandwidthResponse {
    #[default]
    Pending,
    Auto,
    Unlimited,
    Known,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hysteria2EffectiveCongestionController {
    Brutal,
    Bbr,
    Reno,
}

impl Hysteria2EffectiveCongestionController {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Brutal => "brutal",
            Self::Bbr => "bbr",
            Self::Reno => "reno",
        }
    }
}

impl Hysteria2ServerBandwidthResponse {
    const fn code(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Auto => 1,
            Self::Unlimited => 2,
            Self::Known => 3,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Auto,
            2 => Self::Unlimited,
            3 => Self::Known,
            _ => Self::Pending,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Auto => "auto",
            Self::Unlimited => "zero",
            Self::Known => "known",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hysteria2CongestionNegotiation {
    pub max_tx: u64,
    pub max_rx: u64,
    pub server_response: Hysteria2ServerBandwidthResponse,
    pub server_rx: u64,
    pub effective_tx: u64,
    pub controller: Hysteria2EffectiveCongestionController,
    pub profile: Hysteria2BbrProfile,
    pub loss_compensation: bool,
}

#[derive(Debug)]
struct Hysteria2CongestionState {
    server_response: AtomicU8,
    server_rx: AtomicU64,
    effective_tx: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct Hysteria2CongestionRuntime {
    config: Hysteria2CongestionConfig,
    max_tx: u64,
    max_rx: u64,
    state: Arc<Hysteria2CongestionState>,
}

impl Hysteria2CongestionRuntime {
    pub fn new(
        config: Hysteria2CongestionConfig,
        max_tx: u64,
        max_rx: u64,
    ) -> Result<Self, OutboundError> {
        Ok(Self {
            config: config.validate_quinn()?,
            max_tx,
            max_rx,
            state: Arc::new(Hysteria2CongestionState {
                server_response: AtomicU8::new(Hysteria2ServerBandwidthResponse::Pending.code()),
                server_rx: AtomicU64::new(0),
                effective_tx: AtomicU64::new(0),
            }),
        })
    }

    pub const fn requested_rx(&self) -> u64 {
        self.max_rx
    }

    pub fn apply_server_response(&self, rx_auto: bool, server_rx: u64) {
        let response = if rx_auto {
            Hysteria2ServerBandwidthResponse::Auto
        } else if server_rx == 0 {
            Hysteria2ServerBandwidthResponse::Unlimited
        } else {
            Hysteria2ServerBandwidthResponse::Known
        };
        let effective_tx = if rx_auto {
            0
        } else if server_rx == 0 || server_rx > self.max_tx {
            self.max_tx
        } else {
            server_rx
        };
        self.state.server_rx.store(server_rx, Ordering::Relaxed);
        self.state
            .effective_tx
            .store(effective_tx, Ordering::Release);
        self.state
            .server_response
            .store(response.code(), Ordering::Release);
    }

    pub fn negotiation(&self) -> Hysteria2CongestionNegotiation {
        let server_response = Hysteria2ServerBandwidthResponse::from_code(
            self.state.server_response.load(Ordering::Acquire),
        );
        let effective_tx = self.state.effective_tx.load(Ordering::Relaxed);
        Hysteria2CongestionNegotiation {
            max_tx: self.max_tx,
            max_rx: self.max_rx,
            server_response,
            server_rx: self.state.server_rx.load(Ordering::Relaxed),
            effective_tx,
            controller: if effective_tx > 0 {
                Hysteria2EffectiveCongestionController::Brutal
            } else {
                match self.config.controller {
                    Hysteria2CongestionController::Bbr => {
                        Hysteria2EffectiveCongestionController::Bbr
                    }
                    Hysteria2CongestionController::Reno => {
                        Hysteria2EffectiveCongestionController::Reno
                    }
                }
            },
            profile: self.config.bbr_profile,
            loss_compensation: effective_tx > 0 && !self.config.disable_loss_compensation,
        }
    }
}

impl ControllerFactory for Hysteria2CongestionRuntime {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let configured = match self.config.controller {
            Hysteria2CongestionController::Bbr => ConfiguredController::Bbr(Box::new(Bbr::new(
                Arc::new(BbrConfig::default()),
                current_mtu,
            ))),
            Hysteria2CongestionController::Reno => ConfiguredController::Reno(NewReno::new(
                Arc::new(NewRenoConfig::default()),
                now,
                current_mtu,
            )),
        };
        Box::new(Hysteria2CongestionControllerRuntime {
            runtime: self,
            configured,
            brutal: BrutalController::new(now, current_mtu),
        })
    }
}

#[derive(Clone)]
enum ConfiguredController {
    Bbr(Box<Bbr>),
    Reno(NewReno),
}

impl ConfiguredController {
    fn on_sent(&mut self, now: Instant, bytes: u64, packet: u64) {
        match self {
            Self::Bbr(controller) => controller.on_sent(now, bytes, packet),
            Self::Reno(controller) => controller.on_sent(now, bytes, packet),
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        match self {
            Self::Bbr(controller) => controller.on_ack(now, sent, bytes, app_limited, rtt),
            Self::Reno(controller) => controller.on_ack(now, sent, bytes, app_limited, rtt),
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        match self {
            Self::Bbr(controller) => {
                controller.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked)
            }
            Self::Reno(controller) => {
                controller.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked)
            }
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        persistent: bool,
        lost_bytes: u64,
    ) {
        match self {
            Self::Bbr(controller) => {
                controller.on_congestion_event(now, sent, persistent, lost_bytes)
            }
            Self::Reno(controller) => {
                controller.on_congestion_event(now, sent, persistent, lost_bytes)
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        match self {
            Self::Bbr(controller) => controller.on_mtu_update(new_mtu),
            Self::Reno(controller) => controller.on_mtu_update(new_mtu),
        }
    }

    fn window(&self) -> u64 {
        match self {
            Self::Bbr(controller) => controller.window(),
            Self::Reno(controller) => controller.window(),
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        match self {
            Self::Bbr(controller) => controller.metrics(),
            Self::Reno(controller) => controller.metrics(),
        }
    }

    fn initial_window(&self) -> u64 {
        match self {
            Self::Bbr(controller) => controller.initial_window(),
            Self::Reno(controller) => controller.initial_window(),
        }
    }
}

#[derive(Clone)]
struct Hysteria2CongestionControllerRuntime {
    runtime: Arc<Hysteria2CongestionRuntime>,
    configured: ConfiguredController,
    brutal: BrutalController,
}

impl Hysteria2CongestionControllerRuntime {
    fn brutal_enabled(&self) -> bool {
        self.runtime.state.effective_tx.load(Ordering::Acquire) > 0
    }
}

impl Controller for Hysteria2CongestionControllerRuntime {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        if self.brutal_enabled() {
            self.brutal.on_sent(now, bytes);
        } else {
            self.configured.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if self.brutal_enabled() {
            self.brutal.on_ack(now, bytes, rtt);
        } else {
            self.configured.on_ack(now, sent, bytes, app_limited, rtt);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if self.brutal_enabled() {
            self.brutal
                .update_ack_rate(now, self.runtime.config.disable_loss_compensation);
        } else {
            self.configured
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if self.brutal_enabled() {
            self.brutal.on_loss(now, lost_bytes);
        } else {
            self.configured
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.configured.on_mtu_update(new_mtu);
        self.brutal.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        let target = self.runtime.state.effective_tx.load(Ordering::Acquire);
        if target > 0 {
            self.brutal.window(target)
        } else {
            self.configured.window()
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let target = self.runtime.state.effective_tx.load(Ordering::Acquire);
        if target == 0 {
            return self.configured.metrics();
        }
        let compensated = self.brutal.compensated_rate(target);
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.brutal.window(target);
        metrics.pacing_rate = Some(compensated.saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.configured.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Clone, Copy, Debug)]
struct BrutalSample {
    second: u64,
    acknowledgements: u64,
    losses: u64,
}

#[derive(Clone)]
struct BrutalController {
    origin: Instant,
    mtu: u16,
    smoothed_rtt: Duration,
    samples: [BrutalSample; BRUTAL_SAMPLE_SECONDS],
    acknowledgement_rate: f64,
}

impl BrutalController {
    fn new(origin: Instant, mtu: u16) -> Self {
        Self {
            origin,
            mtu,
            smoothed_rtt: Duration::ZERO,
            samples: [BrutalSample {
                second: u64::MAX,
                acknowledgements: 0,
                losses: 0,
            }; BRUTAL_SAMPLE_SECONDS],
            acknowledgement_rate: 1.0,
        }
    }

    fn on_sent(&mut self, _now: Instant, _bytes: u64) {}

    fn on_ack(&mut self, now: Instant, bytes: u64, rtt: &RttEstimator) {
        self.smoothed_rtt = rtt.get();
        let packets = packet_count(bytes, self.mtu);
        let sample = self.sample_mut(now);
        sample.acknowledgements = sample.acknowledgements.saturating_add(packets);
    }

    fn on_loss(&mut self, now: Instant, bytes: u64) {
        let packets = packet_count(bytes, self.mtu);
        let sample = self.sample_mut(now);
        sample.losses = sample.losses.saturating_add(packets);
    }

    fn sample_mut(&mut self, now: Instant) -> &mut BrutalSample {
        let second = now
            .checked_duration_since(self.origin)
            .unwrap_or_default()
            .as_secs();
        let slot = second as usize % BRUTAL_SAMPLE_SECONDS;
        if self.samples[slot].second != second {
            self.samples[slot] = BrutalSample {
                second,
                acknowledgements: 0,
                losses: 0,
            };
        }
        &mut self.samples[slot]
    }

    fn update_ack_rate(&mut self, now: Instant, disable_loss_compensation: bool) {
        if disable_loss_compensation {
            self.acknowledgement_rate = 1.0;
            return;
        }
        let current = now
            .checked_duration_since(self.origin)
            .unwrap_or_default()
            .as_secs();
        let earliest = current.saturating_sub(BRUTAL_SAMPLE_SECONDS as u64);
        let (acknowledgements, losses) = self.samples.iter().fold((0_u64, 0_u64), |sum, sample| {
            if sample.second < earliest || sample.second > current {
                sum
            } else {
                (
                    sum.0.saturating_add(sample.acknowledgements),
                    sum.1.saturating_add(sample.losses),
                )
            }
        });
        let total = acknowledgements.saturating_add(losses);
        self.acknowledgement_rate = if total < BRUTAL_MINIMUM_SAMPLE_PACKETS {
            1.0
        } else {
            ((acknowledgements as f64) / (total as f64)).max(BRUTAL_MINIMUM_ACK_RATE)
        };
    }

    fn compensated_rate(&self, target: u64) -> u64 {
        ((target as f64) / self.acknowledgement_rate).min(u64::MAX as f64) as u64
    }

    fn window(&self, target: u64) -> u64 {
        if self.smoothed_rtt.is_zero() {
            return BRUTAL_INITIAL_WINDOW_BYTES.max(u64::from(self.mtu));
        }
        let compensated = u128::from(self.compensated_rate(target));
        let window = compensated
            .saturating_mul(self.smoothed_rtt.as_nanos())
            .saturating_mul(u128::from(QUINN_PACING_DENOMINATOR))
            / 1_000_000_000_u128
            / u128::from(QUINN_PACING_NUMERATOR);
        u64::try_from(window)
            .unwrap_or(u64::MAX)
            .max(u64::from(self.mtu))
    }
}

fn packet_count(bytes: u64, mtu: u16) -> u64 {
    let mtu = u64::from(mtu).max(1);
    bytes.saturating_add(mtu - 1) / mtu
}

pub fn parse_hysteria2_bandwidth(value: &str) -> Result<u64, OutboundError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(bad_congestion("empty Hysteria2 bandwidth"));
    }
    let split = normalized
        .char_indices()
        .find_map(|(index, character)| (!character.is_ascii_digit()).then_some(index));
    let Some(split) = split else {
        return normalized
            .parse::<u64>()
            .map_err(|_| bad_congestion("invalid Hysteria2 bandwidth"));
    };
    if split == 0 {
        return Err(bad_congestion("invalid Hysteria2 bandwidth"));
    }
    let value = normalized[..split]
        .parse::<u64>()
        .map_err(|_| bad_congestion("invalid Hysteria2 bandwidth"))?;
    let multiplier = match normalized[split..].trim() {
        "b" | "bps" => 1_u64,
        "k" | "kb" | "kbps" => 1_000,
        "m" | "mb" | "mbps" => 1_000_000,
        "g" | "gb" | "gbps" => 1_000_000_000,
        "t" | "tb" | "tbps" => 1_000_000_000_000,
        _ => return Err(bad_congestion("unsupported Hysteria2 bandwidth unit")),
    };
    value
        .checked_mul(multiplier)
        .map(|bits| bits / 8)
        .ok_or_else(|| bad_congestion("Hysteria2 bandwidth exceeds u64"))
}

fn bad_congestion(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_parser_accepts_dae_units_and_raw_bytes_per_second() {
        assert_eq!(parse_hysteria2_bandwidth("0").unwrap(), 0);
        assert_eq!(parse_hysteria2_bandwidth("25000000").unwrap(), 25_000_000);
        assert_eq!(parse_hysteria2_bandwidth("200 mbps").unwrap(), 25_000_000);
        assert_eq!(parse_hysteria2_bandwidth("1 gbps").unwrap(), 125_000_000);
        assert!(parse_hysteria2_bandwidth("1.5 gbps").is_err());
        assert!(parse_hysteria2_bandwidth("10 unknown").is_err());
    }

    #[test]
    fn server_response_negotiates_auto_zero_and_known_bandwidth() {
        let runtime =
            Hysteria2CongestionRuntime::new(Hysteria2CongestionConfig::default(), 100_000, 200_000)
                .unwrap();
        assert_eq!(runtime.requested_rx(), 200_000);

        runtime.apply_server_response(false, 60_000);
        let known = runtime.negotiation();
        assert_eq!(
            known.server_response,
            Hysteria2ServerBandwidthResponse::Known
        );
        assert_eq!(known.effective_tx, 60_000);
        assert_eq!(
            known.controller,
            Hysteria2EffectiveCongestionController::Brutal
        );

        runtime.apply_server_response(false, 0);
        let unlimited = runtime.negotiation();
        assert_eq!(
            unlimited.server_response,
            Hysteria2ServerBandwidthResponse::Unlimited
        );
        assert_eq!(unlimited.effective_tx, 100_000);

        runtime.apply_server_response(true, 80_000);
        let automatic = runtime.negotiation();
        assert_eq!(
            automatic.server_response,
            Hysteria2ServerBandwidthResponse::Auto
        );
        assert_eq!(automatic.effective_tx, 0);
        assert_eq!(
            automatic.controller,
            Hysteria2EffectiveCongestionController::Bbr
        );
    }

    #[test]
    fn max_rx_only_and_max_tx_only_remain_distinct() {
        let max_rx_only =
            Hysteria2CongestionRuntime::new(Hysteria2CongestionConfig::default(), 0, 200_000)
                .unwrap();
        max_rx_only.apply_server_response(false, 50_000);
        assert_eq!(max_rx_only.requested_rx(), 200_000);
        assert_eq!(max_rx_only.negotiation().effective_tx, 0);
        assert_eq!(
            max_rx_only.negotiation().controller,
            Hysteria2EffectiveCongestionController::Bbr
        );

        let max_tx_only = Hysteria2CongestionRuntime::new(
            Hysteria2CongestionConfig {
                controller: Hysteria2CongestionController::Reno,
                ..Hysteria2CongestionConfig::default()
            },
            100_000,
            0,
        )
        .unwrap();
        max_tx_only.apply_server_response(false, 0);
        assert_eq!(max_tx_only.requested_rx(), 0);
        assert_eq!(max_tx_only.negotiation().effective_tx, 100_000);
        assert_eq!(
            max_tx_only.negotiation().controller,
            Hysteria2EffectiveCongestionController::Brutal
        );
    }

    #[test]
    fn unsupported_quinn_bbr_profiles_fail_before_transport_construction() {
        let error = Hysteria2CongestionRuntime::new(
            Hysteria2CongestionConfig {
                bbr_profile: Hysteria2BbrProfile::Aggressive,
                ..Hysteria2CongestionConfig::default()
            },
            0,
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("only the standard BBR profile"));
    }

    #[test]
    fn brutal_window_tracks_target_rate_and_bounded_loss_compensation() {
        let now = Instant::now();
        let mut controller = BrutalController::new(now, 1_200);
        controller.smoothed_rtt = Duration::from_millis(100);
        assert_eq!(controller.window(1_000_000), 80_000);

        controller.samples[0] = BrutalSample {
            second: 0,
            acknowledgements: 40,
            losses: 10,
        };
        controller.update_ack_rate(now, false);
        assert_eq!(controller.acknowledgement_rate, BRUTAL_MINIMUM_ACK_RATE);
        assert_eq!(controller.compensated_rate(1_000_000), 1_250_000);
        assert_eq!(controller.window(1_000_000), 100_000);

        controller.update_ack_rate(now, true);
        assert_eq!(controller.acknowledgement_rate, 1.0);
        assert_eq!(controller.window(1_000_000), 80_000);
    }
}
