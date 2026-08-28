use super::*;

const DEFAULT_ACTIVE_WINDOW_LIMIT: usize = 16;
const DEFAULT_RETAINED_SESSION_LIMIT: usize = 64;
const DEFAULT_ESTIMATED_BYTE_LIMIT: usize = 64 * 1024;
const HASH_ENTRY_ESTIMATED_OVERHEAD: usize = 2 * std::mem::size_of::<usize>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ss2022UdpReplayPolicy {
    window_size: usize,
    active_window_limit: usize,
    retained_session_limit: usize,
    estimated_byte_limit: usize,
    retention_secs: u64,
}

impl Default for Ss2022UdpReplayPolicy {
    fn default() -> Self {
        Self {
            window_size: UDP_REPLAY_WINDOW_SIZE,
            active_window_limit: DEFAULT_ACTIVE_WINDOW_LIMIT,
            retained_session_limit: DEFAULT_RETAINED_SESSION_LIMIT,
            estimated_byte_limit: DEFAULT_ESTIMATED_BYTE_LIMIT,
            retention_secs: SERVER_SESSION_RETENTION_SECS,
        }
    }
}

impl Ss2022UdpReplayPolicy {
    pub fn new(
        window_size: usize,
        active_window_limit: usize,
        retained_session_limit: usize,
        estimated_byte_limit: usize,
        retention_secs: u64,
    ) -> Result<Self, OutboundError> {
        let policy = Self {
            window_size,
            active_window_limit,
            retained_session_limit,
            estimated_byte_limit,
            retention_secs,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn window_size(self) -> usize {
        self.window_size
    }

    pub fn active_window_limit(self) -> usize {
        self.active_window_limit
    }

    pub fn retained_session_limit(self) -> usize {
        self.retained_session_limit
    }

    pub fn estimated_byte_limit(self) -> usize {
        self.estimated_byte_limit
    }

    pub fn retention_secs(self) -> u64 {
        self.retention_secs
    }

    pub fn estimated_active_window_bytes(self) -> usize {
        active_window_charge(self.window_size)
    }

    fn validate(self) -> Result<(), OutboundError> {
        if self.window_size == 0 {
            return Err(invalid_policy("replay window size must be non-zero"));
        }
        if self.active_window_limit == 0 {
            return Err(invalid_policy(
                "active replay window limit must be non-zero",
            ));
        }
        if self.retained_session_limit < self.active_window_limit {
            return Err(invalid_policy(
                "retained session limit must cover active replay windows",
            ));
        }
        if self.retention_secs == 0 {
            return Err(invalid_policy("server session retention must be non-zero"));
        }
        if self.estimated_byte_limit < active_window_charge(self.window_size) {
            return Err(invalid_policy(
                "estimated byte limit cannot hold one replay window",
            ));
        }
        Ok(())
    }
}

pub use dae_core_types::Ss2022UdpReplayMetricsSnapshot;

#[derive(Debug)]
struct ActiveReplayWindow {
    filter: SlidingWindowFilter,
    last_valid_at: u64,
    last_access_order: u64,
}

#[derive(Debug)]
struct QuarantinedSession {
    retired_at: u64,
}

#[derive(Debug)]
pub(super) struct Ss2022UdpReplayTable {
    policy: Ss2022UdpReplayPolicy,
    active: HashMap<[u8; 8], ActiveReplayWindow>,
    quarantined: HashMap<[u8; 8], QuarantinedSession>,
    access_order: u64,
    metrics: Ss2022UdpReplayMetricsSnapshot,
}

impl Default for Ss2022UdpReplayTable {
    fn default() -> Self {
        Self::from_valid_policy(Ss2022UdpReplayPolicy::default())
    }
}

impl Ss2022UdpReplayTable {
    pub(super) fn new(policy: Ss2022UdpReplayPolicy) -> Result<Self, OutboundError> {
        policy.validate()?;
        Ok(Self::from_valid_policy(policy))
    }

    fn from_valid_policy(policy: Ss2022UdpReplayPolicy) -> Self {
        Self {
            policy,
            active: HashMap::new(),
            quarantined: HashMap::new(),
            access_order: 0,
            metrics: Ss2022UdpReplayMetricsSnapshot::default(),
        }
    }

    pub(super) fn check(
        &mut self,
        session_id: [u8; 8],
        packet_id: u64,
        now: u64,
    ) -> Result<(), OutboundError> {
        self.expire(now);
        self.access_order = self.access_order.saturating_add(1);

        if let Some(window) = self.active.get_mut(&session_id) {
            if !window.filter.check_and_update(packet_id) {
                self.metrics.replay_rejections = self.metrics.replay_rejections.saturating_add(1);
                return Err(replay_error());
            }
            window.last_valid_at = now;
            window.last_access_order = self.access_order;
            return Ok(());
        }

        if self.quarantined.contains_key(&session_id) {
            self.metrics.replay_rejections = self.metrics.replay_rejections.saturating_add(1);
            return Err(replay_error());
        }

        let evicted_session = if self.active.len() >= self.policy.active_window_limit {
            self.active
                .iter()
                .min_by_key(|(session, window)| (window.last_access_order, **session))
                .map(|(session, _)| *session)
        } else {
            None
        };
        let projected_active = self.active.len() + usize::from(evicted_session.is_none());
        let projected_quarantined = self.quarantined.len() + usize::from(evicted_session.is_some());
        let projected_retained = projected_active.saturating_add(projected_quarantined);
        let projected_bytes = estimated_table_bytes(
            self.policy.window_size,
            projected_active,
            projected_quarantined,
        );
        if projected_retained > self.policy.retained_session_limit
            || projected_bytes > self.policy.estimated_byte_limit
        {
            self.metrics.saturation_rejections =
                self.metrics.saturation_rejections.saturating_add(1);
            self.refresh_current_metrics();
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP replay state is saturated".to_owned(),
            ));
        }

        if let Some(evicted_session) = evicted_session {
            let removed = self.active.remove(&evicted_session);
            debug_assert!(removed.is_some());
            self.quarantined
                .insert(evicted_session, QuarantinedSession { retired_at: now });
            self.metrics.lru_evictions = self.metrics.lru_evictions.saturating_add(1);
        }

        let mut filter = SlidingWindowFilter::new(self.policy.window_size);
        let accepted = filter.check_and_update(packet_id);
        debug_assert!(accepted);
        self.active.insert(
            session_id,
            ActiveReplayWindow {
                filter,
                last_valid_at: now,
                last_access_order: self.access_order,
            },
        );
        self.refresh_current_metrics();
        Ok(())
    }

    pub(super) fn expire(&mut self, now: u64) {
        let active_before = self.active.len();
        self.active.retain(|_, window| {
            now.saturating_sub(window.last_valid_at) < self.policy.retention_secs
        });
        let quarantined_before = self.quarantined.len();
        self.quarantined.retain(|_, session| {
            now.saturating_sub(session.retired_at) < self.policy.retention_secs
        });
        let expired = active_before
            .saturating_sub(self.active.len())
            .saturating_add(quarantined_before.saturating_sub(self.quarantined.len()));
        if expired > 0 {
            self.active.shrink_to_fit();
            self.quarantined.shrink_to_fit();
        }
        self.metrics.ttl_expirations = self.metrics.ttl_expirations.saturating_add(expired as u64);
        self.refresh_current_metrics();
    }

    pub(super) fn metrics_snapshot(&self) -> Ss2022UdpReplayMetricsSnapshot {
        self.metrics
    }

    fn refresh_current_metrics(&mut self) {
        self.metrics.active_windows = self.active.len();
        self.metrics.quarantined_sessions = self.quarantined.len();
        self.metrics.retained_sessions = self.active.len().saturating_add(self.quarantined.len());
        self.metrics.estimated_bytes = estimated_table_bytes(
            self.policy.window_size,
            self.active.len(),
            self.quarantined.len(),
        );
        self.metrics.high_water_retained_sessions = self
            .metrics
            .high_water_retained_sessions
            .max(self.metrics.retained_sessions);
        self.metrics.high_water_estimated_bytes = self
            .metrics
            .high_water_estimated_bytes
            .max(self.metrics.estimated_bytes);
    }
}

fn active_window_charge(window_size: usize) -> usize {
    let bitmap_bytes = window_size
        .div_ceil(u64::BITS as usize)
        .saturating_mul(std::mem::size_of::<u64>());
    std::mem::size_of::<([u8; 8], ActiveReplayWindow)>()
        .saturating_add(bitmap_bytes)
        .saturating_add(HASH_ENTRY_ESTIMATED_OVERHEAD)
}

fn quarantined_session_charge() -> usize {
    std::mem::size_of::<([u8; 8], QuarantinedSession)>()
        .saturating_add(HASH_ENTRY_ESTIMATED_OVERHEAD)
}

fn estimated_table_bytes(
    window_size: usize,
    active_windows: usize,
    quarantined_sessions: usize,
) -> usize {
    active_windows
        .saturating_mul(active_window_charge(window_size))
        .saturating_add(quarantined_sessions.saturating_mul(quarantined_session_charge()))
}

fn invalid_policy(message: &str) -> OutboundError {
    OutboundError::BadShadowsocks(format!("invalid SS2022 UDP replay policy: {message}"))
}

fn replay_error() -> OutboundError {
    OutboundError::BadShadowsocks("SS2022 UDP replay attack detected".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn policy(
        window_size: usize,
        active: usize,
        retained: usize,
        bytes: usize,
        ttl: u64,
    ) -> Ss2022UdpReplayPolicy {
        Ss2022UdpReplayPolicy::new(window_size, active, retained, bytes, ttl).unwrap()
    }

    #[test]
    fn bitmap_accepts_reordering_once_and_handles_u64_edges() {
        let mut filter = SlidingWindowFilter::new(65);
        assert!(filter.check_and_update(u64::MAX - 1));
        assert!(filter.check_and_update(u64::MAX));
        assert!(filter.check_and_update(u64::MAX - 2));
        assert!(!filter.check_and_update(u64::MAX - 2));
        assert!(!filter.check_and_update(u64::MAX - 65));

        let mut jump = SlidingWindowFilter::new(17);
        assert!(jump.check_and_update(1));
        assert!(jump.check_and_update(u64::MAX));
        assert!(!jump.check_and_update(u64::MAX - 17));
        assert!(jump.check_and_update(u64::MAX - 16));
    }

    #[test]
    fn bitmap_matches_the_packet_window_contract_for_arbitrary_sizes() {
        let sequence = [
            10,
            9,
            10,
            11,
            8,
            75,
            74,
            12,
            76,
            u64::MAX - 1,
            u64::MAX,
            u64::MAX - 2,
            u64::MAX - 1,
        ];
        for window_size in [1, 2, 7, 63, 64, 65, 127] {
            let mut bitmap = SlidingWindowFilter::new(window_size);
            let mut latest = None;
            let mut seen = HashSet::new();
            for packet_id in sequence {
                let expected = match latest {
                    None => {
                        latest = Some(packet_id);
                        seen.insert(packet_id);
                        true
                    }
                    Some(current_latest)
                        if packet_id <= current_latest
                            && current_latest - packet_id >= window_size as u64 =>
                    {
                        false
                    }
                    Some(_) if seen.contains(&packet_id) => false,
                    Some(current_latest) => {
                        if packet_id > current_latest {
                            latest = Some(packet_id);
                            seen.retain(|seen_id| packet_id - *seen_id < window_size as u64);
                        }
                        seen.insert(packet_id);
                        true
                    }
                };
                assert_eq!(
                    bitmap.check_and_update(packet_id),
                    expected,
                    "window={window_size} packet={packet_id}"
                );
            }
        }
    }

    #[test]
    fn lru_eviction_quarantines_old_session_and_saturates_without_growth() {
        let one_window = active_window_charge(64);
        let tombstone = quarantined_session_charge();
        let mut table =
            Ss2022UdpReplayTable::new(policy(64, 2, 3, one_window * 2 + tombstone, 60)).unwrap();
        assert!(table.check(*b"session1", 0, 1).is_ok());
        assert!(table.check(*b"session2", 0, 2).is_ok());
        assert!(table.check(*b"session1", 1, 3).is_ok());
        assert!(table.check(*b"session3", 0, 4).is_ok());
        assert!(table.check(*b"session2", 1, 5).is_err());
        assert!(table.check(*b"session4", 0, 5).is_err());

        let snapshot = table.metrics_snapshot();
        assert_eq!(snapshot.active_windows, 2);
        assert_eq!(snapshot.quarantined_sessions, 1);
        assert_eq!(snapshot.retained_sessions, 3);
        assert_eq!(snapshot.lru_evictions, 1);
        assert_eq!(snapshot.replay_rejections, 1);
        assert_eq!(snapshot.saturation_rejections, 1);
        assert_eq!(snapshot.estimated_bytes, one_window * 2 + tombstone);
    }

    #[test]
    fn byte_budget_can_saturate_before_retained_count() {
        let one_window = active_window_charge(64);
        let mut table = Ss2022UdpReplayTable::new(policy(64, 4, 8, one_window * 2, 60)).unwrap();
        assert!(table.check(*b"session1", 0, 1).is_ok());
        assert!(table.check(*b"session2", 0, 1).is_ok());
        assert!(table.check(*b"session3", 0, 1).is_err());
        let snapshot = table.metrics_snapshot();
        assert_eq!(snapshot.retained_sessions, 2);
        assert_eq!(snapshot.saturation_rejections, 1);
        assert!(snapshot.estimated_bytes <= one_window * 2);
    }

    #[test]
    fn expiration_recovers_capacity_deterministically() {
        let one_window = active_window_charge(64);
        let mut table = Ss2022UdpReplayTable::new(policy(64, 1, 1, one_window, 10)).unwrap();
        assert!(table.check(*b"session1", 7, 5).is_ok());
        assert!(table.check(*b"session2", 0, 14).is_err());
        assert!(table.check(*b"session2", 0, 15).is_ok());
        let snapshot = table.metrics_snapshot();
        assert_eq!(snapshot.retained_sessions, 1);
        assert_eq!(snapshot.ttl_expirations, 1);
        assert_eq!(snapshot.saturation_rejections, 1);
    }

    #[test]
    fn policy_rejects_unusable_limits() {
        assert!(Ss2022UdpReplayPolicy::new(0, 1, 1, 1024, 1).is_err());
        assert!(Ss2022UdpReplayPolicy::new(64, 0, 1, 1024, 1).is_err());
        assert!(Ss2022UdpReplayPolicy::new(64, 2, 1, 1024, 1).is_err());
        assert!(Ss2022UdpReplayPolicy::new(64, 1, 1, 1, 1).is_err());
        assert!(Ss2022UdpReplayPolicy::new(64, 1, 1, 1024, 0).is_err());
    }
}
