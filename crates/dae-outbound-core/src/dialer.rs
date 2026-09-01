use crate::alive::AliveDialerSet;
use crate::latency::LatenciesN;
use crate::types::{NETWORK_TYPE_COLLECTION_COUNT, NetworkType};
use std::sync::Arc;

pub const TIMEOUT_MS: i64 = 10_000;

fn update_moving_average(current: i64, sample: i64) -> i64 {
    if current <= 0 {
        return sample;
    }
    ((i128::from(current) + i128::from(sample)) / 2)
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HealthState {
    Alive,
    Dead,
    Unavailable,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DialerHealthSnapshot {
    pub latency_ms: Option<i64>,
    pub alive: bool,
    pub checked_at_unix: i64,
    pub health_state: HealthState,
    pub last_success_at_unix: i64,
    pub last_failure_at_unix: i64,
    pub last_unknown_at_unix: i64,
}

impl HealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Dead => "dead",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "alive" => Some(Self::Alive),
            "dead" => Some(Self::Dead),
            "unavailable" => Some(Self::Unavailable),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Collection {
    pub alive_set_refs: usize,
    pub latencies10: LatenciesN,
    pub moving_average_ms: i64,
    pub alive: bool,
    pub checked_at_unix: i64,
    pub health_state: HealthState,
    pub last_success_at_unix: i64,
    pub last_failure_at_unix: i64,
    pub last_unknown_at_unix: i64,
}

impl Default for Collection {
    fn default() -> Self {
        Self {
            alive_set_refs: 0,
            latencies10: LatenciesN::new(10),
            moving_average_ms: 0,
            alive: true,
            checked_at_unix: 0,
            health_state: HealthState::Unknown,
            last_success_at_unix: 0,
            last_failure_at_unix: 0,
            last_unknown_at_unix: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dialer {
    pub name: String,
    pub subscription_tag: String,
    pub link: Arc<str>,
    collections: Vec<Option<Collection>>,
    probe_http_client_created: bool,
    probe_http_transport_created: bool,
}

impl Dialer {
    pub fn new(name: impl Into<String>, subscription_tag: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            link: Arc::from(""),
            name,
            subscription_tag: subscription_tag.into(),
            collections: vec![None; NETWORK_TYPE_COLLECTION_COUNT],
            probe_http_client_created: false,
            probe_http_transport_created: false,
        }
    }

    pub fn with_link(mut self, link: impl Into<Arc<str>>) -> Self {
        self.link = link.into();
        self
    }

    pub fn collection(&self, typ: NetworkType) -> Option<&Collection> {
        self.collections[typ.collection_index()].as_ref()
    }

    pub fn collection_mut(&mut self, typ: NetworkType) -> Option<&mut Collection> {
        self.collections[typ.collection_index()].as_mut()
    }

    pub fn must_get_collection(&mut self, typ: NetworkType) -> &mut Collection {
        let index = typ.collection_index();
        if self.collections[index].is_none() {
            self.collections[index] = Some(Collection::default());
        }
        self.collections[index].as_mut().unwrap()
    }

    pub fn must_get_alive(&self, typ: NetworkType) -> bool {
        self.collection(typ)
            .map(|collection| collection.alive)
            .unwrap_or(true)
    }

    pub fn must_get_latencies10(&mut self, typ: NetworkType) -> &mut LatenciesN {
        &mut self.must_get_collection(typ).latencies10
    }

    pub fn last_latency_snapshot(&self, typ: NetworkType) -> (i64, bool, i64, bool) {
        let Some(collection) = self.collection(typ) else {
            return (0, true, 0, false);
        };
        let Some(latency) = collection.latencies10.last() else {
            return (0, collection.alive, collection.checked_at_unix, false);
        };
        (latency, collection.alive, collection.checked_at_unix, true)
    }

    pub fn health_snapshot(&self, typ: NetworkType) -> Option<DialerHealthSnapshot> {
        let collection = self.collection(typ)?;
        Some(DialerHealthSnapshot {
            latency_ms: collection.latencies10.last(),
            alive: collection.alive,
            checked_at_unix: collection.checked_at_unix,
            health_state: collection.health_state,
            last_success_at_unix: collection.last_success_at_unix,
            last_failure_at_unix: collection.last_failure_at_unix,
            last_unknown_at_unix: collection.last_unknown_at_unix,
        })
    }

    pub fn restore_health_snapshot(&mut self, typ: NetworkType, snapshot: DialerHealthSnapshot) {
        let collection = self.must_get_collection(typ);
        if let Some(latency_ms) = snapshot.latency_ms {
            collection.latencies10.append(latency_ms);
            collection.moving_average_ms =
                update_moving_average(collection.moving_average_ms, latency_ms);
        }
        collection.alive = match snapshot.health_state {
            HealthState::Alive => true,
            HealthState::Dead | HealthState::Unavailable => false,
            HealthState::Unknown => snapshot.alive,
        };
        collection.checked_at_unix = snapshot.checked_at_unix;
        collection.health_state = snapshot.health_state;
        collection.last_success_at_unix = snapshot.last_success_at_unix;
        collection.last_failure_at_unix = snapshot.last_failure_at_unix;
        collection.last_unknown_at_unix = snapshot.last_unknown_at_unix;
    }

    pub fn set_moving_average(&mut self, typ: NetworkType, latency_ms: i64) {
        self.must_get_collection(typ).moving_average_ms = latency_ms;
    }

    pub fn record_check_result(
        &mut self,
        typ: NetworkType,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) {
        let collection = self.must_get_collection(typ);
        if let Some(latency) = latency_ms {
            collection.latencies10.append(latency);
            collection.moving_average_ms =
                update_moving_average(collection.moving_average_ms, latency);
        }
        collection.alive = latency_ms.is_some();
        collection.checked_at_unix = checked_at_unix;
        if latency_ms.is_some() {
            collection.health_state = HealthState::Alive;
            collection.last_success_at_unix = checked_at_unix;
        } else {
            collection.health_state = HealthState::Dead;
            collection.last_failure_at_unix = checked_at_unix;
        }
    }

    pub fn record_check_failure_without_latency(&mut self, typ: NetworkType, checked_at_unix: i64) {
        let collection = self.must_get_collection(typ);
        collection.alive = false;
        collection.checked_at_unix = checked_at_unix;
        collection.health_state = HealthState::Dead;
        collection.last_failure_at_unix = checked_at_unix;
    }

    pub fn record_available_traffic(&mut self, typ: NetworkType, checked_at_unix: i64) {
        let collection = self.must_get_collection(typ);
        collection.alive = true;
        collection.checked_at_unix = checked_at_unix;
        collection.health_state = HealthState::Alive;
        collection.last_success_at_unix = checked_at_unix;
    }

    pub fn record_check_unavailable(&mut self, typ: NetworkType, checked_at_unix: i64) {
        let collection = self.must_get_collection(typ);
        collection.alive = false;
        collection.checked_at_unix = checked_at_unix;
        collection.health_state = HealthState::Unavailable;
    }

    pub fn record_check_unknown(&mut self, typ: NetworkType, checked_at_unix: i64) {
        let collection = self.must_get_collection(typ);
        collection.last_unknown_at_unix = checked_at_unix;
        if collection.checked_at_unix == 0 {
            collection.health_state = HealthState::Unknown;
        }
    }

    pub fn register_alive_dialer_set(&mut self, alive_set: Option<&AliveDialerSet>) {
        let Some(alive_set) = alive_set else {
            return;
        };
        self.must_get_collection(alive_set.network_type)
            .alive_set_refs += 1;
    }

    pub fn unregister_alive_dialer_set(&mut self, alive_set: Option<&AliveDialerSet>) {
        let Some(alive_set) = alive_set else {
            return;
        };
        if let Some(collection) = self.collection_mut(alive_set.network_type) {
            collection.alive_set_refs = collection.alive_set_refs.saturating_sub(1);
        }
    }

    pub fn has_alive_dialer_sets(&self) -> bool {
        self.collections
            .iter()
            .flatten()
            .any(|collection| collection.alive_set_refs > 0)
    }

    pub fn collection_allocated_count(&self) -> usize {
        self.collections
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }

    pub fn get_probe_http_client_id(&mut self) -> usize {
        self.probe_http_transport_created = true;
        self.probe_http_client_created = true;
        1
    }

    pub fn probe_http_client_created(&self) -> bool {
        self.probe_http_client_created
    }

    pub fn probe_http_transport_created(&self) -> bool {
        self.probe_http_transport_created
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moving_average_uses_the_first_sample_then_applies_ema() {
        assert_eq!(update_moving_average(0, 80), 80);
        assert_eq!(update_moving_average(80, 40), 60);
        assert_eq!(update_moving_average(i64::MAX, i64::MAX), i64::MAX);
    }

    #[test]
    fn restored_and_live_health_samples_share_moving_average_semantics() {
        let network = NetworkType::TCP4;
        let mut restored = Dialer::new("restored", "fixture");
        restored.restore_health_snapshot(
            network,
            DialerHealthSnapshot {
                latency_ms: Some(80),
                alive: true,
                checked_at_unix: 1,
                health_state: HealthState::Alive,
                last_success_at_unix: 1,
                last_failure_at_unix: 0,
                last_unknown_at_unix: 0,
            },
        );
        let mut live = Dialer::new("live", "fixture");
        live.record_check_result(network, Some(80), 1);

        assert_eq!(restored.collection(network).unwrap().moving_average_ms, 80);
        assert_eq!(live.collection(network).unwrap().moving_average_ms, 80);
    }
}
