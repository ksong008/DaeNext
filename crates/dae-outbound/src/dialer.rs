use crate::alive::AliveDialerSet;
use crate::latency::LatenciesN;
use crate::types::NetworkType;

pub const TIMEOUT_MS: i64 = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Collection {
    pub alive_set_refs: usize,
    pub latencies10: LatenciesN,
    pub moving_average_ms: i64,
    pub alive: bool,
    pub checked_at_unix: i64,
}

impl Default for Collection {
    fn default() -> Self {
        Self {
            alive_set_refs: 0,
            latencies10: LatenciesN::new(10),
            moving_average_ms: 0,
            alive: true,
            checked_at_unix: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dialer {
    pub name: String,
    pub subscription_tag: String,
    pub link: String,
    collections: Vec<Option<Collection>>,
    probe_http_client_created: bool,
    probe_http_transport_created: bool,
}

impl Dialer {
    pub fn new(name: impl Into<String>, subscription_tag: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            link: String::new(),
            name,
            subscription_tag: subscription_tag.into(),
            collections: vec![None, None, None, None, None, None],
            probe_http_client_created: false,
            probe_http_transport_created: false,
        }
    }

    pub fn with_link(mut self, link: impl Into<String>) -> Self {
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
        let latency = latency_ms.unwrap_or(TIMEOUT_MS);
        collection.latencies10.append(latency);
        collection.moving_average_ms = (collection.moving_average_ms + latency) / 2;
        collection.alive = latency_ms.is_some();
        collection.checked_at_unix = checked_at_unix;
    }

    pub fn record_check_failure_without_latency(&mut self, typ: NetworkType, checked_at_unix: i64) {
        let collection = self.must_get_collection(typ);
        collection.alive = false;
        collection.checked_at_unix = checked_at_unix;
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
