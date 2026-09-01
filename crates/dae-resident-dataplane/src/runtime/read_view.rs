use super::*;

#[derive(Clone)]
pub(super) struct ResidentRuntimeOwnerReadHandle {
    pub(super) metrics: Arc<ResidentDataplaneMetrics>,
    pub(super) reload_generation: u64,
    pub(super) runtime_owner: Arc<Value>,
    pub(super) packet_session_manager: Arc<Value>,
    pub(super) resources: Arc<Value>,
    pub(super) udp_payload_admission: ResidentUdpPayloadAdmission,
    pub(super) event_writer: ResidentEventWriterHandle,
    pub(super) hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    pub(super) tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    pub(super) juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    pub(super) anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    pub(super) h2_carrier_generation_owner: Option<H2CarrierGenerationOwnerHandle>,
    pub(super) meek_transport_generation_owner: Option<MeekTransportGenerationOwnerHandle>,
    pub(super) vless_mux_generation_owner: Option<VlessMuxGenerationOwnerHandle>,
    pub(super) xhttp_xmux_generation_owner: Option<tcp::XhttpXmuxGenerationOwnerHandle>,
}

impl ResidentRuntimeOwnerReadHandle {
    pub(super) fn metrics_snapshot(&self) -> Value {
        let mut snapshot = self.metrics.snapshot();
        snapshot["reloadGeneration"] = json!(self.reload_generation);
        snapshot["runtimeOwner"] = self.runtime_owner.as_ref().clone();
        snapshot["packetSessionManager"] = self.packet_session_manager.as_ref().clone();
        snapshot["resources"] = self.resources.as_ref().clone();
        snapshot["udpPayloadAdmission"] = self.udp_payload_admission.snapshot();
        snapshot["eventWriter"] = self.event_writer.metrics_snapshot();
        snapshot["tlsConfigCache"] = crate::client::resident_tls_config_cache_metrics();
        snapshot["connectUdpPools"] =
            udp::connect_udp_pool_metrics_snapshot(self.reload_generation);
        snapshot["quicEndpoints"] = tcp::quic_endpoint_metrics_snapshot(self.reload_generation);
        snapshot["hysteria2Owners"] = self
            .hysteria2_owner_registry
            .as_ref()
            .map(Hysteria2OwnerRegistryHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["tuicOwners"] = self
            .tuic_owner_registry
            .as_ref()
            .map(TuicOwnerRegistryHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["juicityOwners"] = self
            .juicity_owner_registry
            .as_ref()
            .map(JuicityOwnerRegistryHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["anytlsOwners"] = self
            .anytls_owner_registry
            .as_ref()
            .map(AnyTlsOwnerRegistryHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["h2CarrierOwners"] = self
            .h2_carrier_generation_owner
            .as_ref()
            .map(H2CarrierGenerationOwnerHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["meekTransportOwners"] = self
            .meek_transport_generation_owner
            .as_ref()
            .map(MeekTransportGenerationOwnerHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["vlessMuxOwners"] = self
            .vless_mux_generation_owner
            .as_ref()
            .map(VlessMuxGenerationOwnerHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot["xhttpXmuxOwner"] = self
            .xhttp_xmux_generation_owner
            .as_ref()
            .map(tcp::XhttpXmuxGenerationOwnerHandle::metrics_snapshot)
            .unwrap_or(Value::Null);
        snapshot
    }
}

#[derive(Clone)]
pub struct ResidentDataplaneReadHandle {
    owner: ResidentRuntimeOwnerReadHandle,
    generation_drain: ResidentGenerationDrain,
    coordinator: ResidentRuntimeCoordinator<ResidentDataplaneGeneration>,
}

impl std::fmt::Debug for ResidentDataplaneReadHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentDataplaneReadHandle")
            .field("reload_generation", &self.owner.reload_generation)
            .finish_non_exhaustive()
    }
}

impl ResidentDataplaneReadHandle {
    pub(super) fn new(
        owner: ResidentRuntimeOwnerReadHandle,
        generation_drain: ResidentGenerationDrain,
        coordinator: ResidentRuntimeCoordinator<ResidentDataplaneGeneration>,
    ) -> Self {
        Self {
            owner,
            generation_drain,
            coordinator,
        }
    }

    pub fn metrics_snapshot(&self) -> Value {
        let mut metrics = self.owner.metrics_snapshot();
        metrics["generationDrain"] = self.generation_drain.snapshot();
        let generation = self.coordinator.load();
        let (dns_cache_entries, dns_routing_cache_entries) = generation
            .dns_reload_handle
            .cache_entry_counts()
            .unwrap_or((0, 0));
        let resident_node_count = generation
            .groups
            .iter()
            .map(|group| group.candidate_count())
            .sum::<usize>();
        metrics["dnsCacheEntries"] = json!(dns_cache_entries);
        metrics["dnsRoutingCacheEntries"] = json!(dns_routing_cache_entries);
        metrics["residentNodeCount"] = json!(resident_node_count);
        metrics["activeGeneration"] = json!(generation.reload_generation.get());
        metrics
    }
}
