use std::num::NonZeroU64;

pub(super) const QUIC_ENDPOINT_CHARGE_SCHEMA: &str = "quinn-endpoint-charge";
pub(super) const QUIC_ENDPOINT_CHARGE_SCHEMA_VERSION: u64 = 1;
pub(super) const QUIC_ENDPOINT_CHARGE_MODEL: &str = "quinn-0.11-receive-slab-safety-reserve";
pub(super) const QUIC_ENDPOINT_CHARGE_MODEL_VERSION: u64 = 1;

const QUINN_RECEIVE_DATAGRAM_LIMIT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuicEndpointSafetyChargeProfile {
    pub quic_transport_bytes: NonZeroU64,
    pub http3_bytes: NonZeroU64,
    pub tls_bytes: NonZeroU64,
    pub queue_bytes: NonZeroU64,
}

impl QuicEndpointSafetyChargeProfile {
    // These are accounting reserves, not an exact RSS claim. Admission is deliberately outside
    // this model; a later measured profile can replace the values without changing the formula.
    const OBSERVABILITY_BASELINE: Self = Self {
        quic_transport_bytes: NonZeroU64::new(256 * 1024).unwrap(),
        http3_bytes: NonZeroU64::new(256 * 1024).unwrap(),
        tls_bytes: NonZeroU64::new(128 * 1024).unwrap(),
        queue_bytes: NonZeroU64::new(128 * 1024).unwrap(),
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuicEndpointCharge {
    pub receive_slab_bytes: u64,
    pub quic_transport_bytes: u64,
    pub http3_bytes: u64,
    pub tls_bytes: u64,
    pub queue_bytes: u64,
    pub total_bytes: u64,
    pub max_udp_payload_bytes: u64,
    pub receive_segments: u64,
    pub batch_size: u64,
}

impl QuicEndpointCharge {
    pub(super) fn for_socket(
        endpoint_config: &quinn::EndpointConfig,
        max_receive_segments: usize,
        uses_http3: bool,
    ) -> Result<Self, String> {
        let max_udp_payload_bytes = endpoint_config
            .get_max_udp_payload_size()
            .min(QUINN_RECEIVE_DATAGRAM_LIMIT_BYTES);
        let receive_segments = u64::try_from(max_receive_segments)
            .map_err(|_| "QUIC receive segment count does not fit u64".to_owned())?;
        let batch_size = u64::try_from(quinn::udp::BATCH_SIZE)
            .map_err(|_| "QUIC UDP batch size does not fit u64".to_owned())?;
        let receive_slab_bytes = max_udp_payload_bytes
            .checked_mul(receive_segments)
            .and_then(|value| value.checked_mul(batch_size))
            .ok_or_else(|| "QUIC receive-slab charge overflow".to_owned())?;
        let profile = QuicEndpointSafetyChargeProfile::OBSERVABILITY_BASELINE;
        let quic_transport_bytes = profile.quic_transport_bytes.get();
        let http3_bytes = if uses_http3 {
            profile.http3_bytes.get()
        } else {
            0
        };
        let tls_bytes = profile.tls_bytes.get();
        let queue_bytes = profile.queue_bytes.get();
        let total_bytes = receive_slab_bytes
            .checked_add(quic_transport_bytes)
            .and_then(|value| value.checked_add(http3_bytes))
            .and_then(|value| value.checked_add(tls_bytes))
            .and_then(|value| value.checked_add(queue_bytes))
            .ok_or_else(|| "QUIC endpoint total charge overflow".to_owned())?;
        Ok(Self {
            receive_slab_bytes,
            quic_transport_bytes,
            http3_bytes,
            tls_bytes,
            queue_bytes,
            total_bytes,
            max_udp_payload_bytes,
            receive_segments,
            batch_size,
        })
    }
}

pub(super) fn charge_model_json() -> serde_json::Value {
    let profile = QuicEndpointSafetyChargeProfile::OBSERVABILITY_BASELINE;
    serde_json::json!({
        "schema": QUIC_ENDPOINT_CHARGE_SCHEMA,
        "schemaVersion": QUIC_ENDPOINT_CHARGE_SCHEMA_VERSION,
        "model": QUIC_ENDPOINT_CHARGE_MODEL,
        "modelVersion": QUIC_ENDPOINT_CHARGE_MODEL_VERSION,
        "quinnReceivePayloadCapBytes": QUINN_RECEIVE_DATAGRAM_LIMIT_BYTES,
        "quinnUdpBatchSize": quinn::udp::BATCH_SIZE,
        "safetyReserve": {
            "quicTransportBytes": profile.quic_transport_bytes.get(),
            "http3Bytes": profile.http3_bytes.get(),
            "tlsBytes": profile.tls_bytes.get(),
            "queueBytes": profile.queue_bytes.get(),
        },
        "admissionEnforced": false,
        "rssClaim": false,
    })
}
