use std::num::NonZeroU64;

use super::model::QuicEndpointUnderlay;

pub(super) const QUIC_ENDPOINT_CHARGE_SCHEMA: &str = "quinn-endpoint-charge";
pub(super) const QUIC_ENDPOINT_CHARGE_SCHEMA_VERSION: u64 = 3;
pub(super) const QUIC_ENDPOINT_CHARGE_MODEL: &str =
    "quinn-0.11-endpoint-and-underlay-safety-reserve";
pub(super) const QUIC_ENDPOINT_CHARGE_MODEL_VERSION: u64 = 4;

const QUINN_RECEIVE_DATAGRAM_LIMIT_BYTES: u64 = 64 * 1024;
const QUINN_GRO_RECEIVE_SEGMENTS: usize = 64;
const QUINN_SINGLE_DATAGRAM_RECEIVE_SEGMENTS: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuicEndpointSafetyChargeProfile {
    pub quic_transport_bytes: NonZeroU64,
    pub http3_bytes: NonZeroU64,
    pub tls_bytes: NonZeroU64,
    pub queue_bytes: NonZeroU64,
    pub underlay_socket_bytes: NonZeroU64,
}

impl QuicEndpointSafetyChargeProfile {
    // These are accounting reserves, not an exact RSS claim. Admission is deliberately outside
    // this model; a later measured profile can replace the values without changing the formula.
    const OBSERVABILITY_BASELINE: Self = Self {
        quic_transport_bytes: NonZeroU64::new(256 * 1024).unwrap(),
        http3_bytes: NonZeroU64::new(256 * 1024).unwrap(),
        tls_bytes: NonZeroU64::new(128 * 1024).unwrap(),
        queue_bytes: NonZeroU64::new(128 * 1024).unwrap(),
        underlay_socket_bytes: NonZeroU64::new(64 * 1024).unwrap(),
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuicEndpointCharge {
    pub receive_slab_bytes: u64,
    pub quic_transport_bytes: u64,
    pub http3_bytes: u64,
    pub tls_bytes: u64,
    pub queue_bytes: u64,
    pub underlay_socket_bytes: u64,
    pub total_bytes: u64,
    pub max_udp_payload_bytes: u64,
    pub receive_segments: u64,
    pub batch_size: u64,
    pub udp_socket_count: u64,
}

impl QuicEndpointCharge {
    pub(super) fn before_socket(
        endpoint_config: &quinn::EndpointConfig,
        underlay: QuicEndpointUnderlay,
        uses_http3: bool,
    ) -> Result<Self, String> {
        let receive_segments = if underlay.uses_single_datagram_receive() {
            QUINN_SINGLE_DATAGRAM_RECEIVE_SEGMENTS
        } else {
            conservative_platform_receive_segments()
        };
        Self::for_socket_count(
            endpoint_config,
            receive_segments,
            underlay.socket_charge_count(),
            uses_http3,
        )
    }

    #[cfg(test)]
    pub(super) fn for_socket(
        endpoint_config: &quinn::EndpointConfig,
        max_receive_segments: usize,
        uses_http3: bool,
    ) -> Result<Self, String> {
        Self::for_socket_count(endpoint_config, max_receive_segments, 1, uses_http3)
    }

    pub(super) fn for_wrapped_underlay(
        endpoint_config: &quinn::EndpointConfig,
        max_receive_segments: usize,
        underlay: QuicEndpointUnderlay,
        uses_http3: bool,
    ) -> Result<Self, String> {
        Self::for_socket_count(
            endpoint_config,
            max_receive_segments,
            underlay.socket_charge_count(),
            uses_http3,
        )
    }

    fn for_socket_count(
        endpoint_config: &quinn::EndpointConfig,
        max_receive_segments: usize,
        udp_socket_count: usize,
        uses_http3: bool,
    ) -> Result<Self, String> {
        let max_udp_payload_bytes = endpoint_config
            .get_max_udp_payload_size()
            .min(QUINN_RECEIVE_DATAGRAM_LIMIT_BYTES);
        let receive_segments = u64::try_from(max_receive_segments)
            .map_err(|_| "QUIC receive segment count does not fit u64".to_owned())?;
        let batch_size = u64::try_from(quinn::udp::BATCH_SIZE)
            .map_err(|_| "QUIC UDP batch size does not fit u64".to_owned())?;
        let udp_socket_count = u64::try_from(udp_socket_count)
            .map_err(|_| "QUIC UDP socket count does not fit u64".to_owned())?;
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
        let underlay_socket_bytes = profile
            .underlay_socket_bytes
            .get()
            .checked_mul(udp_socket_count)
            .ok_or_else(|| "QUIC underlay-socket charge overflow".to_owned())?;
        let total_bytes = receive_slab_bytes
            .checked_add(quic_transport_bytes)
            .and_then(|value| value.checked_add(http3_bytes))
            .and_then(|value| value.checked_add(tls_bytes))
            .and_then(|value| value.checked_add(queue_bytes))
            .and_then(|value| value.checked_add(underlay_socket_bytes))
            .ok_or_else(|| "QUIC endpoint total charge overflow".to_owned())?;
        Ok(Self {
            receive_slab_bytes,
            quic_transport_bytes,
            http3_bytes,
            tls_bytes,
            queue_bytes,
            underlay_socket_bytes,
            total_bytes,
            max_udp_payload_bytes,
            receive_segments,
            batch_size,
            udp_socket_count,
        })
    }
}

const fn conservative_platform_receive_segments() -> usize {
    if cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )) {
        // Quinn 0.11 / quinn-udp 0.5 reserve for Linux UDP_GRO_CNT_MAX and use the same
        // conservative segment count on Windows. This is deliberately evaluated before bind.
        QUINN_GRO_RECEIVE_SEGMENTS
    } else {
        QUINN_SINGLE_DATAGRAM_RECEIVE_SEGMENTS
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
        "preSocketOrdinaryReceiveSegments": conservative_platform_receive_segments(),
        "preSocketSalamanderReceiveSegments": QUINN_SINGLE_DATAGRAM_RECEIVE_SEGMENTS,
        "portHoppingSocketCountSource": "runtimeProfile",
        "receiveSlabScope": "one Quinn Endpoint-wide receive slab, independent of wrapped underlay socket count",
        "portHoppingChargeScope": "underlay socket reserve only; QUIC, HTTP/3, TLS, queue and receive-slab reserves remain one physical owner",
        "safetyReserve": {
            "quicTransportBytes": profile.quic_transport_bytes.get(),
            "http3Bytes": profile.http3_bytes.get(),
            "tlsBytes": profile.tls_bytes.get(),
            "queueBytes": profile.queue_bytes.get(),
            "underlaySocketBytesEach": profile.underlay_socket_bytes.get(),
        },
        "admissionEnforced": true,
        "rssClaim": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_socket_charge_covers_wrapped_socket_segment_counts() {
        let config = quinn_boring::helpers::default_endpoint_config();
        let ordinary =
            QuicEndpointCharge::before_socket(&config, QuicEndpointUnderlay::Ordinary, true)
                .unwrap();
        let single = QuicEndpointCharge::for_socket(&config, 1, true).unwrap();
        let maximum =
            QuicEndpointCharge::for_socket(&config, conservative_platform_receive_segments(), true)
                .unwrap();
        assert!(ordinary.total_bytes >= single.total_bytes);
        assert_eq!(ordinary, maximum);

        let salamander =
            QuicEndpointCharge::before_socket(&config, QuicEndpointUnderlay::Salamander, true)
                .unwrap();
        assert_eq!(salamander.receive_segments, 1);
    }

    #[test]
    fn port_hopping_charges_one_receive_slab_and_independent_underlay_sockets() {
        let config = quinn_boring::helpers::default_endpoint_config();
        for (receive_segments, ordinary, hopping) in [
            (
                conservative_platform_receive_segments(),
                QuicEndpointUnderlay::Ordinary,
                QuicEndpointUnderlay::PortHopping {
                    transition_socket_limit: 3,
                },
            ),
            (
                QUINN_SINGLE_DATAGRAM_RECEIVE_SEGMENTS,
                QuicEndpointUnderlay::Salamander,
                QuicEndpointUnderlay::SalamanderPortHopping {
                    transition_socket_limit: 3,
                },
            ),
        ] {
            let ordinary =
                QuicEndpointCharge::for_wrapped_underlay(&config, receive_segments, ordinary, true)
                    .unwrap();
            let hopping =
                QuicEndpointCharge::for_wrapped_underlay(&config, receive_segments, hopping, true)
                    .unwrap();

            assert_eq!(ordinary.receive_slab_bytes, hopping.receive_slab_bytes);
            assert_eq!(ordinary.udp_socket_count, 1);
            assert_eq!(hopping.udp_socket_count, 3);
            assert_eq!(
                hopping.underlay_socket_bytes,
                ordinary.underlay_socket_bytes * 3
            );
            assert_eq!(
                hopping.total_bytes - ordinary.total_bytes,
                hopping.underlay_socket_bytes - ordinary.underlay_socket_bytes
            );
        }
    }
}
