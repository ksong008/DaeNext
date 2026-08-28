pub mod boring_quic;
pub mod contract;
pub mod dataplane;
pub mod ech;
pub mod grpc;
pub mod grpc_cache;
pub mod grpc_http2;
pub(crate) mod hpack;
pub(crate) mod hpack_decode;
pub mod ir;
pub mod meek;
pub mod mldsa65;
pub mod mux;
pub mod quic_congestion;
pub mod quic_h3;
pub mod reality;
pub mod reality_aead;
pub mod system_ca;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(any(test, feature = "test-support"))]
pub mod tls;
pub mod tls_fragment;
pub mod utls_fingerprint;
pub mod utls_template;
pub mod utls_wire;
pub mod utls_wire_builder;
pub mod xhttp;
#[cfg(any(test, feature = "test-support"))]
pub mod xhttp_h3;

pub const XHTTP_H3_ALPN: &str = "h3";
pub const XHTTP_H3_KEEPALIVE_SECS: u64 = 5;
pub const XHTTP_H3_HANDSHAKE_IDLE_TIMEOUT_SECS: u64 = 8;
pub(crate) const MAX_HTTP_MESSAGE_BODY_BYTES: usize = 1024 * 1024;

pub(crate) fn bounded_http_message_body_length(
    length: usize,
    context: &str,
) -> Result<usize, crate::error::OutboundError> {
    if length > MAX_HTTP_MESSAGE_BODY_BYTES {
        return Err(crate::error::OutboundError::BadSharedTransport(format!(
            "{context} body too large: {length} bytes (max {MAX_HTTP_MESSAGE_BODY_BYTES})"
        )));
    }
    Ok(length)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod body_length_tests {
    use super::*;

    #[test]
    fn http_message_body_length_is_bounded() {
        assert!(bounded_http_message_body_length(MAX_HTTP_MESSAGE_BODY_BYTES, "fixture").is_ok());
        let error = bounded_http_message_body_length(MAX_HTTP_MESSAGE_BODY_BYTES + 1, "fixture")
            .unwrap_err()
            .to_string();
        assert!(error.contains("body too large"));
    }
}

pub use dataplane::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, SharedTransportLoopbackReport, SimpleObfsHttpOptions,
    WS_ACCEPT_SAMPLE, WS_MASK_KEY, WebSocketClientHandshake, http_upgrade_exchange,
    http_upgrade_request, read_http_head, read_http_head_with_leftover,
    read_websocket_binary_frame, simpleobfs_http_exchange, simpleobfs_http_request,
    validate_http_status, validate_websocket_handshake_response, websocket_accept_for_key,
    websocket_client_binary_frame, websocket_client_binary_frame_with_random_mask,
    websocket_client_handshake, websocket_client_handshake_key, websocket_client_handshake_request,
    websocket_client_mask_key, websocket_exchange, websocket_handshake_request,
    websocket_server_binary_frame,
};
pub use ech::{
    ECH_CONFIG_LIST_MAX_BASE64_BYTES, ECH_CONFIG_LIST_MAX_BYTES, EchConfigList, EchConfigListError,
    parse_optional_ech_config_list,
};
pub use grpc::{
    GRPC_ACCEPT_ENCODING_HEADER, GRPC_CONTENT_TYPE_APPLICATION, GRPC_CONTENT_TYPE_HEADER,
    GRPC_ENCODING_HEADER, GRPC_IDENTITY_ENCODING, GRPC_TE_HEADER, GRPC_TE_TRAILERS,
    GrpcCacheReport, GrpcLifecycleCache, GrpcLifecycleOptions, GrpcLifecycleReport, GrpcMode,
    grpc_data_frame, grpc_hunk_exchange, grpc_hunk_frame, grpc_hunk_frame_len, grpc_hunk_message,
    grpc_hunk_payload, grpc_hunk_payload_ref, grpc_multi_hunk_frame, grpc_multi_hunk_payloads,
    grpc_request_path, grpc_stream_preface, read_grpc_hunk_frame,
};
pub use grpc_cache::{
    GrpcCacheCancellationStressReport, GrpcDetachedStreamCancellationReport,
    grpc_cache_cleanup_cancellation_stress,
};
pub use grpc_http2::{
    GrpcHttp2FrameReport, GrpcHttp2LifecycleOptions, GrpcHttp2Request, HTTP2_CLIENT_PREFACE,
    HTTP2_FLAG_ACK, HTTP2_FLAG_END_HEADERS, HTTP2_FRAME_DATA, HTTP2_FRAME_HEADERS,
    HTTP2_FRAME_SETTINGS, grpc_hunk_http2_data, http2_frame, read_grpc_http2_request,
    read_grpc_http2_response, read_http2_frame, write_grpc_http2_request,
    write_grpc_http2_response,
};
pub use meek::{
    MeekRoundTripOptions, MeekRoundTripReport, meek_http_request, meek_polling_exchange,
};
pub use mldsa65::{
    MLDSA65_PUBLIC_KEY_BASE64_BYTES, MLDSA65_PUBLIC_KEY_BYTES, MLDSA65_SIGNATURE_BYTES,
    Mldsa65VerifyKey, Mldsa65VerifyKeyError, parse_optional_mldsa65_verify_key,
};
pub use mux::{
    MUX_DATA_FRAME_HEADER_BYTES, MUX_MAX_FRAME_BYTES, MUX_MAX_METADATA_BYTES,
    MUX_MAX_PAYLOAD_BYTES, MuxFrame, MuxFrameDecoder, MuxFrameOptions, MuxLifecycleReport,
    mux_data_frame, mux_data_frame_header, mux_end_frame, mux_error_frame, mux_frame_exchange,
    mux_new_frame,
};
pub use quic_congestion::{QuicCongestionController, QuicCongestionControllerError};
pub use quic_h3::{
    QuicH3HarnessOptions, QuicH3HarnessReport, parse_quic_h3_datagram, quic_h3_datagram_exchange,
    quic_h3_datagram_packet,
};
pub use reality::{
    RealityMutationOptions, RealityMutationReport, reality_mutation_exchange,
    reality_mutation_report, reality_session_id,
};
pub use reality_aead::{
    REALITY_AEAD_NONCE_LEN, REALITY_CLIENT_RANDOM_LEN, REALITY_HKDF_SALT_LEN,
    REALITY_SESSION_ID_LEN, REALITY_SESSION_ID_PLAINTEXT_LEN, REALITY_SESSION_ID_RAW_OFFSET,
    RealityAeadAlgorithm, RealitySessionIdMutationOptions, RealitySessionIdMutationReport,
    apply_reality_session_id_to_hello_raw, mutate_reality_session_id, reality_auth_key,
    reality_session_id_mutation_report, reality_session_id_plaintext,
};
pub use system_ca::{
    SYSTEM_CA_BUNDLE_PATHS, SystemCaError, SystemCaIdentity, SystemCaSnapshot,
    invalidate_system_ca_snapshot, system_ca_snapshot,
};
#[cfg(any(test, feature = "test-support"))]
pub use tls::{
    DEFAULT_TLS_ALPN, DEFAULT_TLS_SERVER_NAME, TlsLoopbackMaterial, TlsServerObservation,
    TlsUnderlayOptions, TlsUnderlayReport, tls_client_echo_exchange, tls_loopback_material,
    tls_server_echo,
};
pub use tls_fragment::{
    SharedTlsFragmentStats, TLS_FRAGMENT_MAX_BUFFERED_RECORD_LEN, TLS_HANDSHAKE_CONTENT_TYPE,
    TLS_RECORD_HEADER_LEN, TlsFragmentOptions, TlsFragmentPlan, TlsFragmentPlanner,
    TlsFragmentSegment, TlsFragmentStats, TlsFragmentWrite, TlsFragmentWriteReport,
    TlsFragmentingStream, fragment_tls_write, new_tls_fragment_stats, parse_tls_fragment_range,
    snapshot_tls_fragment_stats,
};
pub use utls_fingerprint::{
    DEFAULT_UTLS_FINGERPRINT, SUPPORTED_UTLS_FINGERPRINTS, U_TLS_WIRE_STACK_DEFERRED, UTLS_ALPN_H2,
    UTLS_ALPN_HTTP_1_1, UTLS_ALPN_POLICY_AUTO, UTLS_ALPN_POLICY_FIXED,
    UTLS_ALPN_POLICY_RANDOMIZED_ALPN, UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN,
    UTLS_BROWSER_DEFAULT_ALPN, UTLS_CONTRACT_GLOBAL_PROBE_FINGERPRINT,
    UTLS_CONTRACT_LINK_PROBE_FINGERPRINT, UTLS_CONTRACT_UNKNOWN_PROBE_FINGERPRINT, UTLS_FAMILY_360,
    UTLS_FAMILY_ANDROID, UTLS_FAMILY_CHROME, UTLS_FAMILY_EDGE, UTLS_FAMILY_FIREFOX,
    UTLS_FAMILY_IOS, UTLS_FAMILY_QQ, UTLS_FAMILY_RANDOM, UTLS_FAMILY_SAFARI, UtlsFingerprint,
    resolve_utls_client_hello_id, supported_utls_fingerprint_count,
    utls_fingerprint_default_alpn_protocols, utls_fingerprint_names,
};
pub use utls_template::{
    UTLS_TEMPLATE_GREASE, UtlsAlpnTemplate, UtlsPaddingTemplate, UtlsRuntimeTemplate,
    UtlsRuntimeTemplateCapabilities, UtlsServerNameTemplate, UtlsSessionIdTemplate,
    UtlsTemplateCoverage, UtlsTemplateFamily, UtlsTemplateMode, UtlsTemplateProfile,
    UtlsTemplateValue, normalize_utls_template_profile, resolve_utls_runtime_template,
    resolve_utls_template_mode, utls_template_coverage, utls_template_mode_label,
};
pub use utls_wire::{
    UtlsClientHelloProfile, parse_utls_client_hello_record, parse_utls_client_hello_record_hex,
};
pub use utls_wire_builder::{
    build_synthetic_utls_client_hello_record, build_synthetic_utls_client_hello_record_hex,
};
pub use xhttp::{
    XHttpHttp2FrameReport, XHttpHttp2Request, XHttpLifecycleOptions, XHttpLifecycleReport,
    XHttpXmuxOptions, read_xhttp_http2_request, read_xhttp_http2_response,
    write_xhttp_http2_request, write_xhttp_http2_response, xhttp_packet_exchange,
    xhttp_packet_request, xhttp_request_path,
};
#[cfg(any(test, feature = "test-support"))]
pub use xhttp_h3::{XHttpH3LoopbackOptions, XHttpH3LoopbackReport, xhttp_h3_packet_up_loopback};
