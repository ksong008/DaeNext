use super::*;

#[test]
fn shared_transport_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/shared_transport_native_optin.json");

    assert_eq!(
        crate::shared_transport::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::PROTOCOL_SCOPE,
        string_values(&fixture["protocol_scope"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::TRANSPORT_SCOPE,
        string_values(&fixture["transport_scope"]).as_slice()
    );

    let tls = &fixture["tls_transport"];
    assert_eq!(
        crate::shared_transport::contract::TLS_SCHEMES,
        string_values(&tls["schemes"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::ALLOW_INSECURE_ALIASES,
        string_values(&tls["allow_insecure_aliases"]).as_slice()
    );
    for case in tls["allow_insecure_samples"].as_array().unwrap() {
        assert_eq!(
            crate::shared_transport::ir::parse_bool(case["value"].as_str().unwrap()),
            case["parsed"].as_bool().unwrap()
        );
    }
    assert_eq!(
        crate::shared_transport::contract::GLOBAL_TLS_FRAGMENT,
        tls["global_tls_fragment"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::UDP_PASSTHROUGH_KEY,
        tls["udp_passthrough_key"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::UDP_WITHOUT_PASSTHROUGH,
        tls["udp_without_passthrough"].as_str().unwrap()
    );

    let reality = &fixture["reality_transport"];
    assert_eq!(
        hex_encode(
            &crate::shared_transport::ir::reality_sid_decode(
                reality["sid_input"].as_str().unwrap()
            )
            .unwrap()
        ),
        reality["sid_decoded_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(
            &crate::shared_transport::ir::reality_pbk_decode(
                reality["pbk_input"].as_str().unwrap()
            )
            .unwrap()
        ),
        reality["pbk_decoded_hex"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::REALITY_SPX_DEFAULT,
        reality["spx_default"].as_str().unwrap()
    );
    let spider_y =
        crate::shared_transport::ir::reality_spider_y(reality["spx_input"].as_str().unwrap());
    assert_eq!(
        spider_y.as_slice(),
        reality["spider_y"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_i64().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::REALITY_REQUIRES_UTLS_HANDSHAKE_STATE,
        reality["requires_utls_handshake_state"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::REALITY_VERIFY_PEER_CERTIFICATE,
        reality["verify_peer_certificate"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::REALITY_DATA_PLANE_DEFERRED,
        reality["data_plane_deferred"].as_bool().unwrap()
    );

    let ws = &fixture["ws_transport"];
    assert_eq!(
        crate::shared_transport::contract::WS_SCHEMES,
        string_values(&ws["schemes"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::ALLOW_INSECURE_ALIASES,
        string_values(&ws["allow_insecure_aliases"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::UDP_WITHOUT_PASSTHROUGH,
        ws["udp_without_passthrough"].as_str().unwrap()
    );

    let grpc = &fixture["grpc_transport"];
    assert_eq!(
        crate::shared_transport::contract::GRPC_CLEAN_CACHE_HOOK,
        grpc["clean_cache_hook"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_CACHE_KEY_FIELDS,
        string_values(&grpc["cache_key_fields"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::ir::grpc_cache_key(
            "addr:443",
            "sni.example",
            "dialer-1",
            true,
            1234,
            true
        ),
        grpc["sample_cache_key_a"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::ir::grpc_cache_key(
            "addr:443",
            "sni.example",
            "dialer-1",
            true,
            1234,
            false
        ),
        grpc["sample_cache_key_b"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_BACKOFF_BASE_MS,
        grpc["backoff_base_ms"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_BACKOFF_MAX_SECONDS,
        grpc["backoff_max_seconds"].as_u64().unwrap()
    );
    assert!(
        (crate::shared_transport::contract::GRPC_BACKOFF_MULTIPLIER
            - grpc["backoff_multiplier"].as_f64().unwrap())
        .abs()
            < f64::EPSILON
    );
    assert!(
        (crate::shared_transport::contract::GRPC_BACKOFF_JITTER
            - grpc["backoff_jitter"].as_f64().unwrap())
        .abs()
            < f64::EPSILON
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_KEEPALIVE_SECONDS,
        grpc["keepalive_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_KEEPALIVE_TIMEOUT_SECONDS,
        grpc["keepalive_timeout_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::GRPC_MIN_CONNECT_TIMEOUT_SECONDS,
        grpc["min_connect_timeout_seconds"].as_u64().unwrap()
    );

    let httpupgrade = &fixture["httpupgrade_transport"];
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_REQUEST_METHOD,
        httpupgrade["request_method"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_CONNECTION_HEADER,
        httpupgrade["connection_header"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_UPGRADE_HEADER,
        httpupgrade["upgrade_header"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_SUCCESS_STATUS,
        httpupgrade["success_status"].as_u64().unwrap() as u16
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_HTTPS_ALPN,
        string_values(&httpupgrade["https_alpn"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::HTTPUPGRADE_UDP,
        httpupgrade["udp"].as_str().unwrap()
    );

    let meek = &fixture["meek_transport"];
    assert_eq!(
        crate::shared_transport::contract::MEEK_URL_SCHEME_REQUIRED,
        meek["url_scheme_required"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_DEFAULT_ALPN,
        string_values(&meek["default_alpn"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_MAX_WRITE,
        meek["max_write"].as_u64().unwrap() as usize
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_INITIAL_POLLING_MS,
        meek["initial_polling_ms"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_MAX_POLLING_MS,
        meek["max_polling_ms"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_MIN_POLLING_MS,
        meek["min_polling_ms"].as_u64().unwrap()
    );
    assert!(
        (crate::shared_transport::contract::MEEK_BACKOFF - meek["backoff"].as_f64().unwrap()).abs()
            < f64::EPSILON
    );
    assert_eq!(
        crate::shared_transport::contract::MEEK_CLEAN_CACHE_HOOK,
        meek["clean_cache_hook"].as_str().unwrap()
    );

    let simpleobfs = &fixture["simpleobfs_transport"];
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_SUPPORTED,
        string_values(&simpleobfs["supported"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_TYPE_KEYS,
        string_values(&simpleobfs["type_keys"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_PATH_KEYS,
        string_values(&simpleobfs["path_keys"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_HOST_KEY,
        simpleobfs["host_key"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::SIMPLEOBFS_PROTOCOL_LABEL,
        simpleobfs["protocol_label"].as_str().unwrap()
    );

    let mux = &fixture["mux_transport"];
    assert_eq!(
        crate::shared_transport::contract::MUX_REQUEST_HEADER_HEX,
        mux["request_header_hex"].as_str().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::MUX_DATA_PLANE_DEFERRED,
        mux["data_plane_deferred"].as_bool().unwrap()
    );

    let xhttp = &fixture["xhttp_transport"];
    for case in xhttp["mode_cases"].as_array().unwrap() {
        let got = crate::shared_transport::ir::normalize_xhttp_mode(
            case["mode"].as_str().unwrap(),
            case["scheme"].as_str().unwrap(),
            case["security"].as_str().unwrap(),
            case["hasDownload"].as_bool().unwrap(),
        );
        assert_eq!(got.normalized, case["normalized"].as_str().unwrap());
        assert_eq!(got.ok, case["ok"].as_bool().unwrap());
        assert_eq!(got.error_contains, case["error_contains"].as_str().unwrap());
    }
    for case in xhttp["alpn_cases"].as_array().unwrap() {
        let got = crate::shared_transport::ir::validate_xhttp_alpn(
            case["security"].as_str().unwrap(),
            case["alpn"].as_str().unwrap(),
        );
        assert_eq!(got.ok, case["ok"].as_bool().unwrap());
        assert_eq!(got.use_h3, case["use_h3"].as_bool().unwrap());
        assert_eq!(got.error_contains, case["error_contains"].as_str().unwrap());
    }
    assert_eq!(
        crate::shared_transport::ir::canonical_json(xhttp["extra_raw"].as_str().unwrap()).unwrap(),
        xhttp["extra_canonical"].as_str().unwrap()
    );
    for case in xhttp["path_cases"].as_array().unwrap() {
        let got = crate::shared_transport::ir::normalize_xhttp_path_and_query(
            case["input"].as_str().unwrap(),
        );
        assert_eq!(got.path, case["path"].as_str().unwrap());
        assert_eq!(got.query, case["query"].as_str().unwrap());
    }
    assert_eq!(
        crate::shared_transport::contract::XHTTP_PACKET_MAX_BYTES_DEFAULT,
        xhttp["packet_max_bytes_default"].as_u64().unwrap() as usize
    );
    assert_eq!(
        crate::shared_transport::contract::XHTTP_PACKET_MIN_GAP_MS_DEFAULT,
        xhttp["packet_min_gap_ms_default"].as_u64().unwrap()
    );
    assert_eq!(
        crate::shared_transport::contract::XHTTP_UNSUPPORTED_EXTRA_FIELDS,
        string_values(&xhttp["unsupported_extra_fields"]).as_slice()
    );
    assert_eq!(
        crate::shared_transport::contract::XHTTP_TRUE_DATA_PLANE_DEFERRED,
        xhttp["true_data_plane_deferred"].as_bool().unwrap()
    );
}
