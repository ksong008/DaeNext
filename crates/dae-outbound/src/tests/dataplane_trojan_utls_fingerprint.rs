use super::*;

#[test]
fn case_utls_fingerprint_map_covers_native_client_hello_ids() {
    assert_eq!(shared_transport::supported_utls_fingerprint_count(), 45);
    let names = shared_transport::utls_fingerprint_names();
    for expected in [
        "random",
        "randomized",
        "randomizedalpn",
        "randomizednoalpn",
        "firefox",
        "firefox_auto",
        "firefox_105",
        "chrome",
        "chrome_auto",
        "chrome_102",
        "ios",
        "ios_14",
        "android_11_okhttp",
        "edge",
        "edge_106",
        "safari",
        "safari_16_0",
        "360",
        "360_11_0",
        "qq",
        "qq_11_1",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
}

#[test]
fn case_utls_fingerprint_aliases_match_native_boundaries() {
    let chrome = shared_transport::resolve_utls_client_hello_id("chrome").unwrap();
    assert_eq!(chrome.canonical, "chrome_auto");
    assert_eq!(chrome.family, "chrome");
    assert!(chrome.auto_alias);

    let randomized = shared_transport::resolve_utls_client_hello_id("randomized").unwrap();
    assert_eq!(randomized.canonical, "random");
    assert!(randomized.randomized);

    let no_alpn = shared_transport::resolve_utls_client_hello_id("randomizednoalpn").unwrap();
    assert_eq!(no_alpn.alpn_policy, "force-no-alpn");

    let err = shared_transport::resolve_utls_client_hello_id("Chrome").unwrap_err();
    assert!(
        err.to_string()
            .contains("unknown uTLS Client Hello ID: Chrome")
    );
}

#[test]
fn case_utls_wire_stack_remains_deferred() {
    assert!(shared_transport::U_TLS_WIRE_STACK_DEFERRED);
}
