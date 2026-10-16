use super::QuicCongestionController;

#[test]
fn config_values_normalize_to_canonical_controller_names() {
    for (input, expected, canonical) in [
        ("", QuicCongestionController::Bbr, "bbr"),
        ("BBR", QuicCongestionController::Bbr, "bbr"),
        ("cubic", QuicCongestionController::Cubic, "cubic"),
        ("new-reno", QuicCongestionController::NewReno, "new_reno"),
        ("reno", QuicCongestionController::NewReno, "new_reno"),
    ] {
        let parsed = QuicCongestionController::from_config(input).unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.as_str(), canonical);
    }
    assert!(QuicCongestionController::from_config("brutal").is_err());
}
