use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::*;

fn target(last_octet: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)), port)
}

fn token(value: &[u8]) -> UdpResponseIdentityToken {
    UdpResponseIdentityToken::from_protocol_identity(b"fixture-protocol", value).unwrap()
}

fn compatibility(source: SocketAddr) -> UdpFixedTargetExpectation {
    UdpFixedTargetExpectation::compatibility(source)
}

#[test]
fn fixed_target_source_and_protocol_identity_must_both_match() {
    let expected_target = target(1, 443);
    let expected_identity = token(b"expected-session");
    let expectation =
        UdpFixedTargetExpectation::with_protocol_identity(expected_target, expected_identity);
    let response = UdpExchangeResult::new(vec![1, 2, 3], "fixture")
        .with_decoded_response_identity(Some(expected_target), Some(expected_identity));
    assert_eq!(
        response.validate_fixed_target(expectation),
        UdpFixedTargetValidation::Validated
    );
}

#[test]
fn wrong_or_missing_wire_source_is_dropped() {
    let expected_target = target(1, 443);
    for (wire_source, reason) in [
        (None, UdpResponseDropReason::MissingWireSource),
        (
            Some(target(2, 443)),
            UdpResponseDropReason::UnexpectedWireSource,
        ),
    ] {
        let validation = UdpResponseIdentityEvidence::Decoded {
            wire_source,
            observed_identity: None,
        }
        .validate_fixed_target(UdpFixedTargetExpectation::decoded_source(expected_target));
        assert_eq!(validation, UdpFixedTargetValidation::Dropped(reason));
        assert!(!validation.should_forward());
    }
}

#[test]
fn missing_or_cross_session_identity_is_dropped() {
    let expected_target = target(1, 443);
    let expected_identity = token(b"expected-session");
    let expectation =
        UdpFixedTargetExpectation::with_protocol_identity(expected_target, expected_identity);
    for (observed_identity, reason) in [
        (None, UdpResponseDropReason::MissingProtocolIdentity),
        (
            Some(token(b"different-session")),
            UdpResponseDropReason::UnexpectedProtocolIdentity,
        ),
    ] {
        assert_eq!(
            UdpResponseIdentityEvidence::Decoded {
                wire_source: Some(expected_target),
                observed_identity,
            }
            .validate_fixed_target(expectation),
            UdpFixedTargetValidation::Dropped(reason)
        );
    }
}

#[test]
fn observed_identity_without_an_expected_session_contract_is_dropped() {
    let expected_target = target(1, 443);
    assert_eq!(
        UdpResponseIdentityEvidence::Decoded {
            wire_source: Some(expected_target),
            observed_identity: Some(token(b"unexpected-session")),
        }
        .validate_fixed_target(UdpFixedTargetExpectation::decoded_source(expected_target)),
        UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedProtocolIdentity)
    );
}

#[test]
fn protocol_decoder_rejections_remain_typed() {
    let expected_target = target(1, 443);
    for reason in [
        UdpResponseDropReason::LateResponse,
        UdpResponseDropReason::MalformedIdentity,
        UdpResponseDropReason::CrossSessionIdentity,
    ] {
        let validation = UdpExchangeResult::new(vec![1, 2, 3], "fixture")
            .with_rejected_response_identity(reason)
            .validate_fixed_target(compatibility(expected_target));
        assert_eq!(validation.drop_reason(), Some(reason));
        assert!(!validation.should_forward());
    }
}

#[test]
fn compatibility_state_is_visible_without_changing_transparent_reply_source() {
    let expected_target = target(1, 443);
    let validation = UdpResponseIdentityEvidence::CompatibilityUnverified
        .validate_fixed_target(compatibility(expected_target));
    assert_eq!(
        validation,
        UdpFixedTargetValidation::CompatibilityUnverified
    );
    assert!(validation.should_forward());
    assert_eq!(validation.label(), "compatibility-unverified");
}

#[test]
fn fixed_target_adapter_moves_the_existing_payload_without_copying() {
    let expected_target = target(1, 443);
    let payload = vec![0x5a; 1500];
    let original_ptr = payload.as_ptr();
    let mut response = UdpExchangeResult::new(payload, "fixture");

    let accepted = response.take_fixed_target_payload(compatibility(expected_target));
    assert_eq!(
        accepted.validation(),
        UdpFixedTargetValidation::CompatibilityUnverified
    );
    let payload = accepted.into_payload().unwrap();
    assert_eq!(payload.as_ptr(), original_ptr);
    assert_eq!(payload.len(), 1500);
    assert!(response.payload_for_test().is_empty());
}

#[test]
fn rejected_fixed_target_payload_is_consumed_before_forwarding() {
    let expected_target = target(1, 443);
    let mut response = UdpExchangeResult::new(vec![0x33; 4096], "fixture")
        .with_decoded_response_identity(Some(target(2, 443)), None);

    let rejected = response
        .take_fixed_target_payload(UdpFixedTargetExpectation::decoded_source(expected_target));
    assert_eq!(rejected.payload_len(), 4096);
    assert_eq!(
        rejected.validation(),
        UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
    );
    assert_eq!(
        rejected.into_payload(),
        Err(UdpResponseDropReason::UnexpectedWireSource)
    );
    assert!(response.payload_for_test().is_empty());
}

#[test]
fn opaque_identity_debug_output_does_not_expose_wire_identity() {
    let wire_identity = b"private-session-material";
    let rendered = format!("{:?}", token(wire_identity));
    assert!(!rendered.contains(std::str::from_utf8(wire_identity).unwrap()));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn producer_identity_api_does_not_accept_expected_identity() {
    assert!(!include_str!("envelope.rs").contains("expected_identity"));
}

#[test]
fn decoded_expectations_reject_compatibility_evidence() {
    let expected_target = target(1, 443);
    assert_eq!(
        UdpResponseIdentityEvidence::CompatibilityUnverified
            .validate_fixed_target(UdpFixedTargetExpectation::decoded_source(expected_target)),
        UdpFixedTargetValidation::Dropped(UdpResponseDropReason::MissingWireSource)
    );
    assert_eq!(
        UdpResponseIdentityEvidence::CompatibilityUnverified.validate_fixed_target(
            UdpFixedTargetExpectation::with_protocol_identity(
                expected_target,
                token(b"expected-session"),
            ),
        ),
        UdpFixedTargetValidation::Dropped(UdpResponseDropReason::MissingProtocolIdentity)
    );
}

#[test]
fn compatibility_expectation_rejects_decoded_evidence() {
    let expected_target = target(1, 443);
    assert_eq!(
        UdpResponseIdentityEvidence::Decoded {
            wire_source: Some(expected_target),
            observed_identity: None,
        }
        .validate_fixed_target(compatibility(expected_target)),
        UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedIdentityEvidence)
    );
}
