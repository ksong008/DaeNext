use super::fixtures::*;
use super::*;

#[test]
fn faulting_one_owner_domain_does_not_stop_another() {
    let first_admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let second_admission = PhysicalOwnerAdmission::new(budget(1, 100));
    let cancellation = OwnerCancellationSignal::new();
    let first = first_admission
        .try_reserve(charge(40), deadline(), &cancellation)
        .unwrap();
    let second = second_admission
        .try_reserve(charge(40), deadline(), &cancellation)
        .unwrap();

    first_admission.begin_drain(OwnerDrainReason::Fault);
    drop(first);
    assert_eq!(first_admission.metrics().active_owners, 0);
    assert_eq!(second_admission.metrics().active_owners, 1);
    assert!(matches!(
        second_admission.metrics().state,
        OwnerAdmissionState::Open
    ));

    let first_cell = SingleFlightPhysicalOwner::<String>::new();
    let second_cell = SingleFlightPhysicalOwner::<String>::new();
    first_cell.fail(PhysicalOwnerFailure::new(
        OwnerFailureClass::Transport,
        "transport-driver",
    ));
    assert_eq!(first_cell.snapshot().state, PhysicalOwnerState::Failed);
    assert!(matches!(
        second_cell
            .begin_or_observe(deadline(), &cancellation)
            .unwrap(),
        SingleFlightDecision::Build(_)
    ));
    drop(second);
}

#[test]
fn evidence_schema_reconciles_generation_lifecycle_admission_and_tasks() {
    let lifecycle = PhysicalOwnerLifecycle::connecting();
    lifecycle.mark_ready().unwrap();
    let admission = PhysicalOwnerAdmission::new(budget(2, 200));
    let boundary = GenerationOwnerBoundary::new(TEST_GENERATION, identity(11));
    let single_flight = SingleFlightPhysicalOwner::<String>::new();

    let evidence = PhysicalOwnerEvidenceSnapshot::capture(
        TEST_GENERATION,
        identity(12),
        lifecycle.snapshot(),
        &admission,
        &boundary,
        Some(single_flight.snapshot()),
    )
    .unwrap();
    assert_eq!(evidence.schema, PHYSICAL_OWNER_EVIDENCE_SCHEMA);
    assert_eq!(
        evidence.schema_version,
        PHYSICAL_OWNER_EVIDENCE_SCHEMA_VERSION
    );
    assert_eq!(evidence.generation, TEST_GENERATION);
    assert_eq!(evidence.lifecycle.state, PhysicalOwnerState::Ready);
    assert_eq!(evidence.admission.active_owners, 0);

    assert_eq!(
        PhysicalOwnerEvidenceSnapshot::capture(
            OwnerGeneration::new(TEST_GENERATION.get() + 1),
            identity(12),
            lifecycle.snapshot(),
            &admission,
            &boundary,
            None,
        ),
        Err(PhysicalOwnerEvidenceError::GenerationMismatch)
    );
}
