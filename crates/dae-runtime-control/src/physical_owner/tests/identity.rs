use super::fixtures::*;
use super::*;

#[test]
fn key_projection_requires_generation_and_reports_only_a_fingerprint() {
    let key = TestOwnerKey {
        graph: 41,
        transport: 73,
        private_material: "private-test-material".to_owned(),
        fingerprint_seed: 5,
    };
    let projection = PhysicalOwnerKeyProjection::new(TEST_GENERATION, key.clone());

    assert_eq!(projection.generation(), TEST_GENERATION);
    assert_eq!(projection.key(), &key);
    let report = projection.redacted_identity().report_value();
    assert!(report.starts_with("registry:"));
    assert!(!report.contains(&key.private_material));
    assert_eq!(report.len(), "registry:".len() + 64);
}

#[test]
fn redacted_identity_rejects_namespace_delimiters() {
    assert_eq!(
        RedactedOwnerIdentity::new("", [0; 32]),
        Err(RedactedIdentityError::EmptyNamespace)
    );
    assert_eq!(
        RedactedOwnerIdentity::new("registry://authority", [0; 32]),
        Err(RedactedIdentityError::InvalidNamespace)
    );
}

#[test]
fn owner_generation_compatibility_export_has_the_shared_type_identity() {
    let shared = dae_core_types::OwnerGeneration::new(u64::MAX);
    let legacy: OwnerGeneration = shared;
    let projection = PhysicalOwnerKeyProjection::new(
        legacy,
        TestOwnerKey {
            graph: 1,
            transport: 2,
            private_material: String::new(),
            fingerprint_seed: 3,
        },
    );
    assert_eq!(projection.generation(), shared);
    assert_eq!(shared.get(), u64::MAX);
}
