use super::{
    GenerationOwnerBoundary, GenerationOwnerSnapshot, OwnerAdmissionMetrics, OwnerGeneration,
    OwnerLifecycleSnapshot, PhysicalOwnerAdmission, RedactedOwnerIdentity,
    SingleFlightOwnerSnapshot,
};

pub const PHYSICAL_OWNER_EVIDENCE_SCHEMA: &str = "physical-owner-evidence";
pub const PHYSICAL_OWNER_EVIDENCE_SCHEMA_VERSION: u64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalOwnerEvidenceSnapshot {
    pub schema: &'static str,
    pub schema_version: u64,
    pub generation: OwnerGeneration,
    pub redacted_identity: RedactedOwnerIdentity,
    pub lifecycle: OwnerLifecycleSnapshot,
    pub admission: OwnerAdmissionMetrics,
    pub generation_owner: GenerationOwnerSnapshot,
    pub single_flight: Option<SingleFlightOwnerSnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalOwnerEvidenceError {
    GenerationMismatch,
}

impl PhysicalOwnerEvidenceSnapshot {
    pub fn capture(
        generation: OwnerGeneration,
        redacted_identity: RedactedOwnerIdentity,
        lifecycle: OwnerLifecycleSnapshot,
        admission: &PhysicalOwnerAdmission,
        generation_owner: &GenerationOwnerBoundary,
        single_flight: Option<SingleFlightOwnerSnapshot>,
    ) -> Result<Self, PhysicalOwnerEvidenceError> {
        let generation_owner = generation_owner.snapshot();
        if generation_owner.generation != generation {
            return Err(PhysicalOwnerEvidenceError::GenerationMismatch);
        }
        Ok(Self {
            schema: PHYSICAL_OWNER_EVIDENCE_SCHEMA,
            schema_version: PHYSICAL_OWNER_EVIDENCE_SCHEMA_VERSION,
            generation,
            redacted_identity,
            lifecycle,
            admission: admission.metrics(),
            generation_owner,
            single_flight,
        })
    }
}
