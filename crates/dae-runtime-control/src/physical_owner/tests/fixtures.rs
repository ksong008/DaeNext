use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use super::*;

pub(super) const TEST_GENERATION: OwnerGeneration = OwnerGeneration::new(17);
const TEST_DEADLINE_WINDOW: Duration = Duration::from_secs(30);

pub(super) fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::from_now(Instant::now(), TEST_DEADLINE_WINDOW)
}

pub(super) fn budget(count: usize, charged_bytes: usize) -> OwnerResourceBudget {
    OwnerResourceBudget::new(
        NonZeroUsize::new(count).unwrap(),
        NonZeroUsize::new(charged_bytes).unwrap(),
    )
}

pub(super) fn charge(charged_bytes: usize) -> ChargedOwnerBytes {
    ChargedOwnerBytes::new(NonZeroUsize::new(charged_bytes).unwrap())
}

pub(super) fn identity(seed: u8) -> RedactedOwnerIdentity {
    RedactedOwnerIdentity::new("registry", [seed; 32]).unwrap()
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct TestOwnerKey {
    pub graph: u64,
    pub transport: u64,
    pub private_material: String,
    pub fingerprint_seed: u8,
}

impl PhysicalOwnerKey for TestOwnerKey {
    fn redacted_identity(&self) -> RedactedOwnerIdentity {
        identity(self.fingerprint_seed)
    }
}
