use serde::Serialize;

macro_rules! generation_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub(crate) struct $name(u64);

        impl $name {
            pub(crate) const fn new(value: u64) -> Self {
                Self(value)
            }

            pub(crate) const fn get(self) -> u64 {
                self.0
            }
        }
    };
}

generation_id!(PhysicalRuntimeId);
generation_id!(LogicalGenerationId);
generation_id!(PublicationEpoch);

impl PublicationEpoch {
    pub(crate) const INITIAL: Self = Self(1);

    pub(crate) const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct GenerationToken {
    physical: PhysicalRuntimeId,
    logical: LogicalGenerationId,
}

impl GenerationToken {
    pub(crate) const fn new(physical: PhysicalRuntimeId, logical: LogicalGenerationId) -> Self {
        Self { physical, logical }
    }

    pub(crate) const fn physical(self) -> PhysicalRuntimeId {
        self.physical
    }

    pub(crate) const fn logical(self) -> LogicalGenerationId {
        self.logical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_epoch_wraps_without_implying_numeric_order() {
        let last = PublicationEpoch::new(u64::MAX);
        assert_eq!(last.next(), PublicationEpoch::new(0));
        assert_ne!(last, last.next());
    }

    #[test]
    fn generation_token_keeps_physical_and_logical_identity_distinct() {
        let token = GenerationToken::new(PhysicalRuntimeId::new(7), LogicalGenerationId::new(11));
        assert_eq!(token.physical().get(), 7);
        assert_eq!(token.logical().get(), 11);
    }
}
