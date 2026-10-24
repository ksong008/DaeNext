use std::fmt;
use std::sync::Arc;

use crate::{
    ActiveGenerationSlot, GenerationFence, GenerationGate, GenerationToken, PublicationEpoch,
};

pub struct GenerationCoordinator<T> {
    active_generation: ActiveGenerationSlot<T>,
    generation_gate: Arc<GenerationGate>,
}

impl<T> Clone for GenerationCoordinator<T> {
    fn clone(&self) -> Self {
        Self {
            active_generation: self.active_generation.clone(),
            generation_gate: Arc::clone(&self.generation_gate),
        }
    }
}

impl<T> GenerationCoordinator<T> {
    pub fn with_gate(
        active_generation: ActiveGenerationSlot<T>,
        generation_gate: Arc<GenerationGate>,
    ) -> Self {
        Self {
            active_generation,
            generation_gate,
        }
    }

    pub fn active_generation_slot(&self) -> ActiveGenerationSlot<T> {
        self.active_generation.clone()
    }

    pub fn load(&self) -> Arc<T> {
        self.active_generation.load()
    }

    pub fn load_versioned(&self) -> (PublicationEpoch, Arc<T>) {
        self.active_generation.load_versioned()
    }

    pub fn subscribe_publication(&self) -> tokio::sync::watch::Receiver<PublicationEpoch> {
        self.active_generation.subscribe_publication()
    }

    pub fn generation_gate(&self) -> Arc<GenerationGate> {
        Arc::clone(&self.generation_gate)
    }

    pub fn resource_fence<U>(&self, state: U) -> GenerationFence<U> {
        self.generation_gate.resource(state)
    }

    pub fn is_active(&self, token: GenerationToken) -> bool {
        self.generation_gate.is_active(token)
    }

    /// Revalidate a versioned snapshot under the publication gate. Callbacks
    /// reserve work only; do not await or access external resources here.
    pub fn with_current<R>(
        &self,
        publication: PublicationEpoch,
        token: GenerationToken,
        expected: &Arc<T>,
        reserve: impl FnOnce(&T) -> R,
    ) -> Option<R> {
        let _gate = self.generation_gate.acquire_write(token)?;
        let (current_publication, current) = self.active_generation.load_versioned();
        if current_publication != publication || !Arc::ptr_eq(expected, &current) {
            return None;
        }
        Some(reserve(&current))
    }

    pub fn publish(&self, token: GenerationToken, generation: Arc<T>) -> Arc<T> {
        self.generation_gate
            .publish(token, &self.active_generation, generation)
    }

    pub fn publish_with(
        &self,
        token: GenerationToken,
        generation: Arc<T>,
        commit: impl FnOnce(),
    ) -> Arc<T> {
        self.generation_gate
            .switch(token, || {
                commit();
                Ok::<_, std::convert::Infallible>(
                    self.active_generation.publish_unchecked(generation),
                )
            })
            .unwrap_or_else(|error| match error {})
    }

    pub fn clear(&self) -> Option<Arc<T>> {
        self.generation_gate.clear();
        self.active_generation.clear()
    }
}

impl<T: fmt::Debug> fmt::Debug for GenerationCoordinator<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationCoordinator")
            .field("active_generation", &self.active_generation)
            .field("generation_gate", &self.generation_gate)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LogicalGenerationId, PhysicalRuntimeId};

    fn token(logical: u64) -> GenerationToken {
        GenerationToken::new(PhysicalRuntimeId::new(1), LogicalGenerationId::new(logical))
    }

    #[test]
    fn publication_switches_gate_and_keeps_previous_generation_pinned() {
        let gate = Arc::new(GenerationGate::new(Some(token(1))));
        let first = Arc::new(String::from("first"));
        let coordinator = GenerationCoordinator::with_gate(
            ActiveGenerationSlot::new(Arc::clone(&first)),
            Arc::clone(&gate),
        );
        let pinned = coordinator.load();

        let previous = coordinator.publish(token(2), Arc::new(String::from("second")));

        assert_eq!(pinned.as_str(), "first");
        assert!(Arc::ptr_eq(&previous, &first));
        assert_eq!(coordinator.load().as_str(), "second");
        assert!(coordinator.is_active(token(2)));
    }

    #[test]
    fn coordinator_exposes_the_single_publication_source() {
        let gate = Arc::new(GenerationGate::new(Some(token(1))));
        let coordinator = GenerationCoordinator::with_gate(
            ActiveGenerationSlot::new(Arc::new(String::from("first"))),
            gate,
        );
        let mut publication = coordinator.subscribe_publication();
        let initial = *publication.borrow_and_update();

        coordinator.publish(token(2), Arc::new(String::from("second")));

        assert!(coordinator.load_versioned().0 > initial);
        assert!(publication.has_changed().unwrap_or(false));
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate::{LogicalGenerationId, PhysicalRuntimeId};

    #[test]
    fn a_batch_snapshot_cannot_admit_after_publication_or_aba() {
        let token =
            |id| GenerationToken::new(PhysicalRuntimeId::new(1), LogicalGenerationId::new(id));
        let first = Arc::new(1_u64);
        let coordinator = GenerationCoordinator::with_gate(
            ActiveGenerationSlot::new(Arc::clone(&first)),
            Arc::new(GenerationGate::new(Some(token(1)))),
        );
        let (epoch, active) = coordinator.load_versioned();
        assert_eq!(
            coordinator.with_current(epoch, token(1), &active, |id| *id),
            Some(1)
        );
        coordinator.publish(token(2), Arc::new(2));
        assert_eq!(
            coordinator.with_current(epoch, token(1), &active, |id| *id),
            None
        );
        let (new_epoch, current) = coordinator.load_versioned();
        assert_eq!(
            coordinator.with_current(new_epoch, token(2), &current, |id| *id),
            Some(2)
        );
        coordinator.publish(token(1), first);
        assert_eq!(
            coordinator.with_current(epoch, token(1), &active, |id| *id),
            None
        );
    }
}
