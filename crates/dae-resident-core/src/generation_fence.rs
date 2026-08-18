use std::sync::{Arc, Mutex};

use crate::GenerationToken;

#[derive(Debug, Default)]
pub struct GenerationGate {
    active: Mutex<Option<GenerationToken>>,
}

impl GenerationGate {
    pub fn new(active: Option<GenerationToken>) -> Self {
        Self {
            active: Mutex::new(active),
        }
    }

    pub fn active(&self) -> Option<GenerationToken> {
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .to_owned()
    }

    pub fn is_active(&self, generation: GenerationToken) -> bool {
        self.active() == Some(generation)
    }

    pub fn switch<R, E>(
        &self,
        generation: GenerationToken,
        operation: impl FnOnce() -> Result<R, E>,
    ) -> Result<R, E> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = operation()?;
        *active = Some(generation);
        Ok(result)
    }
}

#[derive(Debug)]
pub struct GenerationFence<T> {
    gate: Arc<GenerationGate>,
    state: Mutex<T>,
}

impl<T: Default> Default for GenerationFence<T> {
    fn default() -> Self {
        Self::new(Arc::new(GenerationGate::default()), T::default())
    }
}

impl<T> GenerationFence<T> {
    pub fn new(gate: Arc<GenerationGate>, state: T) -> Self {
        Self {
            gate,
            state: Mutex::new(state),
        }
    }

    pub fn gate(&self) -> &Arc<GenerationGate> {
        &self.gate
    }

    pub fn with_active<R, E>(
        &self,
        generation: GenerationToken,
        operation: impl FnOnce(&mut T) -> Result<R, E>,
    ) -> Result<Option<R>, E> {
        let active = self
            .gate
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *active != Some(generation) {
            return Ok(None);
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        operation(&mut state).map(Some)
    }

    pub fn switch<R, E>(
        &self,
        generation: GenerationToken,
        operation: impl FnOnce(&mut T) -> Result<R, E>,
    ) -> Result<R, E> {
        self.gate.switch(generation, || {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            operation(&mut state)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LogicalGenerationId, PhysicalRuntimeId};

    fn generation(logical: u64) -> GenerationToken {
        GenerationToken::new(PhysicalRuntimeId::new(1), LogicalGenerationId::new(logical))
    }

    #[test]
    fn failed_switch_keeps_the_previous_generation() {
        let gate = GenerationGate::new(Some(generation(1)));

        let result: Result<(), &str> = gate.switch(generation(2), || Err("not ready"));

        assert_eq!(result, Err("not ready"));
        assert_eq!(gate.active(), Some(generation(1)));
    }

    #[test]
    fn resource_writes_are_rejected_after_a_generation_switch() {
        let gate = Arc::new(GenerationGate::new(Some(generation(1))));
        let fence = GenerationFence::new(Arc::clone(&gate), 0_u32);

        assert_eq!(
            fence.with_active(generation(1), |value| {
                *value += 1;
                Ok::<_, ()>(())
            }),
            Ok(Some(()))
        );
        gate.switch(generation(2), || Ok::<_, ()>(())).unwrap();
        assert_eq!(
            fence.with_active(generation(1), |_| Ok::<_, ()>(())),
            Ok(None)
        );
        assert_eq!(
            fence
                .with_active(generation(2), |value| Ok::<_, ()>(*value))
                .unwrap(),
            Some(1)
        );
    }
}
