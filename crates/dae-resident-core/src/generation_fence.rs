use std::sync::{Arc, Mutex, MutexGuard};

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

    pub fn acquire_write(&self, generation: GenerationToken) -> Option<GenerationWritePermit<'_>> {
        let active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *active != Some(generation) {
            return None;
        }
        Some(GenerationWritePermit {
            generation,
            _active: active,
        })
    }

    pub fn with_active<R, E>(
        &self,
        generation: GenerationToken,
        operation: impl FnOnce() -> Result<R, E>,
    ) -> Result<Option<R>, E> {
        let Some(_permit) = self.acquire_write(generation) else {
            return Ok(None);
        };
        operation().map(Some)
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

pub struct GenerationWritePermit<'a> {
    generation: GenerationToken,
    _active: MutexGuard<'a, Option<GenerationToken>>,
}

impl GenerationWritePermit<'_> {
    pub fn generation(&self) -> GenerationToken {
        self.generation
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
        self.gate.with_active(generation, || {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            operation(&mut state)
        })
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

    #[test]
    fn write_permit_is_shared_and_generation_scoped() {
        let first = generation(1);
        let second = generation(2);
        let gate = GenerationGate::new(Some(first));

        assert!(gate.acquire_write(second).is_none());
        let permit = gate
            .acquire_write(first)
            .expect("active generation write permit");
        assert_eq!(permit.generation(), first);
        drop(permit);

        gate.switch(second, || Ok::<_, ()>(())).unwrap();
        assert!(gate.acquire_write(first).is_none());
        assert_eq!(gate.acquire_write(second).unwrap().generation(), second);
    }

    #[test]
    fn generation_switch_waits_for_an_in_flight_resource_write() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let first = generation(1);
        let second = generation(2);
        let gate = Arc::new(GenerationGate::new(Some(first)));
        let fence = Arc::new(GenerationFence::new(Arc::clone(&gate), 0_u32));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));

        let writer_fence = Arc::clone(&fence);
        let writer_entered = Arc::clone(&entered);
        let writer_release = Arc::clone(&release);
        let writer = thread::spawn(move || {
            writer_fence
                .with_active(first, |value| {
                    writer_entered.wait();
                    writer_release.wait();
                    *value = 1;
                    Ok::<_, ()>(())
                })
                .unwrap();
        });
        entered.wait();

        let switch_gate = Arc::clone(&gate);
        let switch = thread::spawn(move || switch_gate.switch(second, || Ok::<_, ()>(())));
        release.wait();
        writer.join().unwrap();
        switch.join().unwrap().unwrap();

        assert_eq!(
            fence
                .with_active(second, |value| Ok::<_, ()>(*value))
                .unwrap(),
            Some(1)
        );
    }
}
