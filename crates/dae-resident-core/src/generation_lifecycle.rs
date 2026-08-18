use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResidentGenerationState {
    Prepared = 0,
    Active = 1,
    Retired = 2,
    Draining = 3,
    Stopped = 4,
}

impl ResidentGenerationState {
    fn from_raw(value: u8) -> Result<Self, &'static str> {
        match value {
            0 => Ok(Self::Prepared),
            1 => Ok(Self::Active),
            2 => Ok(Self::Retired),
            3 => Ok(Self::Draining),
            4 => Ok(Self::Stopped),
            _ => Err("resident generation has an invalid lifecycle state"),
        }
    }
}

#[derive(Debug)]
pub struct ResidentGenerationLifecycle {
    state: AtomicU8,
}

impl Default for ResidentGenerationLifecycle {
    fn default() -> Self {
        Self {
            state: AtomicU8::new(ResidentGenerationState::Prepared as u8),
        }
    }
}

impl ResidentGenerationLifecycle {
    pub fn state(&self) -> Result<ResidentGenerationState, &'static str> {
        ResidentGenerationState::from_raw(self.state.load(Ordering::Acquire))
    }

    pub fn admission_is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == ResidentGenerationState::Active as u8
    }

    pub fn activate(&self) -> Result<(), &'static str> {
        loop {
            let current = self.state.load(Ordering::Acquire);
            match ResidentGenerationState::from_raw(current)? {
                ResidentGenerationState::Prepared | ResidentGenerationState::Retired => {
                    if self
                        .state
                        .compare_exchange(
                            current,
                            ResidentGenerationState::Active as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
                ResidentGenerationState::Active => return Ok(()),
                ResidentGenerationState::Draining | ResidentGenerationState::Stopped => {
                    return Err("a stopped resident generation cannot accept new work");
                }
            }
        }
    }

    pub fn retire(&self) {
        let _ = self.state.compare_exchange(
            ResidentGenerationState::Active as u8,
            ResidentGenerationState::Retired as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn begin_draining(&self) -> bool {
        loop {
            let current = self.state.load(Ordering::Acquire);
            match ResidentGenerationState::from_raw(current) {
                Ok(ResidentGenerationState::Draining | ResidentGenerationState::Stopped) => {
                    return false;
                }
                Ok(_) => {
                    if self
                        .state
                        .compare_exchange(
                            current,
                            ResidentGenerationState::Draining as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    pub fn stop(&self) -> bool {
        self.state
            .swap(ResidentGenerationState::Stopped as u8, Ordering::AcqRel)
            != ResidentGenerationState::Stopped as u8
    }

    pub fn close_admission(&self) {
        self.retire();
    }

    pub fn reopen_admission(&self) -> Result<(), &'static str> {
        self.activate()
    }

    pub fn request_stop(&self) -> bool {
        self.begin_draining()
    }

    pub fn stop_is_requested(&self) -> bool {
        matches!(
            self.state(),
            Ok(ResidentGenerationState::Draining | ResidentGenerationState::Stopped)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_moves_from_prepared_through_retired_and_can_reactivate() {
        let lifecycle = ResidentGenerationLifecycle::default();
        assert_eq!(
            lifecycle.state().unwrap(),
            ResidentGenerationState::Prepared
        );
        assert!(!lifecycle.admission_is_open());

        lifecycle.activate().unwrap();
        assert_eq!(lifecycle.state().unwrap(), ResidentGenerationState::Active);
        assert!(lifecycle.admission_is_open());

        lifecycle.close_admission();
        assert_eq!(lifecycle.state().unwrap(), ResidentGenerationState::Retired);
        assert!(!lifecycle.admission_is_open());
        lifecycle.reopen_admission().unwrap();
        assert_eq!(lifecycle.state().unwrap(), ResidentGenerationState::Active);
    }

    #[test]
    fn draining_and_stopped_generations_cannot_reactivate() {
        let lifecycle = ResidentGenerationLifecycle::default();
        lifecycle.activate().unwrap();
        lifecycle.close_admission();
        assert!(lifecycle.request_stop());
        assert!(!lifecycle.request_stop());
        assert_eq!(
            lifecycle.state().unwrap(),
            ResidentGenerationState::Draining
        );
        assert!(lifecycle.stop_is_requested());
        assert!(lifecycle.reopen_admission().is_err());

        assert!(lifecycle.stop());
        assert!(!lifecycle.stop());
        assert_eq!(lifecycle.state().unwrap(), ResidentGenerationState::Stopped);
        assert!(lifecycle.reopen_admission().is_err());
    }
}
