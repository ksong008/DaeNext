use super::*;
use std::sync::atomic::AtomicU8;

const GENERATION_ADMISSION_OPEN: u8 = 0;
const GENERATION_ADMISSION_CLOSED: u8 = 1;
const GENERATION_STOP_REQUESTED: u8 = 2;

#[derive(Debug, Default)]
pub(super) struct ResidentGenerationLifecycle {
    state: AtomicU8,
}

impl ResidentGenerationLifecycle {
    pub(super) fn admission_is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == GENERATION_ADMISSION_OPEN
    }

    pub(super) fn close_admission(&self) {
        let _ = self.state.compare_exchange(
            GENERATION_ADMISSION_OPEN,
            GENERATION_ADMISSION_CLOSED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(super) fn reopen_admission(&self) -> Result<(), &'static str> {
        match self.state.compare_exchange(
            GENERATION_ADMISSION_CLOSED,
            GENERATION_ADMISSION_OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(GENERATION_ADMISSION_OPEN) => Ok(()),
            Err(GENERATION_STOP_REQUESTED) => {
                Err("a stopped resident generation cannot accept new work")
            }
            Err(_) => Err("resident generation has an invalid lifecycle state"),
        }
    }

    pub(super) fn request_stop(&self) -> bool {
        self.state.swap(GENERATION_STOP_REQUESTED, Ordering::AcqRel) != GENERATION_STOP_REQUESTED
    }

    pub(super) fn stop_is_requested(&self) -> bool {
        self.state.load(Ordering::Acquire) == GENERATION_STOP_REQUESTED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_admission_can_close_and_reopen_before_stop() {
        let lifecycle = ResidentGenerationLifecycle::default();
        assert!(lifecycle.admission_is_open());

        lifecycle.close_admission();
        assert!(!lifecycle.admission_is_open());
        assert!(lifecycle.reopen_admission().is_ok());
        assert!(lifecycle.admission_is_open());
    }

    #[test]
    fn stopped_generation_cannot_reopen_admission() {
        let lifecycle = ResidentGenerationLifecycle::default();
        lifecycle.close_admission();
        assert!(lifecycle.request_stop());
        assert!(!lifecycle.request_stop());
        assert!(lifecycle.stop_is_requested());
        assert!(lifecycle.reopen_admission().is_err());
        assert!(!lifecycle.admission_is_open());
    }
}
