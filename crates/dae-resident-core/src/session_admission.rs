use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde_json::{Value, json};

const UNLIMITED_SESSION_LIMIT: usize = usize::MAX;

#[derive(Clone, Debug)]
pub struct ResidentUdpSessionAdmission {
    state: Arc<ResidentUdpSessionAdmissionState>,
}

#[derive(Debug)]
struct ResidentUdpSessionAdmissionState {
    limit: AtomicUsize,
    current: AtomicUsize,
    peak: AtomicUsize,
    rejected: AtomicU64,
}

#[derive(Debug)]
pub struct ResidentUdpSessionPermit {
    state: Arc<ResidentUdpSessionAdmissionState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentUdpSessionAdmissionError {
    pub current: usize,
    pub limit: Option<usize>,
}

impl ResidentUdpSessionAdmission {
    pub fn new(limit: Option<usize>) -> Self {
        Self {
            state: Arc::new(ResidentUdpSessionAdmissionState {
                limit: AtomicUsize::new(normalize_limit(limit)),
                current: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                rejected: AtomicU64::new(0),
            }),
        }
    }

    pub fn set_limit(&self, limit: Option<usize>) {
        self.state
            .limit
            .store(normalize_limit(limit), Ordering::Release);
    }

    pub fn configured_limit(&self) -> Option<usize> {
        denormalize_limit(self.state.limit.load(Ordering::Acquire))
    }

    pub fn current(&self) -> usize {
        self.state.current.load(Ordering::Acquire)
    }

    pub fn try_acquire(
        &self,
    ) -> Result<ResidentUdpSessionPermit, ResidentUdpSessionAdmissionError> {
        let mut current = self.state.current.load(Ordering::Acquire);
        loop {
            let limit = self.state.limit.load(Ordering::Acquire);
            let Some(next) = current.checked_add(1) else {
                return Err(self.reject(current, limit));
            };
            if next > limit {
                return Err(self.reject(current, limit));
            }
            match self.state.current.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.state.peak.fetch_max(next, Ordering::Relaxed);
                    return Ok(ResidentUdpSessionPermit {
                        state: Arc::clone(&self.state),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn reject(&self, current: usize, normalized_limit: usize) -> ResidentUdpSessionAdmissionError {
        self.state.rejected.fetch_add(1, Ordering::Relaxed);
        ResidentUdpSessionAdmissionError {
            current,
            limit: denormalize_limit(normalized_limit),
        }
    }

    pub fn snapshot(&self) -> Value {
        let limit = self.configured_limit();
        json!({
            "mode": if limit.is_some() { "fixed" } else { "automatic" },
            "fixedLimit": limit,
            "current": self.current(),
            "peak": self.state.peak.load(Ordering::Relaxed),
            "rejected": self.state.rejected.load(Ordering::Relaxed),
            "scope": "resident-udp-manager",
        })
    }
}

impl ResidentUdpSessionPermit {
    pub fn current(&self) -> usize {
        self.state.current.load(Ordering::Acquire)
    }
}

impl Drop for ResidentUdpSessionPermit {
    fn drop(&mut self) {
        let _ = self
            .state
            .current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(1))
            });
    }
}

fn normalize_limit(limit: Option<usize>) -> usize {
    limit.map_or(UNLIMITED_SESSION_LIMIT, |limit| limit.max(1))
}

fn denormalize_limit(limit: usize) -> Option<usize> {
    (limit != UNLIMITED_SESSION_LIMIT).then_some(limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_admission_does_not_reject_normal_session_counts() {
        let admission = ResidentUdpSessionAdmission::new(None);
        let permits: Vec<_> = (0..1024)
            .map(|_| admission.try_acquire().unwrap())
            .collect();
        assert_eq!(admission.current(), permits.len());
        drop(permits);
        assert_eq!(admission.current(), 0);
        assert_eq!(admission.snapshot()["mode"], "automatic");
    }

    #[test]
    fn fixed_admission_is_shared_and_releases_on_drop() {
        let admission = ResidentUdpSessionAdmission::new(Some(2));
        let first = admission.try_acquire().unwrap();
        let second = admission.try_acquire().unwrap();
        assert_eq!(
            admission.try_acquire().unwrap_err(),
            ResidentUdpSessionAdmissionError {
                current: 2,
                limit: Some(2),
            }
        );
        drop(first);
        assert_eq!(admission.current(), 1);
        drop(second);
        assert_eq!(admission.current(), 0);
        assert_eq!(admission.snapshot()["peak"], 2);
    }

    #[test]
    fn changing_the_active_generation_limit_preserves_existing_permits() {
        let admission = ResidentUdpSessionAdmission::new(None);
        let retained = admission.try_acquire().unwrap();
        admission.set_limit(Some(1));
        assert!(admission.try_acquire().is_err());
        admission.set_limit(None);
        let extra = admission.try_acquire().unwrap();
        assert_eq!(admission.current(), 2);
        drop(retained);
        assert_eq!(admission.current(), 1);
        drop(extra);
        assert_eq!(admission.current(), 0);
    }
}
