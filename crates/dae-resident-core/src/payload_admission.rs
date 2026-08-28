use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde_json::{Value, json};

#[derive(Clone)]
pub struct ResidentUdpPayloadAdmission {
    generation: u64,
    state: Arc<ResidentUdpPayloadAdmissionState>,
}

struct ResidentUdpPayloadAdmissionState {
    limit: usize,
    current: AtomicUsize,
    peak: AtomicUsize,
    rejected_packets: AtomicU64,
    rejected_bytes: AtomicU64,
}

#[derive(Debug)]
pub struct ResidentUdpPayloadPermit {
    admission: ResidentUdpPayloadAdmission,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentUdpPayloadAdmissionError {
    pub requested: usize,
    pub current: usize,
    pub limit: usize,
}

impl ResidentUdpPayloadAdmission {
    pub fn new(generation: u64, limit: usize) -> Self {
        Self {
            generation,
            state: Arc::new(ResidentUdpPayloadAdmissionState {
                limit: limit.max(1),
                current: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                rejected_packets: AtomicU64::new(0),
                rejected_bytes: AtomicU64::new(0),
            }),
        }
    }

    pub fn try_acquire(
        &self,
        bytes: usize,
    ) -> Result<ResidentUdpPayloadPermit, ResidentUdpPayloadAdmissionError> {
        let mut current = self.state.current.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return Err(self.reject(bytes, current));
            };
            if next > self.state.limit {
                return Err(self.reject(bytes, current));
            }
            match self.state.current.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.state.peak.fetch_max(next, Ordering::Relaxed);
                    return Ok(ResidentUdpPayloadPermit {
                        admission: self.clone(),
                        bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn reject(&self, requested: usize, current: usize) -> ResidentUdpPayloadAdmissionError {
        self.state.rejected_packets.fetch_add(1, Ordering::Relaxed);
        self.state
            .rejected_bytes
            .fetch_add(requested.min(u64::MAX as usize) as u64, Ordering::Relaxed);
        ResidentUdpPayloadAdmissionError {
            requested,
            current,
            limit: self.state.limit,
        }
    }

    pub fn limit(&self) -> usize {
        self.state.limit
    }

    pub fn current(&self) -> usize {
        self.state.current.load(Ordering::Acquire)
    }

    pub fn snapshot(&self) -> Value {
        json!({
            "generation": self.generation,
            "limitBytes": self.state.limit,
            "currentBytes": self.current(),
            "peakBytes": self.state.peak.load(Ordering::Relaxed),
            "rejectedPackets": self.state.rejected_packets.load(Ordering::Relaxed),
            "rejectedBytes": self.state.rejected_bytes.load(Ordering::Relaxed),
        })
    }
}

impl PartialEq for ResidentUdpPayloadAdmission {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation && self.state.limit == other.state.limit
    }
}

impl Eq for ResidentUdpPayloadAdmission {}

impl fmt::Debug for ResidentUdpPayloadAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResidentUdpPayloadAdmission")
            .field("generation", &self.generation)
            .field("limit", &self.state.limit)
            .field("current", &self.current())
            .finish()
    }
}

impl Drop for ResidentUdpPayloadPermit {
    fn drop(&mut self) {
        let _ = self.admission.state.current.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| Some(current.saturating_sub(self.bytes)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_admission_releases_exactly_once_on_all_drop_paths() {
        let admission = ResidentUdpPayloadAdmission::new(7, 10);
        let first = admission.try_acquire(6).unwrap();
        assert_eq!(admission.current(), 6);
        assert_eq!(admission.try_acquire(5).unwrap_err().limit, 10);
        let second = admission.try_acquire(4).unwrap();
        assert_eq!(admission.current(), 10);
        drop(first);
        assert_eq!(admission.current(), 4);
        drop(second);
        assert_eq!(admission.current(), 0);
        assert_eq!(admission.snapshot()["peakBytes"], 10);
        assert_eq!(admission.snapshot()["rejectedPackets"], 1);
    }

    #[test]
    fn byte_admission_releases_during_panic_unwind() {
        let admission = ResidentUdpPayloadAdmission::new(8, 1024);
        let unwind_admission = admission.clone();
        let result = std::panic::catch_unwind(move || {
            let _permit = unwind_admission.try_acquire(512).unwrap();
            panic!("injected queued payload owner panic");
        });
        assert!(result.is_err());
        assert_eq!(admission.current(), 0);
    }

    #[tokio::test]
    async fn dropping_a_closed_queue_releases_queued_payload_bytes() {
        struct QueuedPayload {
            _permit: ResidentUdpPayloadPermit,
        }

        let admission = ResidentUdpPayloadAdmission::new(9, 1024);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(QueuedPayload {
                _permit: admission.try_acquire(768).unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(admission.current(), 768);
        drop(receiver);
        assert_eq!(admission.current(), 0);
    }
}
