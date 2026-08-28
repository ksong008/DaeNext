use std::fmt;
use std::sync::Arc;

pub trait PayloadByteReservationOwner: Send + Sync {
    fn release(&self, bytes: usize);
}

pub struct PayloadByteReservation {
    owner: Arc<dyn PayloadByteReservationOwner>,
    bytes: usize,
}

impl PayloadByteReservation {
    pub fn new(owner: Arc<dyn PayloadByteReservationOwner>, bytes: usize) -> Self {
        Self { owner, bytes }
    }
}

impl fmt::Debug for PayloadByteReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PayloadByteReservation")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for PayloadByteReservation {
    fn drop(&mut self) {
        self.owner.release(self.bytes);
    }
}
