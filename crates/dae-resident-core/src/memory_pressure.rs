use std::sync::atomic::{AtomicBool, Ordering};

// Published by the process telemetry sampler independently of allocator purges.
static MEMORY_PRESSURE: AtomicBool = AtomicBool::new(false);

pub fn set_resident_memory_pressure(pressured: bool) {
    MEMORY_PRESSURE.store(pressured, Ordering::Release);
}

pub fn resident_memory_pressure() -> bool {
    MEMORY_PRESSURE.load(Ordering::Acquire)
}
