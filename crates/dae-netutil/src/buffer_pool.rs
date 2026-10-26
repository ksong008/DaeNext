//! Shared scratch storage. Only idle buffers count against the retention budget.
//!
//! A returned buffer is filed under the widest class its capacity still
//! satisfies, so reuse survives the accidental capacity drift that `Vec`
//! growth introduces.
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const CLASSES: [usize; 5] = [4096, 16384, 32768, 65536, 131072];
const IDLE_BUDGET: usize = 4 * 1024 * 1024;
const PER_CLASS_LIMIT: usize = 32;

#[derive(Default)]
struct Pool {
    bins: [Vec<Vec<u8>>; 5],
    bytes: usize,
    acquisitions: u64,
    hits: u64,
    returns: u64,
    rejected_unclassed: u64,
    rejected_oversized: u64,
    rejected_budget: u64,
    rejected_class_full: u64,
}

static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();

impl Pool {
    /// Returns that were actually retained, derived from the rejection reasons
    /// so the categories can never disagree with the total.
    fn accepted_returns(&self) -> u64 {
        self.returns.saturating_sub(
            self.rejected_unclassed
                + self.rejected_oversized
                + self.rejected_budget
                + self.rejected_class_full,
        )
    }
}
static CONTENDED_ACQUISITIONS: AtomicU64 = AtomicU64::new(0);
static CONTENDED_RETURNS: AtomicU64 = AtomicU64::new(0);

/// Process-lifetime pool accounting, for proving that reuse actually happens.
///
/// The pool is global, so every counter is cumulative from process start.
/// `reuse_hits_per_acquisition` is the headline number: it should stay high
/// once callers return and re-acquire buffers of similar size.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PooledBufferPoolStats {
    /// Pool-eligible `with_capacity` calls that acquired the pool lock.
    pub acquisitions: u64,
    /// Acquisitions served from a bin.
    pub hits: u64,
    /// Acquisitions that had to allocate.
    pub misses: u64,
    /// `with_capacity` calls that skipped the pool because the lock was held.
    pub contended_acquisitions: u64,
    /// Drops that acquired the pool lock: returns that were considered.
    pub returns: u64,
    /// Those that acquired the pool lock and kept the buffer.
    pub accepted_returns: u64,
    /// Returns skipped because no class covers the capacity.
    pub rejected_unclassed: u64,
    /// Returns skipped because the storage is wider than its class bin retains.
    pub rejected_oversized: u64,
    /// Returns skipped because they would exceed [`IDLE_BUDGET`].
    pub rejected_budget: u64,
    /// Returns skipped because the class bin is already at its limit.
    pub rejected_class_full: u64,
    /// Drops that skipped the pool because the lock was held.
    pub contended_returns: u64,
    /// Idle bytes currently retained across all bins.
    pub idle_bytes: usize,
}

impl PooledBufferPoolStats {
    /// Share of pool-eligible acquisitions served without allocating.
    pub fn reuse_hits_per_acquisition(&self) -> f64 {
        let attempts = self.acquisitions + self.contended_acquisitions;
        if attempts == 0 {
            return 0.0;
        }
        self.hits as f64 / attempts as f64
    }
}

/// Snapshot of pool accounting. Blocks on the pool lock, so call it from
/// diagnostics rather than from a data path.
pub fn pool_stats() -> PooledBufferPoolStats {
    let mut stats = PooledBufferPoolStats {
        contended_acquisitions: CONTENDED_ACQUISITIONS.load(Ordering::Relaxed),
        contended_returns: CONTENDED_RETURNS.load(Ordering::Relaxed),
        ..PooledBufferPoolStats::default()
    };
    let pool = POOL.get_or_init(Mutex::default);
    let pool = pool
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    stats.acquisitions = pool.acquisitions;
    stats.hits = pool.hits;
    stats.misses = pool.acquisitions.saturating_sub(pool.hits);
    stats.returns = pool.returns;
    stats.accepted_returns = pool.accepted_returns();
    stats.rejected_unclassed = pool.rejected_unclassed;
    stats.rejected_oversized = pool.rejected_oversized;
    stats.rejected_budget = pool.rejected_budget;
    stats.rejected_class_full = pool.rejected_class_full;
    stats.idle_bytes = pool.bytes;
    stats
}

/// An owned buffer returned to a bounded pool when its final owner drops.
/// Empty/default buffers allocate lazily. Resizing initializes every exposed byte.
#[derive(Debug, Default)]
pub struct PooledBuffer(Vec<u8>);

impl PooledBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        let Some(class) = CLASSES.iter().position(|&size| size >= capacity) else {
            return Self(Vec::with_capacity(capacity));
        };
        if let Some(buffer) = take_pooled(class) {
            return Self(buffer);
        }
        Self(Vec::with_capacity(CLASSES[class]))
    }

    pub fn resize(&mut self, len: usize, value: u8) {
        if self.0.capacity() < len {
            let mut replacement = Self::with_capacity(len);
            replacement.extend_from_slice(&self.0);
            std::mem::swap(self, &mut replacement);
        }
        self.0.resize(len, value);
    }
}

fn take_pooled(class: usize) -> Option<Vec<u8>> {
    let pool = POOL.get_or_init(Mutex::default);
    let Ok(mut pool) = pool.try_lock() else {
        CONTENDED_ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    take_unlocked(&mut pool, class)
}

/// Serve an acquisition from `bins[class]`, attributing it to the pool totals.
///
/// Split from [`take_pooled`] so tests can drive a local [`Pool`] instead of the
/// process-global one, where concurrent `try_lock` failures make hit counting
/// non-deterministic.
fn take_unlocked(pool: &mut Pool, class: usize) -> Option<Vec<u8>> {
    pool.acquisitions += 1;
    let buffer = pool.bins[class].pop()?;
    pool.hits += 1;
    pool.bytes -= buffer.capacity();
    Some(buffer)
}

/// Largest capacity the pool keeps for reuse.
///
/// Storage wider than this is left to the allocator, as it was before drift
/// tolerance was added. `with_capacity` already bypasses the pool for requests
/// above this size, so retaining such storage could only inflate retention.
const MAX_RETAINED_CAPACITY: usize = CLASSES[CLASSES.len() - 1];

/// File a buffer under the widest class its capacity still satisfies.
///
/// `with_capacity` serves `bins[class]` only to callers that ask for at most
/// `CLASSES[class]` bytes, so a buffer wider than its class stays correct.
/// Filing it under the next larger class would hand out undersized storage.
fn return_unlocked(pool: &mut Pool, mut buffer: Vec<u8>) {
    let capacity = buffer.capacity();
    pool.returns += 1;
    let Some(class) = CLASSES.iter().rposition(|&size| size <= capacity) else {
        pool.rejected_unclassed += 1;
        return;
    };
    if capacity > MAX_RETAINED_CAPACITY {
        pool.rejected_oversized += 1;
        return;
    }
    if capacity > IDLE_BUDGET.saturating_sub(pool.bytes) {
        pool.rejected_budget += 1;
        return;
    }
    if pool.bins[class].len() >= PER_CLASS_LIMIT {
        pool.rejected_class_full += 1;
        return;
    }
    buffer.clear();
    pool.bytes += capacity;
    pool.bins[class].push(buffer);
}

impl Deref for PooledBuffer {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for PooledBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let pool = POOL.get_or_init(Mutex::default);
        let Ok(mut pool) = pool.try_lock() else {
            CONTENDED_RETURNS.fetch_add(1, Ordering::Relaxed);
            return;
        };
        return_unlocked(&mut pool, std::mem::take(&mut self.0));
    }
}

#[cfg(test)]
mod tests;
