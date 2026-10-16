//! Shared scratch storage. Only idle buffers count against the retention budget.
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, OnceLock};

const CLASSES: [usize; 5] = [4096, 16384, 32768, 65536, 131072];
const IDLE_BUDGET: usize = 4 * 1024 * 1024;
const PER_CLASS_LIMIT: usize = 32;

#[derive(Default)]
struct Pool {
    bins: [Vec<Vec<u8>>; 5],
    bytes: usize,
}

static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();

/// An owned buffer returned to a bounded pool when its final owner drops.
/// Empty/default buffers allocate lazily. Resizing initializes every exposed byte.
#[derive(Debug, Default)]
pub struct PooledBuffer(Vec<u8>);

impl PooledBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        let Some(class) = CLASSES.iter().position(|&size| size >= capacity) else {
            return Self(Vec::with_capacity(capacity));
        };
        if let Ok(mut pool) = POOL.get_or_init(Mutex::default).try_lock()
            && let Some(buffer) = pool.bins[class].pop()
        {
            pool.bytes -= buffer.capacity();
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
        let capacity = self.0.capacity();
        let Some(class) = CLASSES.iter().position(|&size| size == capacity) else {
            return;
        };
        if let Ok(mut pool) = POOL.get_or_init(Mutex::default).try_lock()
            && pool.bytes + capacity <= IDLE_BUDGET
            && pool.bins[class].len() < PER_CLASS_LIMIT
        {
            self.0.clear();
            pool.bytes += capacity;
            pool.bins[class].push(std::mem::take(&mut self.0));
        }
    }
}

#[cfg(test)]
mod tests;
