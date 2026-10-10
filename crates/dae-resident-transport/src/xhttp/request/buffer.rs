use std::sync::{Mutex, OnceLock};

static HEADS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

pub(super) fn take_head() -> String {
    HEADS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .pop()
        .unwrap_or_default()
}

pub(crate) struct RequestBuffer(Vec<u8>);
impl From<Vec<u8>> for RequestBuffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
impl std::ops::Deref for RequestBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for RequestBuffer {
    fn drop(&mut self) {
        // H1 requests consist of UTF-8 headers and arbitrary body bytes. Clearing
        // before conversion retains capacity without interpreting the body.
        if self.0.capacity() > 128 * 1024 {
            return;
        }
        self.0.clear();
        let Ok(buffer) = String::from_utf8(std::mem::take(&mut self.0)) else {
            return;
        };
        let mut pool = HEADS
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if pool.len() < 32 {
            pool.push(buffer);
        }
    }
}
