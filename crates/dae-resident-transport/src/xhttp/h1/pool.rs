use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

mod maintenance;

const IDLE_TTL: Duration = Duration::from_secs(30);

pub struct XhttpH1UploadPool<T = AsyncResidentTlsClient> {
    inner: Arc<PoolInner<T>>,
    limit: usize,
}

pub(super) struct PoolInner<T> {
    idle: Mutex<Vec<(time::Instant, T)>>,
    permits: Arc<Semaphore>,
    closed: AtomicBool,
    maintenance: Mutex<Option<maintenance::Registration>>,
}

impl<T: Send + 'static> XhttpH1UploadPool<T> {
    pub fn new(limit: usize) -> Self {
        let limit = limit.max(1);
        let inner = Arc::new(PoolInner {
            idle: Mutex::new(Vec::new()),
            permits: Arc::new(Semaphore::new(limit)),
            closed: AtomicBool::new(false),
            maintenance: Mutex::new(None),
        });
        if tokio::runtime::Handle::try_current().is_ok() {
            inner.ensure_maintenance();
        }
        Self { inner, limit }
    }
}

impl<T> XhttpH1UploadPool<T> {
    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.permits.close();
        let registration = crate::owner_cleanup::cleanup_lock(&self.inner.maintenance).take();
        drop(registration);
        let idle = std::mem::take(
            &mut *self
                .inner
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        drop(idle);
    }

    pub(super) async fn take(
        &self,
    ) -> Result<(Option<T>, Arc<PoolInner<T>>, OwnedSemaphorePermit), String>
    where
        T: Send + 'static,
    {
        self.inner.ensure_maintenance();
        let permit = Arc::clone(&self.inner.permits)
            .acquire_owned()
            .await
            .map_err(|_| "xHTTP H1 upload pool is closed".to_owned())?;
        self.inner.prune_idle(time::Instant::now());
        let mut idle = self.inner.idle.lock().map_err(|_| {
            self.inner.closed.store(true, Ordering::Release);
            self.inner.permits.close();
            "xHTTP H1 upload pool lock poisoned".to_owned()
        })?;
        if self.inner.closed.load(Ordering::Acquire) {
            return Err("xHTTP H1 upload pool is closed".to_owned());
        }
        Ok((
            idle.pop().map(|(_, client)| client),
            Arc::clone(&self.inner),
            permit,
        ))
    }
}

impl<T> Drop for XhttpH1UploadPool<T> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<T: Send + 'static> PoolInner<T> {
    fn ensure_maintenance(self: &Arc<Self>) {
        let mut registration = crate::owner_cleanup::cleanup_lock(&self.maintenance);
        if !self.closed.load(Ordering::Acquire)
            && registration
                .as_ref()
                .is_none_or(|entry| !entry.is_running_on(&tokio::runtime::Handle::current()))
        {
            // Unregister before registering again, including same-executor
            // recovery after a task was cancelled during runtime shutdown.
            registration.take();
            *registration = Some(maintenance::register(
                Arc::clone(self) as Arc<dyn maintenance::IdlePool>
            ));
        }
    }
}

impl<T: Send + 'static> maintenance::IdlePool for PoolInner<T> {
    fn sweep(&self, now: time::Instant) {
        self.prune_idle(now);
    }
}

impl<T> PoolInner<T> {
    fn prune_idle(&self, now: time::Instant) {
        let expired = {
            let mut idle = crate::owner_cleanup::cleanup_lock(&self.idle);
            if self.idle.is_poisoned() {
                self.closed.store(true, Ordering::Release);
                self.permits.close();
            }
            let discard_all = self.closed.load(Ordering::Acquire);
            idle.extract_if(.., |(at, _)| {
                discard_all || now.saturating_duration_since(*at) >= IDLE_TTL
            })
            .map(|(_, client)| client)
            .collect::<Vec<_>>()
        };
        // Socket teardown must never run under an idle or maintenance-index lock.
        drop(expired);
    }

    pub(super) fn put(&self, client: T) {
        let mut idle = match self.idle.lock() {
            Ok(idle) => idle,
            Err(_) => {
                self.closed.store(true, Ordering::Release);
                self.permits.close();
                return;
            }
        };
        if !self.closed.load(Ordering::Acquire) {
            idle.push((time::Instant::now(), client));
        } else {
            drop(idle);
            drop(client);
        }
    }
}

// Only fully framed, bounded, successful responses can return a connection to
// the pool. No automatic replay after a write: the peer may already have it.
pub(super) async fn drain_response<T: AsyncRead + Unpin>(
    client: &mut T,
    response: XhttpH1ResponseHead,
) -> Result<bool, String> {
    const MAX_DRAIN: usize = 64 * 1024;
    if !response.keep_alive {
        return Ok(false);
    }
    let lengths = response
        .headers
        .iter()
        .filter(|(k, _)| k == "content-length")
        .collect::<Vec<_>>();
    let encodings = response
        .headers
        .iter()
        .filter(|(k, _)| k == "transfer-encoding")
        .collect::<Vec<_>>();
    if lengths.len() > 1 || encodings.len() > 1 || (!lengths.is_empty() && !encodings.is_empty()) {
        return Ok(false);
    }
    let prefix_len = response.body_prefix.len();
    if let Some((_, value)) = lengths.first() {
        let length: usize = value
            .parse()
            .map_err(|_| "invalid H1 response Content-Length".to_owned())?;
        if length > MAX_DRAIN || prefix_len > length {
            return Ok(false);
        }
        let mut remaining = length - prefix_len;
        let mut buffer = [0; 4096];
        while remaining != 0 {
            let count = remaining.min(buffer.len());
            client
                .read_exact(&mut buffer[..count])
                .await
                .map_err(|e| format!("drain H1 response: {e}"))?;
            remaining -= count;
        }
        return Ok(true);
    }
    if matches!(response.status, 204 | 304) {
        return Ok(prefix_len == 0);
    }
    if !encodings
        .first()
        .is_some_and(|(_, value)| value.eq_ignore_ascii_case("chunked"))
    {
        return Ok(false);
    }
    let mut reader = std::io::Cursor::new(response.body_prefix).chain(client);
    let mut consumed = 0;
    let mut buffer = [0; 4096];
    loop {
        let line = bounded_line(&mut reader, &mut consumed).await?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| "invalid H1 response chunk size".to_owned())?;
        if size == 0 {
            loop {
                if consumed > MAX_DRAIN {
                    return Ok(false);
                }
                if bounded_line(&mut reader, &mut consumed).await?.is_empty() {
                    return Ok(consumed >= prefix_len);
                }
            }
        }
        if size > MAX_DRAIN.saturating_sub(consumed) {
            return Ok(false);
        }
        let mut remaining = size;
        while remaining != 0 {
            let count = remaining.min(buffer.len());
            reader
                .read_exact(&mut buffer[..count])
                .await
                .map_err(|e| format!("drain H1 chunk: {e}"))?;
            remaining -= count;
            consumed += count;
        }
        if !bounded_line(&mut reader, &mut consumed).await?.is_empty() {
            return Err("invalid H1 chunk terminator".to_owned());
        }
    }
}

async fn bounded_line<T: AsyncRead + Unpin>(
    reader: &mut T,
    consumed: &mut usize,
) -> Result<String, String> {
    let mut line = Vec::new();
    while line.len() < MAX_CHUNK_LINE_BYTES {
        let byte = reader
            .read_u8()
            .await
            .map_err(|e| format!("read H1 chunk framing: {e}"))?;
        *consumed += 1;
        line.push(byte);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line).map_err(|_| "invalid H1 chunk framing".to_owned());
        }
    }
    Err("H1 chunk framing exceeds limit".to_owned())
}

#[cfg(test)]
mod poison_tests;
#[cfg(test)]
mod ttl_tests;
