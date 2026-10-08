use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const IDLE_TTL: Duration = Duration::from_secs(30);

pub struct XhttpH1UploadPool<T = AsyncResidentTlsClient> {
    inner: Arc<PoolInner<T>>,
    limit: usize,
}

pub(super) struct PoolInner<T> {
    idle: Mutex<Vec<(time::Instant, T)>>,
    permits: Arc<Semaphore>,
    closed: AtomicBool,
}

impl<T> XhttpH1UploadPool<T> {
    pub fn new(limit: usize) -> Self {
        let limit = limit.max(1);
        Self {
            inner: Arc::new(PoolInner {
                idle: Mutex::new(Vec::new()),
                permits: Arc::new(Semaphore::new(limit)),
                closed: AtomicBool::new(false),
            }),
            limit,
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.permits.close();
        self.inner.idle.lock().unwrap().clear();
    }

    pub(super) async fn take(
        &self,
    ) -> Result<(Option<T>, Arc<PoolInner<T>>, OwnedSemaphorePermit), String> {
        let permit = Arc::clone(&self.inner.permits)
            .acquire_owned()
            .await
            .map_err(|_| "xHTTP H1 upload pool is closed".to_owned())?;
        let mut idle = self.inner.idle.lock().unwrap();
        idle.retain(|(at, _)| at.elapsed() < IDLE_TTL);
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

impl<T> PoolInner<T> {
    pub(super) fn put(&self, client: T) {
        let mut idle = self.idle.lock().unwrap();
        if !self.closed.load(Ordering::Acquire) {
            idle.push((time::Instant::now(), client));
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
