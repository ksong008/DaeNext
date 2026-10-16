use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counted {
    bytes: &'static [u8],
    calls: Arc<AtomicUsize>,
}
impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let len = out.remaining().min(self.bytes.len());
        out.put_slice(&self.bytes[..len]);
        self.bytes = &self.bytes[len..];
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn small_record_reads_share_one_underlying_read_and_preserve_eof() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut reader = PooledReader::new(Counted {
        bytes: b"abcdefghijkl",
        calls: calls.clone(),
    });
    assert_eq!(reader.buffer.capacity(), 0);
    let mut out = [0; 3];
    for chunk in [b"abc", b"def", b"ghi", b"jkl"] {
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, chunk);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(reader.read(&mut out).await.unwrap(), 0);
}

#[tokio::test]
async fn large_read_bypasses_lazy_storage() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut reader = PooledReader::new(Counted {
        bytes: b"abc",
        calls,
    });
    let mut out = [0; 16384];
    assert_eq!(reader.read(&mut out).await.unwrap(), 3);
    assert_eq!(reader.buffer.capacity(), 0);
}
