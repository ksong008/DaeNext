use super::*;

#[tokio::test]
async fn emits_available_bytes_then_grows_only_after_a_full_batch() {
    let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
    let mut buffer = TlsDownloadBuffer::new(64 * 1024);

    writer.write_all(b"short").await.unwrap();
    let short = buffer.read(&mut reader).await.unwrap();
    assert_eq!(short, b"short");
    buffer.grow_after_write(5);
    assert_eq!(buffer.bytes.len(), TLS_DOWNLOAD_INITIAL_BYTES);

    writer.write_all(&vec![42; 64 * 1024]).await.unwrap();
    assert_eq!(buffer.read(&mut reader).await.unwrap(), &[42; 16 * 1024]);
    buffer.grow_after_write(16 * 1024);
    assert_eq!(buffer.bytes.len(), 64 * 1024);

    writer.shutdown().await.unwrap();
    assert_eq!(buffer.read(&mut reader).await.unwrap(), &[42; 48 * 1024]);
    assert!(buffer.read(&mut reader).await.unwrap().is_empty());
}

#[tokio::test]
async fn low_memory_limit_keeps_the_initial_buffer() {
    let mut buffer = TlsDownloadBuffer::new(TLS_DOWNLOAD_INITIAL_BYTES);
    let mut reader = &vec![7; 2 * TLS_DOWNLOAD_INITIAL_BYTES][..];
    assert_eq!(buffer.read(&mut reader).await.unwrap().len(), 16 * 1024);
    buffer.grow_after_write(16 * 1024);
    assert_eq!(buffer.bytes.len(), TLS_DOWNLOAD_INITIAL_BYTES);
    assert_eq!(buffer.read(&mut reader).await.unwrap().len(), 16 * 1024);
}

#[tokio::test]
async fn yields_plaintext_before_a_read_error() {
    struct BytesThenError(bool);

    impl AsyncRead for BytesThenError {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if std::mem::replace(&mut self.0, true) {
                return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            buf.put_slice(b"before reset");
            Poll::Ready(Ok(()))
        }
    }

    let mut buffer = TlsDownloadBuffer::new(64 * 1024);
    let mut reader = BytesThenError(false);
    assert_eq!(buffer.read(&mut reader).await.unwrap(), b"before reset");
    assert_eq!(
        buffer.read(&mut reader).await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionReset
    );
}
