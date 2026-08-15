use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncRead, ReadBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UdpStreamReadMode {
    ReadyOnly,
    Wait,
}

impl UdpStreamReadMode {
    pub(super) fn waits_for_readiness(self) -> bool {
        self == Self::Wait
    }
}

pub(super) async fn read_udp_stream_once<S>(
    stream: &mut S,
    out: &mut [u8],
    mode: UdpStreamReadMode,
    label: &str,
) -> Result<Option<usize>, String>
where
    S: AsyncRead + Unpin,
{
    let mut read_buf = ReadBuf::new(out);
    poll_fn(|cx| {
        map_udp_stream_read_poll(
            mode,
            Pin::new(&mut *stream).poll_read(cx, &mut read_buf),
            read_buf.filled().len(),
            label,
        )
    })
    .await
}

pub(super) fn map_udp_stream_read_poll(
    mode: UdpStreamReadMode,
    result: Poll<io::Result<()>>,
    read: usize,
    label: &str,
) -> Poll<Result<Option<usize>, String>> {
    match result {
        Poll::Ready(Ok(())) if read == 0 => {
            Poll::Ready(Err(format!("{label}: upstream stream closed")))
        }
        Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read))),
        Poll::Ready(Err(err))
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
            ) && !mode.waits_for_readiness() =>
        {
            Poll::Ready(Ok(None))
        }
        Poll::Ready(Err(err)) => Poll::Ready(Err(format!("{label}: {err}"))),
        Poll::Pending if mode.waits_for_readiness() => Poll::Pending,
        Poll::Pending => Poll::Ready(Ok(None)),
    }
}

pub(super) async fn poll_future_once<F>(future: F) -> Option<F::Output>
where
    F: Future,
{
    tokio::pin!(future);
    poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Ready(value) => Poll::Ready(Some(value)),
        Poll::Pending => Poll::Ready(None),
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn waiting_stream_read_stays_pending_until_io_is_ready() {
        let (mut reader, mut writer) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            let mut out = [0_u8; 8];
            read_udp_stream_once(
                &mut reader,
                &mut out,
                UdpStreamReadMode::Wait,
                "fixture stream read",
            )
            .await
            .map(|read| (read, out))
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "idle stream read must not poll-complete"
        );
        writer.write_all(b"ready").await.unwrap();

        let (read, out) = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("readiness-driven stream read timeout")
            .unwrap()
            .unwrap();
        assert_eq!(read, Some(5));
        assert_eq!(&out[..5], b"ready");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_only_stream_read_returns_without_a_timer() {
        let (mut reader, _writer) = tokio::io::duplex(64);
        let mut out = [0_u8; 8];
        assert_eq!(
            read_udp_stream_once(
                &mut reader,
                &mut out,
                UdpStreamReadMode::ReadyOnly,
                "fixture stream read",
            )
            .await
            .unwrap(),
            None
        );
    }
}
