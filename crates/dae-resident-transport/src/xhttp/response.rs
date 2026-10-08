use super::*;
use std::task::{Context, Poll, ready};

type ResponseFuture<T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send>>;

/// The request is already sent; response headers are read alongside the upload.
/// Some CDNs withhold headers until the origin produces data, so waiting for
/// them while opening a logical stream can prevent that stream's first write.
/// Keeping the future here also makes cancellation drop the reader immediately,
/// without a detached task or an additional payload queue.
pub enum XhttpResponseBody<T> {
    Pending(ResponseFuture<T>),
    Ready(T),
    Failed(String),
}

impl<T: Send + 'static> XhttpResponseBody<T> {
    pub(super) fn pending(
        context: &'static str,
        response: impl Future<Output = Result<T, String>> + Send + 'static,
    ) -> Self {
        let deadline = time::Instant::now() + RESIDENT_CONNECT_TIMEOUT;
        Self::Pending(Box::pin(async move {
            time::timeout_at(deadline, response)
                .await
                .map_err(|_| format!("{context} response headers timeout"))?
        }))
    }
}

impl<T> From<T> for XhttpResponseBody<T> {
    fn from(body: T) -> Self {
        Self::Ready(body)
    }
}

impl<T> XhttpResponseBody<T> {
    pub(super) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), String>> {
        let result = match self {
            Self::Pending(response) => ready!(response.as_mut().poll(cx)),
            Self::Ready(_) => return Poll::Ready(Ok(())),
            Self::Failed(error) => return Poll::Ready(Err(error.clone())),
        };
        match result {
            Ok(body) => {
                *self = Self::Ready(body);
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                *self = Self::Failed(error.clone());
                Poll::Ready(Err(error))
            }
        }
    }

    pub(super) fn ready_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Ready(body) => Some(body),
            _ => None,
        }
    }

    pub(super) async fn resolve(&mut self) -> Result<&mut T, String> {
        std::future::poll_fn(|cx| self.poll_ready(cx)).await?;
        Ok(self.ready_mut().expect("response headers resolved"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ReaderGuard(Arc<AtomicUsize>);

    impl Drop for ReaderGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn cancelling_a_read_preserves_the_pending_response() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let mut body = XhttpResponseBody::pending("test", async move {
            receiver.await.map_err(|error| error.to_string())
        });
        assert!(
            time::timeout(Duration::from_millis(5), body.resolve())
                .await
                .is_err()
        );
        sender.send(42).unwrap();
        assert_eq!(*body.resolve().await.unwrap(), 42);
        assert_eq!(*body.resolve().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn dropping_an_unread_response_releases_its_reader() {
        let released = Arc::new(AtomicUsize::new(0));
        let reader = ReaderGuard(Arc::clone(&released));
        let body = XhttpResponseBody::<()>::pending("test", async move {
            let _reader = reader;
            std::future::pending().await
        });
        drop(body);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
}
