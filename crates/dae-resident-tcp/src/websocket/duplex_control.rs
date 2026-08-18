use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::WebSocketBinaryFrameDecoder;
use crate::TcpRelayResourceProfile;

pub type WebSocketControlSender = tokio::sync::mpsc::Sender<Vec<u8>>;
pub type WebSocketControlReceiver = tokio::sync::mpsc::Receiver<Vec<u8>>;

type WebSocketControlPermitFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Vec<u8>>, mpsc::error::SendError<()>>> + Send>,
>;

pub struct WebSocketControlPollSender {
    sender: WebSocketControlSender,
    pending: VecDeque<Vec<u8>>,
    reservation: Option<WebSocketControlPermitFuture>,
}

impl WebSocketControlPollSender {
    pub fn new(sender: WebSocketControlSender) -> Self {
        Self {
            sender,
            pending: VecDeque::new(),
            reservation: None,
        }
    }

    pub fn queue_from(&mut self, decoder: &mut WebSocketBinaryFrameDecoder) {
        self.pending.extend(decoder.take_control_responses());
    }

    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.pending.is_empty() {
            if self.reservation.is_none() {
                self.reservation = Some(Box::pin(self.sender.clone().reserve_owned()));
            }
            let reservation = self
                .reservation
                .as_mut()
                .expect("websocket control reservation initialized");
            match reservation.as_mut().poll(cx) {
                Poll::Ready(Ok(permit)) => {
                    self.reservation = None;
                    let response = self
                        .pending
                        .pop_front()
                        .expect("websocket control response remained pending");
                    permit.send(response);
                }
                Poll::Ready(Err(_)) => {
                    self.reservation = None;
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "websocket control response writer is closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

pub fn websocket_control_channel() -> (WebSocketControlSender, WebSocketControlReceiver) {
    tokio::sync::mpsc::channel(TcpRelayResourceProfile::selected().websocket_control_queue_depth())
}

pub async fn queue_websocket_control_responses(
    decoder: &mut WebSocketBinaryFrameDecoder,
    sender: &WebSocketControlSender,
    context: &str,
) -> Result<(), String> {
    for response in decoder.take_control_responses() {
        sender
            .send(response)
            .await
            .map_err(|_| format!("{context} control response writer is closed"))?;
    }
    Ok(())
}

pub async fn write_websocket_control_response<W>(
    writer: &mut W,
    response: Vec<u8>,
    context: &str,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&response)
        .await
        .map_err(|error| format!("write {context} control response: {error}"))?;
    writer
        .flush()
        .await
        .map_err(|error| format!("flush {context} control response: {error}"))
}
