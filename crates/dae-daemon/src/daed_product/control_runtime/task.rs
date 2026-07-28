use super::*;
use std::future::Future;
use std::pin::Pin;

pub(super) type ProductControlTaskFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum ProductControlTaskKind {
    Dns,
    DirectHttp,
    ProxyHttp,
    RuntimeLifecycle,
}

pub(super) struct ProductControlTaskCommand {
    pub(super) cancellation: ProductControlCancellation,
    pub(super) future: ProductControlTaskFuture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum ProductControlExecutionError {
    Busy,
    Unavailable,
    TimedOut,
}

impl std::fmt::Display for ProductControlExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => formatter.write_str("product control runtime is busy"),
            Self::Unavailable => formatter.write_str("product control runtime is unavailable"),
            Self::TimedOut => formatter.write_str("product control operation timed out"),
        }
    }
}

impl std::error::Error for ProductControlExecutionError {}

#[derive(Default)]
pub(super) struct ProductControlTaskShutdown {
    pub(super) joined: usize,
    pub(super) cancelled: usize,
    pub(super) panicked: usize,
    pub(super) forced: usize,
}

impl ProductControlTaskShutdown {
    pub(super) fn json(&self) -> Value {
        json!({
            "joined": self.joined,
            "cancelled": self.cancelled,
            "panicked": self.panicked,
            "forced": self.forced,
        })
    }
}
