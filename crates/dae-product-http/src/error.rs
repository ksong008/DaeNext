use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRequestReadErrorKind {
    IdleHeaderTimeout,
    PartialHeaderTimeout,
    BodyTimeout,
    ConnectionClosed,
    InvalidRequest,
    Io,
}

#[derive(Debug)]
pub struct HttpRequestReadError {
    kind: HttpRequestReadErrorKind,
    source: io::Error,
}

impl HttpRequestReadError {
    pub(crate) fn new(kind: HttpRequestReadErrorKind, source: io::Error) -> Self {
        Self { kind, source }
    }

    pub(crate) fn timeout(kind: HttpRequestReadErrorKind, message: &'static str) -> Self {
        Self::new(kind, io::Error::new(io::ErrorKind::TimedOut, message))
    }

    pub(crate) fn invalid(source: io::Error) -> Self {
        Self::new(HttpRequestReadErrorKind::InvalidRequest, source)
    }

    pub(crate) fn io(source: io::Error) -> Self {
        Self::new(HttpRequestReadErrorKind::Io, source)
    }

    pub fn kind(&self) -> HttpRequestReadErrorKind {
        self.kind
    }

    pub fn io_kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
}

impl std::fmt::Display for HttpRequestReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for HttpRequestReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
