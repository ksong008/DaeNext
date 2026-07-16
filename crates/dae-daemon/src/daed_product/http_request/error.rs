use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum HttpRequestReadErrorKind {
    IdleHeaderTimeout,
    PartialHeaderTimeout,
    BodyTimeout,
    ConnectionClosed,
    InvalidRequest,
    Io,
}

#[derive(Debug)]
pub(in crate::daed_product) struct HttpRequestReadError {
    kind: HttpRequestReadErrorKind,
    source: io::Error,
}

impl HttpRequestReadError {
    pub(super) fn new(kind: HttpRequestReadErrorKind, source: io::Error) -> Self {
        Self { kind, source }
    }

    pub(super) fn timeout(kind: HttpRequestReadErrorKind, message: &'static str) -> Self {
        Self::new(kind, io::Error::new(io::ErrorKind::TimedOut, message))
    }

    pub(super) fn invalid(source: io::Error) -> Self {
        Self::new(HttpRequestReadErrorKind::InvalidRequest, source)
    }

    pub(super) fn io(source: io::Error) -> Self {
        Self::new(HttpRequestReadErrorKind::Io, source)
    }

    pub(in crate::daed_product) fn kind(&self) -> HttpRequestReadErrorKind {
        self.kind
    }

    #[cfg(test)]
    pub(in crate::daed_product) fn io_kind(&self) -> io::ErrorKind {
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
