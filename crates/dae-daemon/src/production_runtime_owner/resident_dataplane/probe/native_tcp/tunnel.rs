use tokio::io::{AsyncRead, AsyncWrite};

pub(super) trait NativeTcpTunnel: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NativeTcpTunnel for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
