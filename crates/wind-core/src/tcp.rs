use tokio::io::{AsyncRead, AsyncWrite};

pub trait AbstractTcpStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<T> AbstractTcpStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
