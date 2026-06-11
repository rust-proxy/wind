use tokio::io::{AsyncRead, AsyncWrite};

/// A duplex byte stream relayed by the proxy.
///
/// `Sync` is intentionally **not** required: relay streams are always owned and
/// moved into a spawned task (which needs `Send`, not `Sync`). Requiring `Sync`
/// would exclude perfectly valid streams whose halves are joined from channel
/// senders/receivers — e.g. the quiche QUIC backend's `tokio_util::PollSender`,
/// which is `Send` but not `Sync`.
pub trait AbstractTcpStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AbstractTcpStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}
