use crate::types::TargetAddr;
use bytes::Bytes;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct UdpPacket {
	pub source: Option<TargetAddr>,
	pub target: TargetAddr,
	pub payload: Bytes,
}

pub struct UdpStream {
	pub tx: mpsc::Sender<UdpPacket>,
	pub rx: mpsc::Receiver<UdpPacket>,
}
