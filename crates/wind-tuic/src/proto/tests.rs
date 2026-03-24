#[cfg(test)]
mod test {
	use std::net::Ipv4Addr;

	use bytes::BytesMut;
	use tokio_util::codec::Encoder as _;
	use uuid::Uuid;

	use crate::proto::{Address, AddressCodec, CmdCodec, CmdType, Command, Header, HeaderCodec};

	#[test_log::test(tokio::test)]
	async fn hex_check_connect_encode() -> eyre::Result<()> {
		let mut buffer = BytesMut::with_capacity(9);
		let addr = Address::IPv4(Ipv4Addr::LOCALHOST, 80);
		HeaderCodec.encode(Header::new(CmdType::Connect), &mut buffer)?;
		CmdCodec(CmdType::Connect).encode(Command::Connect, &mut buffer)?;
		AddressCodec.encode(addr, &mut buffer)?;

		assert_eq!("0501017f0000010050", hex::encode(buffer));
		Ok(())
	}
	#[test_log::test(tokio::test)]
	async fn hex_check_auth_encode() -> eyre::Result<()> {
		let auth_cmd = Command::Auth {
			uuid:  Uuid::from_u128(0),
			token: [1u8; 32],
		};
		let mut buf = BytesMut::with_capacity(50);
		HeaderCodec.encode(Header::new(CmdType::Auth), &mut buf)?;
		CmdCodec(CmdType::Auth).encode(auth_cmd, &mut buf)?;
		assert_eq!(
			"0500000000000000000000000000000000000101010101010101010101010101010101010101010101010101010101010101",
			hex::encode(buf)
		);
		Ok(())
	}
}
