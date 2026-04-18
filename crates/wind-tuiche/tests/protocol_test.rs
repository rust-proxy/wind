//! Protocol tests for wind-tuiche

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use uuid::Uuid;
use wind_tuiche::proto::{
    Address, AddressCodec, CmdCodec, Command, Header, HeaderCodec,
    decode_header, decode_command, decode_address, address_to_target, CmdType,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use wind_core::types::TargetAddr;

#[test]
fn test_header_codec() {
    let header = Header::new(CmdType::Connect);
    let mut buf = BytesMut::new();
    
    let mut codec = HeaderCodec;
    codec.encode(header.clone(), &mut buf).unwrap();
    
    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(header, decoded);
}

#[test]
fn test_auth_command_codec() {
    let uuid = Uuid::new_v4();
    let token = [0xAAu8; 32];
    let cmd = Command::Auth { uuid, token };
    
    let mut buf = BytesMut::new();
    
    let mut codec = CmdCodec((&cmd).into());
    codec.encode(cmd.clone(), &mut buf).unwrap();
    
    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(cmd, decoded);
}

#[test]
fn test_packet_command_codec() {
    let cmd = Command::Packet {
        assoc_id: 123,
        pkt_id: 456,
        frag_total: 1,
        frag_id: 0,
        size: 1024,
    };
    
    let mut buf = BytesMut::new();
    
    let mut codec = CmdCodec((&cmd).into());
    codec.encode(cmd.clone(), &mut buf).unwrap();
    
    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(cmd, decoded);
}

#[test]
fn test_address_codec_ipv4() {
    let addr = Address::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
    let mut buf = BytesMut::new();
    
    let mut codec = AddressCodec;
    codec.encode(addr.clone(), &mut buf).unwrap();
    
    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(addr, decoded);
}

#[test]
fn test_address_codec_ipv6() {
    let addr = Address::IPv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443);
    let mut buf = BytesMut::new();
    
    let mut codec = AddressCodec;
    codec.encode(addr.clone(), &mut buf).unwrap();
    
    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(addr, decoded);
}

#[test]
fn test_address_codec_domain() {
    let addr = Address::Domain("example.com".to_string(), 443);
    let mut buf = BytesMut::new();
    
    let mut codec = AddressCodec;
    codec.encode(addr.clone(), &mut buf).unwrap();
    
    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(addr, decoded);
}

#[test]
fn test_decode_helpers() {
    let header = Header::new(CmdType::Heartbeat);
    let mut buf = BytesMut::new();
    
    let mut codec = HeaderCodec;
    codec.encode(header.clone(), &mut buf).unwrap();
    
    let decoded = decode_header(&mut buf, "test").unwrap();
    assert_eq!(header, decoded);
}

#[test]
fn test_address_to_target() {
    // Test IPv4
    let addr = Address::IPv4(Ipv4Addr::new(192, 168, 1, 1), 80);
    let target = address_to_target(addr).unwrap();
    assert!(matches!(target, TargetAddr::IPv4(_, 80)));
    
    // Test IPv6
    let addr = Address::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443);
    let target = address_to_target(addr).unwrap();
    assert!(matches!(target, TargetAddr::IPv6(_, 443)));
    
    // Test Domain
    let addr = Address::Domain("example.com".to_string(), 8080);
    let target = address_to_target(addr).unwrap();
    assert!(matches!(target, TargetAddr::Domain(_, 8080)));
    
    // Test None (should fail)
    let addr = Address::None;
    assert!(address_to_target(addr).is_err());
}