#![feature(error_generic_member_access)]

pub mod proto;
mod task;
pub mod tls;
pub mod utils;

pub use utils::{CongestionControl, UdpRelayMode};

#[cfg(feature = "server")]
pub mod inbound;

#[cfg(feature = "client")]
pub mod outbound;

pub type Error = eyre::Report;
pub type Result<T> = eyre::Result<T>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version_constant() {
        assert_eq!(proto::VER, 5);
    }
    
    #[test]
    fn test_error_type() {
        let err: Error = eyre::eyre!("test error");
        assert!(err.to_string().contains("test error"));
    }
    
    #[test]
    fn test_result_type() {
        let ok_result: Result<()> = Ok(());
        assert!(ok_result.is_ok());
        
        let err_result: Result<()> = Err(eyre::eyre!("test"));
        assert!(err_result.is_err());
    }
}