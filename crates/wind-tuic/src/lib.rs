pub mod proto;
#[cfg(feature = "quiche")]
pub mod quiche;
#[cfg(feature = "quinn")]
pub mod quinn;

pub type Error = eyre::Report;
pub type Result<T> = eyre::Result<T>;
