use thiserror::Error;

#[derive(Debug, Error)]
pub enum GeoDataError {
	#[error("failed to decode geodata: {0}")]
	Decode(String),
	#[error("I/O error: {0}")]
	Io(#[from] std::io::Error),
	#[error("failed to serialize rkyv snapshot")]
	Serialize,
}
