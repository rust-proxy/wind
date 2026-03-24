pub use const_str::concat;
pub use tracing;

#[macro_export]
macro_rules! info {
    (target: $target:expr, $($arg:tt)*) => {

		$crate::log::tracing::info!(target: $crate::log::concat!($crate::extract_crate_name!(), " ", $target), $($arg)*)
    };
    (name: $name:expr, target: $target:expr, $($arg:tt)*) => {

		$crate::log::tracing::info!(
            name: $name,
            target: $crate::log::concat!($crate::extract_crate_name!(), " ", $target),
            $($arg)*
        )
    };
    ($($arg:tt)*) => {
		$crate::log::tracing::info!(target: $crate::extract_crate_name!(), $($arg)*)
    };
}

#[macro_export]
macro_rules! warn {
    (target: $target:expr, $($arg:tt)*) => {

		$crate::log::tracing::warn!(target: $crate::log::concat!($crate::extract_crate_name!(), " ", $target), $($arg)*)
    };
    (name: $name:expr, target: $target:expr, $($arg:tt)*) => {

		$crate::log::tracing::warn!(
            name: $name,
            target: $crate::log::concat!($crate::extract_crate_name!(), " ", $target),
            $($arg)*
        )
    };
    ($($arg:tt)*) => {
		$crate::log::tracing::warn!($($arg)*)
    };
}

#[macro_export]
macro_rules! error {
    (target: $target:expr, $($arg:tt)*) => {

		$crate::log::tracing::error!(target: $crate::log::concat!($crate::extract_crate_name!(), " ", $target), $($arg)*)
    };
    (name: $name:expr, target: $target:expr, $($arg:tt)*) => {

		$crate::log::tracing::error!(
            name: $name,
            target: $crate::log::concat!($crate::extract_crate_name!(), " ", $target),
            $($arg)*
        )
    };
    ($($arg:tt)*) => {
		$crate::log::tracing::error!($($arg)*)
    };
}

/// Extract the crate name from the module path at compile time.
///
/// This macro parses `module_path!()` to extract the crate name (the part
/// before the first `::`) using only const operations, ensuring compile-time
/// evaluation.
///
/// # Implementation Notes
///
/// The original implementation had potential issues with the unsafe UTF-8
/// conversion. This version is safer and clearer while maintaining compile-time
/// evaluation.
///
/// Reference: https://github.com/Gadiguibou/current_crate_name/blob/master/src/lib.rs
#[macro_export]
macro_rules! extract_crate_name {
	() => {{
		const MODULE_PATH: &str = module_path!();
		const CRATE_NAME: &str = {
			let bytes = MODULE_PATH.as_bytes();
			let mut end_index = 0;

			// Find the first '::' or end of string
			while end_index < bytes.len() {
				// Check for ':' followed by another ':'
				if end_index + 1 < bytes.len() && bytes[end_index] == b':' && bytes[end_index + 1] == b':' {
					break;
				}
				end_index += 1;
			}

			// Create a slice with the crate name
			// SAFETY: We're slicing at character boundaries (either at '::' which are
			// ASCII, or at the end of the string). Since the original string is valid
			// UTF-8 and we only slice at ASCII character boundaries, the result is also
			// valid UTF-8.
			const fn slice_str(s: &str, end: usize) -> &str {
				let bytes = s.as_bytes();
				// This is safe because we know the input is valid UTF-8 and we slice at
				// ASCII boundaries (either at '::' or string end)
				unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(bytes.as_ptr(), end)) }
			}

			slice_str(MODULE_PATH, end_index)
		};

		CRATE_NAME
	}};
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_extract_crate_name() {
		// Test from root module
		let crate_name = extract_crate_name!();
		assert_eq!(crate_name, "wind_core");
	}

	#[test]
	fn test_extract_crate_name_with_logging() {
		// Test that the macro works in logging context
		let crate_name = extract_crate_name!();
		assert!(!crate_name.is_empty());
		assert!(!crate_name.contains("::"));
	}

	mod nested {
		#[test]
		fn test_extract_crate_name_nested() {
			// Test from nested module
			let crate_name = crate::extract_crate_name!();
			assert_eq!(crate_name, "wind_core");
		}
	}

	mod deeply {
		pub mod nested {
			pub mod module {
				#[test]
				fn test_extract_crate_name_deeply_nested() {
					// Test from deeply nested module
					let crate_name = crate::extract_crate_name!();
					assert_eq!(crate_name, "wind_core");
				}
			}
		}
	}

	#[test]
	fn test_crate_name_is_valid_identifier() {
		let crate_name = extract_crate_name!();

		// Crate name should not be empty
		assert!(!crate_name.is_empty());

		// Crate name should not contain '::'
		assert!(!crate_name.contains("::"));

		// Crate name should only contain valid identifier characters
		assert!(crate_name.chars().all(|c| c.is_alphanumeric() || c == '_'));
	}
}
