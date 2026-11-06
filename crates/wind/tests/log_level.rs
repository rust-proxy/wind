//! End-to-end checks that `--log-level` is parsed and actually governs the
//! global tracing subscriber.
//!
//! These run the real binary (Cargo provides `CARGO_BIN_EXE_wind` for
//! integration tests) with an empty working directory, so no ambient config can
//! influence the run. `--version` exits successfully after logging is
//! configured: the diagnostic `Wind starting` line must be filtered out at
//! `error`, while the version output proves that the binary actually ran.

use std::process::Command;

/// Run the binary with `args` from an empty, per-test working directory.
fn run_wind(args: &[&str]) -> std::process::Output {
	let exe = env!("CARGO_BIN_EXE_wind");
	// Cross wraps the test harness, but Command does not inherit Cargo's
	// runner. Its images expose a whitespace-separated runner command (e.g.
	// `/linux-runner aarch64`); use it for the child binary as well.
	let mut command = match std::env::var("CROSS_TARGET_RUNNER") {
		Ok(runner) => {
			let mut parts = runner.split_whitespace();
			let mut command = Command::new(parts.next().expect("CROSS_TARGET_RUNNER must not be empty"));
			command.args(parts).arg(exe);
			command
		}
		Err(std::env::VarError::NotPresent) => Command::new(exe),
		Err(err) => panic!("invalid CROSS_TARGET_RUNNER: {err}"),
	};
	let dir = std::env::temp_dir().join(format!("wind-log-level-{}-{}", std::process::id(), args.join("_")));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).expect("the scratch working directory must be creatable");
	let output = command
		.args(args)
		.current_dir(&dir)
		.output()
		.expect("the wind binary must be runnable");
	let _ = std::fs::remove_dir_all(&dir);
	output
}

fn stdout(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_version_succeeded(output: &std::process::Output) {
	assert!(
		output.status.success(),
		"--version must exit 0, status: {}, stdout: {}, stderr: {}",
		output.status,
		stdout(output),
		stderr(output)
	);
	assert!(
		stdout(output).lines().any(|line| line.starts_with("wind ")),
		"--version must print the version, got stdout: {}",
		stdout(output)
	);
}

#[test]
fn binary_help_documents_the_log_level_flag() {
	let output = run_wind(&["--help"]);
	assert!(output.status.success(), "--help must exit 0, stderr: {}", stderr(&output));
	assert!(
		stdout(&output).contains("--log-level"),
		"--help must document --log-level, got: {}",
		stdout(&output)
	);
}

#[test]
fn error_level_suppresses_the_info_startup_line() {
	let output = run_wind(&["--version", "--log-level", "error"]);
	assert_version_succeeded(&output);
	let out = stdout(&output);
	assert!(
		!out.contains("Wind starting"),
		"--log-level error must suppress the INFO `Wind starting` line, got stdout: {out}"
	);
}

#[test]
fn default_and_info_levels_emit_the_info_startup_line() {
	for args in [vec!["--version"], vec!["--version", "--log-level", "info"]] {
		let output = run_wind(&args);
		assert_version_succeeded(&output);
		let out = stdout(&output);
		assert!(
			out.contains("Wind starting"),
			"wind {args:?} must log at info by default, got stdout: {out}"
		);
	}
}

#[test]
fn unknown_level_is_rejected_before_any_work_is_done() {
	let output = run_wind(&["--log-level", "verbose"]);
	assert_eq!(
		output.status.code(),
		Some(2),
		"an unknown --log-level must be a clap usage error (exit 2), stderr: {}",
		stderr(&output)
	);
	let err = stderr(&output);
	assert!(
		err.contains("verbose") && err.contains("--log-level"),
		"the usage error must name the rejected value and the flag, got: {err}"
	);
}
