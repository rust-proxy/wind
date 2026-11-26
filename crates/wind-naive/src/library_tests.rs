use std::{env, fs, path::Path, process::Command};

use super::{CRONET_SEARCH_PATHS, load_cronet};

#[test]
#[ignore = "requires WIND_NAIVE_CRONET_LIB pointing to a compatible shared library"]
fn process_library_conflicts() {
	if cronet_rs::sys::STATIC_LINKED {
		return;
	}
	// Each scenario needs a fresh process because the native handle lives
	// forever.
	if let Ok(scenario) = env::var("WIND_TEST_LIBRARY_SCENARIO") {
		tracing_subscriber::fmt().with_ansi(false).without_time().init();
		let active = Path::new("active").join(CRONET_SEARCH_PATHS[0]);
		let other = Path::new("other").join(CRONET_SEARCH_PATHS[0]);
		if scenario == "concurrent" {
			let barrier = std::sync::Barrier::new(2);
			std::thread::scope(|scope| {
				for path in [&active, &other] {
					let barrier = &barrier;
					scope.spawn(move || {
						barrier.wait();
						load_cronet(Some(path.to_str().unwrap().to_owned())).unwrap();
					});
				}
			});
			let actual = cronet_rs::sys::loaded_library_path().unwrap();
			assert!([active, other].iter().any(|p| p.canonicalize().unwrap() == actual));
			return;
		}
		let first = (scenario == "reload").then(|| active.to_str().unwrap().to_owned());
		load_cronet(first).unwrap();
		let actual = cronet_rs::sys::loaded_library_path().unwrap();
		assert_eq!(actual, active.canonicalize().unwrap());

		let hard_link = Path::new("aliases").join(CRONET_SEARCH_PATHS[0]);
		for alias in [
			active.to_str().unwrap(),
			"active",
			CRONET_SEARCH_PATHS[0],
			hard_link.to_str().unwrap(),
		] {
			assert!(cronet_rs::sys::conflicting_library(Path::new(alias)).is_none());
			load_cronet(Some(alias.to_owned())).unwrap();
		}
		assert_eq!(cronet_rs::sys::conflicting_library(&other), Some(actual));
		for _ in 0..2 {
			load_cronet(Some(other.to_str().unwrap().to_owned())).unwrap();
		}
		assert_eq!(cronet_rs::sys::loaded_library_path(), Some(actual));
		return;
	}

	let fixture = tempfile::tempdir().unwrap();
	let active = fixture.path().join("active");
	let other = fixture.path().join("other");
	fs::create_dir(&active).unwrap();
	fs::create_dir(&other).unwrap();
	let library = env::var_os("WIND_NAIVE_CRONET_LIB").unwrap();
	for dir in [&active, &other] {
		fs::copy(&library, dir.join(CRONET_SEARCH_PATHS[0])).unwrap();
	}
	let aliases = fixture.path().join("aliases");
	fs::create_dir(&aliases).unwrap();
	fs::hard_link(active.join(CRONET_SEARCH_PATHS[0]), aliases.join(CRONET_SEARCH_PATHS[0])).unwrap();
	let exe = active.join(env::current_exe().unwrap().file_name().unwrap());
	fs::copy(env::current_exe().unwrap(), &exe).unwrap();
	for scenario in ["default", "reload", "concurrent"] {
		if scenario == "default" && cfg!(feature = "download") {
			// Downloader builds prioritize their prebuilt over the default
			// search name.
			continue;
		}
		let output = Command::new(&exe)
			.args([
				"--exact",
				"library_tests::process_library_conflicts",
				"--ignored",
				"--nocapture",
			])
			.current_dir(fixture.path())
			.env("WIND_TEST_LIBRARY_SCENARIO", scenario)
			.env("LD_LIBRARY_PATH", &active)
			.env("DYLD_LIBRARY_PATH", &active)
			.output()
			.unwrap();
		let log = String::from_utf8_lossy(&output.stdout);
		assert!(
			output.status.success(),
			"{scenario}: {log} {}",
			String::from_utf8_lossy(&output.stderr)
		);
		let warnings: Vec<_> = log.lines().filter(|line| line.contains("Restart the process")).collect();
		assert_eq!(warnings.len(), 1, "{scenario}: {log}");
		assert!(warnings[0].contains("other") && warnings[0].contains("active"));
		if scenario != "concurrent" {
			assert!(
				warnings[0].contains(
					active
						.join(CRONET_SEARCH_PATHS[0])
						.canonicalize()
						.unwrap()
						.to_string_lossy()
						.as_ref()
				)
			);
		}
	}
}
