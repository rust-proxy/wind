use time::macros::format_description;
use tracing::{Level, level_filters::LevelFilter};
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt as _, util::SubscriberInitExt as _};

pub fn init_log(level: Level) -> eyre::Result<()> {
	let filter = tracing_subscriber::filter::Targets::new()
		.with_targets(vec![
			("wind", level),
			("wind_core", level),
			("wind_tuic", level),
			("wind_socks", level),
		])
		.with_default(LevelFilter::INFO);
	let registry = tracing_subscriber::registry();
	registry
		.with(filter)
		.with(
			tracing_subscriber::fmt::layer()
				.with_target(true)
				.with_timer(LocalTime::new(format_description!(
					"[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
				))),
		)
		.try_init()?;

	Ok(())
}
