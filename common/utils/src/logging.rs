//! Shared tracing policy for Silo process entrypoints.
//!
//! Libraries emit events but never install subscribers. Terminal callers supply
//! stderr writers, while services retain ownership of their file/serial sinks.
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Cli { verbosity: u8 },
    Monitor,
    Harness,
    Guest,
}

/// A valid RUST_LOG overrides verbosity; missing, empty or invalid values use
/// the entrypoint's default. Accept the value explicitly to avoid env mutation
/// in tests and to keep precedence in one place.
pub fn filter(profile: Profile, rust_log: Option<&str>) -> EnvFilter {
    if let Some(filter) = rust_log
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| EnvFilter::try_new(value).ok())
    {
        return filter;
    }
    EnvFilter::new(match profile {
        Profile::Cli { verbosity: 0 } => "warn",
        Profile::Cli { verbosity: 1 } => "debug",
        Profile::Cli { .. } => "trace",
        Profile::Monitor | Profile::Harness | Profile::Guest => "info",
    })
}

pub fn subscriber<W>(profile: Profile, writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let rust_log = std::env::var("RUST_LOG").ok();
    tracing_subscriber::fmt()
        .with_env_filter(filter(profile, rust_log.as_deref()))
        .with_ansi(false)
        .with_target(matches!(profile, Profile::Harness))
        .with_level(true)
        .with_writer(writer)
        .finish()
}

/// Install once at process entry so spawned tasks use the same policy and sink.
pub fn init<W>(profile: Profile, writer: W) -> Result<(), tracing_subscriber::util::TryInitError>
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    subscriber(profile, writer).try_init()
}

#[cfg(test)]
mod tests {
    use crate::logging::{filter, Profile};

    #[test]
    fn cli_filter_uses_environment_then_verbosity_then_warn_default() {
        for (verbosity, default) in [(0, "warn"), (1, "debug"), (2, "trace"), (u8::MAX, "trace")] {
            let profile = Profile::Cli { verbosity };
            for value in [None, Some(""), Some("  "), Some("invalid[directive")] {
                assert_eq!(filter(profile, value).to_string(), default);
            }
            assert_eq!(filter(profile, Some("error")).to_string(), "error");
            assert!(filter(profile, Some("warn,libvm=debug"))
                .to_string()
                .contains("libvm=debug"));
        }
    }

    #[test]
    fn background_profiles_keep_info_unless_environment_overrides_it() {
        for profile in [Profile::Monitor, Profile::Harness, Profile::Guest] {
            assert_eq!(filter(profile, None).to_string(), "info");
            assert_eq!(filter(profile, Some("trace")).to_string(), "trace");
            assert_eq!(
                filter(profile, Some("invalid[directive")).to_string(),
                "info"
            );
        }
    }

    #[test]
    fn default_cli_filter_suppresses_in_process_info_but_keeps_warnings() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter(Profile::Cli { verbosity: 0 }, None))
            .with_ansi(false)
            .with_writer(file.reopen().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "libvm::runtime::start_timeline", "machine start timeline");
            tracing::info!(target: "libvm::machine::live_capture", "reconciled live capture");
            tracing::warn!(target: "libvm::runtime", "actionable warning");
        });
        let output = std::fs::read_to_string(file.path()).unwrap();
        assert!(!output.contains("machine start timeline"));
        assert!(!output.contains("reconciled live capture"));
        assert!(output.contains("actionable warning"));
    }
}
