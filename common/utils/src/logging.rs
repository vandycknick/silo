//! Shared tracing policy for Silo process entrypoints.
//!
//! Libraries emit events but never install subscribers. Terminal callers supply
//! stderr writers, while services retain ownership of their file/serial sinks.
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Cli { verbosity: u8 },
    Monitor,
    Harness,
    Guest,
}

/// A valid RUST_LOG overrides verbosity; missing, empty or invalid values use
/// the entrypoint's default. Registry auth diagnostics require an explicit
/// oci_client::client directive even when RUST_LOG enables debug or trace.
/// Accept the value explicitly to avoid env mutation in tests.
pub fn filter<S>(profile: Profile, rust_log: Option<&str>) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    let environment = rust_log
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| EnvFilter::try_new(value).ok().map(|filter| (value, filter)));
    let (diagnostics, credential_level) = match environment {
        Some((value, filter)) => {
            let explicit_auth_target = value
                .split(',')
                .any(|directive| directive.split(['[', '=']).next() == Some("oci_client::client"));
            let credential_level = if explicit_auth_target {
                LevelFilter::TRACE
            } else {
                LevelFilter::INFO
            };
            (filter, credential_level)
        }
        None => (
            EnvFilter::new(match profile {
                Profile::Cli { verbosity: 0 } => "warn",
                Profile::Cli { verbosity: 1 } => "debug,sqlx::query=off",
                Profile::Cli { verbosity: 2 } => "debug,sqlx::query=debug",
                Profile::Cli { .. } => "trace",
                Profile::Monitor | Profile::Harness | Profile::Guest => "info",
            }),
            LevelFilter::INFO,
        ),
    };
    // A separate target cap also blocks broad span-scoped RUST_LOG directives
    // from exposing the client's DEBUG auth response (which contains tokens).
    let credentials = Targets::new()
        .with_default(LevelFilter::TRACE)
        .with_target("oci_client::client", credential_level);
    diagnostics.and_then(credentials)
}

pub fn subscriber<W>(profile: Profile, writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let rust_log = std::env::var("RUST_LOG").ok();
    tracing_subscriber::registry()
        .with(filter(profile, rust_log.as_deref()))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(matches!(profile, Profile::Harness))
                .with_level(true)
                .with_writer(writer),
        )
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
    use tracing_subscriber::layer::SubscriberExt;

    use crate::logging::{filter, Profile};

    fn capture(profile: Profile, rust_log: Option<&str>, emit: impl FnOnce()) -> String {
        let file = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(filter(profile, rust_log))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(file.reopen().unwrap()),
            );
        tracing::subscriber::with_default(subscriber, emit);
        std::fs::read_to_string(file.path()).unwrap()
    }

    fn emit_diagnostics() {
        tracing::error!(target: "libvm::runtime", "silo error");
        tracing::warn!(target: "libvm::runtime", "silo warning");
        tracing::info!(target: "libvm::runtime", "silo info");
        tracing::debug!(target: "libvm::runtime", "silo debug");
        tracing::trace!(target: "libvm::runtime", "silo trace");
        tracing::debug!(target: "third_party::client", "third-party debug");
        tracing::trace!(target: "third_party::client", "third-party trace");
        tracing::debug!(target: "sqlx::query", "SQL statement");
        tracing::warn!(target: "sqlx::query", "slow query warning");
        tracing::debug!(target: "sqlx::pool", "SQL pool diagnostics");
        tracing::info!(target: "oci_client::client", "registry info");
        tracing::debug!(target: "oci_client::client", "Making authentication call");
        tracing::debug!(
            target: "oci_client::client",
            "Received response from auth request: {{\"token\":\"test-secret\"}}"
        );
        tracing::trace!(target: "oci_client::client", "registry trace");
    }

    #[test]
    fn cli_filter_uses_environment_then_verbosity_then_warn_default() {
        for verbosity in [0, 1, 2, 3, u8::MAX] {
            let profile = Profile::Cli { verbosity };
            for value in [None, Some(""), Some("  "), Some("invalid[directive")] {
                let output = capture(profile, value, emit_diagnostics);
                assert!(output.contains("silo warning"));
                assert_eq!(output.contains("silo info"), verbosity >= 1);
                assert_eq!(output.contains("silo debug"), verbosity >= 1);
                assert_eq!(output.contains("third-party debug"), verbosity >= 1);
                assert_eq!(output.contains("SQL pool diagnostics"), verbosity >= 1);
                assert_eq!(output.contains("SQL statement"), verbosity >= 2);
                assert_eq!(output.contains("slow query warning"), verbosity != 1);
                assert_eq!(output.contains("silo trace"), verbosity >= 3);
                assert_eq!(output.contains("third-party trace"), verbosity >= 3);
                assert!(!output.contains("Making authentication call"));
                assert!(!output.contains("test-secret"));
                assert!(!output.contains("registry trace"));
                assert_eq!(output.contains("registry info"), verbosity >= 1);
            }
            let output = capture(profile, Some("error"), emit_diagnostics);
            assert!(output.contains("silo error"));
            assert!(!output.contains("silo warning"));
            assert!(!output.contains("SQL statement"));

            let output = capture(profile, Some("warn,libvm=debug"), emit_diagnostics);
            assert!(output.contains("silo debug"));
            assert!(!output.contains("third-party debug"));
            assert!(!output.contains("SQL statement"));
        }
    }

    #[test]
    fn rust_log_overrides_sql_verbosity_but_requires_explicit_auth_target() {
        for value in ["debug", "trace", "trace,oci_client=trace"] {
            let output = capture(Profile::Cli { verbosity: 0 }, Some(value), emit_diagnostics);
            assert!(output.contains("SQL statement"));
            assert!(output.contains("silo debug"));
            assert!(!output.contains("test-secret"));
            assert!(!output.contains("Making authentication call"));
        }
        let output = capture(
            Profile::Cli { verbosity: 3 },
            Some("trace,sqlx::query=off"),
            emit_diagnostics,
        );
        assert!(output.contains("silo trace"));
        assert!(!output.contains("SQL statement"));
        assert!(!output.contains("test-secret"));

        let output = capture(
            Profile::Cli { verbosity: 0 },
            Some("warn,oci_client::client=debug"),
            emit_diagnostics,
        );
        assert!(output.contains("Making authentication call"));
        assert!(output.contains("test-secret"));
        assert!(!output.contains("silo debug"));
    }

    #[test]
    fn broad_span_directives_cannot_bypass_auth_target_cap() {
        let output = capture(
            Profile::Cli { verbosity: 0 },
            Some("warn,[request]=trace"),
            || {
                let _span = tracing::info_span!("request").entered();
                emit_diagnostics();
            },
        );
        assert!(output.contains("silo trace"));
        assert!(!output.contains("test-secret"));
        assert!(!output.contains("Making authentication call"));
    }

    #[test]
    fn background_profiles_keep_info_unless_environment_overrides_it() {
        for profile in [Profile::Monitor, Profile::Harness, Profile::Guest] {
            for value in [None, Some("invalid[directive")] {
                let output = capture(profile, value, emit_diagnostics);
                assert!(output.contains("silo info"));
                assert!(!output.contains("silo debug"));
            }
            let output = capture(profile, Some("trace"), emit_diagnostics);
            assert!(output.contains("silo trace"));
            assert!(!output.contains("test-secret"));
        }
    }

    #[test]
    fn default_cli_filter_suppresses_in_process_info_but_keeps_warnings() {
        let output = capture(Profile::Cli { verbosity: 0 }, None, || {
            tracing::info!(target: "libvm::runtime::start_timeline", "machine start timeline");
            tracing::info!(target: "libvm::machine::live_capture", "reconciled live capture");
            tracing::warn!(target: "libvm::runtime", "actionable warning");
        });
        assert!(!output.contains("machine start timeline"));
        assert!(!output.contains("reconciled live capture"));
        assert!(output.contains("actionable warning"));
    }
}
