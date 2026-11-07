//! Held-file qcow2 admission and decoding for the independent qemu-img oracle.
//! Never launches a VM or touches a Silo store.
//!
//! ```text
//!  qcow2_decode SOURCE DEST
//!
//!  open SOURCE read-only ─► admit ─► staging file beside DEST ─► decode ─► sync
//!                             │                                    │         │
//!                   rejected, exit 2              failed, exit 1: staging    ▼
//!                   nothing created               removed, DEST untouched   no-clobber
//!                                                                           rename to DEST
//! ```
//!
//! stdout carries exactly one JSON object describing the outcome. DEST exists
//! only after a complete, flushed and synced decode; it is never replaced.

fn main() -> std::process::ExitCode {
    held::main()
}

mod held {
    use std::fmt;
    use std::fs::File;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use disk_image::qcow2::{self, Admission, Version};

    const STAGING_PREFIX: &str = ".qcow2-decode-";
    const EXIT_REJECTED: u8 = 2;

    #[derive(Debug, Clone, Copy)]
    enum Stage {
        Usage,
        Open,
        Admit,
        Staging,
        Decode,
        Publish,
    }

    impl Stage {
        fn name(self) -> &'static str {
            match self {
                Self::Usage => "usage",
                Self::Open => "open",
                Self::Admit => "admit",
                Self::Staging => "staging",
                Self::Decode => "decode",
                Self::Publish => "publish",
            }
        }
    }

    struct Failure {
        stage: Stage,
        debug: String,
        error: String,
    }

    impl Failure {
        fn new<E: fmt::Debug + fmt::Display>(stage: Stage, error: E) -> Self {
            Self {
                stage,
                debug: format!("{error:?}"),
                error: error.to_string(),
            }
        }

        fn usage() -> Self {
            let message = "usage: qcow2_decode SOURCE DEST";
            Self {
                stage: Stage::Usage,
                debug: message.to_owned(),
                error: message.to_owned(),
            }
        }
    }

    pub(crate) fn main() -> ExitCode {
        match run() {
            Ok(admission) => {
                let version = match admission.version() {
                    Version::V2 => 2,
                    Version::V3 => 3,
                };
                let _ = writeln!(
                    io::stdout().lock(),
                    "{{\"result\":\"decoded\",\"version\":{version},\"cluster_size\":{},\"virtual_size\":{},\"source_len\":{}}}",
                    admission.cluster_size(),
                    admission.virtual_size(),
                    admission.source_len(),
                );
                ExitCode::SUCCESS
            }
            Err(failure) => {
                // Admission refuses the input itself; every later stage is a
                // failed conversion of an admitted input.
                let (result, code) = match failure.stage {
                    Stage::Admit => ("rejected", ExitCode::from(EXIT_REJECTED)),
                    _ => ("failed", ExitCode::FAILURE),
                };
                let _ = writeln!(
                    io::stdout().lock(),
                    "{{\"result\":\"{result}\",\"stage\":\"{}\",\"debug\":{},\"error\":{}}}",
                    failure.stage.name(),
                    json_string(&failure.debug),
                    json_string(&failure.error),
                );
                let _ = writeln!(
                    io::stderr().lock(),
                    "qcow2_decode: {} {result}: {}",
                    failure.stage.name(),
                    failure.error,
                );
                code
            }
        }
    }

    fn run() -> Result<Admission, Failure> {
        let mut arguments = std::env::args_os().skip(1);
        let (Some(source), Some(destination), None) =
            (arguments.next(), arguments.next(), arguments.next())
        else {
            return Err(Failure::usage());
        };
        let destination = PathBuf::from(destination);
        let parent = match destination.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };

        let source = File::open(source).map_err(|error| Failure::new(Stage::Open, error))?;
        let admission = qcow2::admit(&source).map_err(|error| Failure::new(Stage::Admit, error))?;

        // Dropping the staging file on any later error unlinks it, so a
        // partial stream is never left behind or published.
        let mut staging = tempfile::Builder::new()
            .prefix(STAGING_PREFIX)
            .suffix(".partial")
            .tempfile_in(parent)
            .map_err(|error| Failure::new(Stage::Staging, error))?;
        qcow2::decode(&source, &admission, &mut staging)
            .map_err(|error| Failure::new(Stage::Decode, error))?;
        staging
            .as_file()
            .sync_all()
            .map_err(|error| Failure::new(Stage::Publish, error))?;
        staging
            .persist_noclobber(&destination)
            .map_err(|error| Failure::new(Stage::Publish, error.error))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| Failure::new(Stage::Publish, error))?;
        Ok(admission)
    }

    fn json_string(value: &str) -> String {
        let mut quoted = String::with_capacity(value.len() + 2);
        quoted.push('"');
        for character in value.chars() {
            match character {
                '"' => quoted.push_str("\\\""),
                '\\' => quoted.push_str("\\\\"),
                '\n' => quoted.push_str("\\n"),
                '\r' => quoted.push_str("\\r"),
                '\t' => quoted.push_str("\\t"),
                control if u32::from(control) < 0x20 => {
                    let _ = fmt::Write::write_fmt(
                        &mut quoted,
                        format_args!("\\u{:04x}", u32::from(control)),
                    );
                }
                other => quoted.push(other),
            }
        }
        quoted.push('"');
        quoted
    }
}
