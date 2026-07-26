use std::process::Command;

use clap::ValueEnum;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Profile {
    Debug,
    Release,
}

impl Profile {
    pub fn directory(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    pub fn apply_cargo(self, command: &mut Command) {
        if self == Self::Release {
            command.arg("--release");
        }
    }

    pub fn apply_go(self, command: &mut Command) {
        if self == Self::Release {
            command.env("CGO_ENABLED", "0").args([
                "-trimpath",
                "-buildvcs=true",
                "-ldflags",
                "-s -w",
            ]);
        }
    }
}
