use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use ocidisk::ImageProgress;

const BENTO_SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"];

pub(crate) struct Progress {
    bar: ProgressBar,
    finished: bool,
}

impl Progress {
    pub(crate) fn start(message: impl Into<String>) -> Self {
        let bar = ProgressBar::new_spinner();
        let style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_strings(BENTO_SPINNER_FRAMES);
        bar.set_style(style);
        bar.enable_steady_tick(Duration::from_millis(90));

        let progress = Self {
            bar,
            finished: false,
        };
        progress.step(message);
        progress
    }

    pub(crate) fn step(&self, message: impl Into<String>) {
        self.bar.set_message(message.into());
    }

    pub(crate) fn image(&self, event: ImageProgress) {
        self.step(match event {
            ImageProgress::ResolvingManifest { image_ref } => {
                format!("asking the registry about {image_ref}")
            }
            ImageProgress::HashingSource { image_ref } => {
                format!("hashing local image source for {image_ref}")
            }
            ImageProgress::ReadingArchive { image_ref } => {
                format!("reading OCI archive for {image_ref}")
            }
            ImageProgress::CheckingCache { image_ref } => {
                format!("checking image cache for {image_ref}")
            }
            ImageProgress::CacheHit { image_ref } => format!("image cache hit for {image_ref}"),
            ImageProgress::CacheMiss { image_ref } => {
                format!("cache miss for {image_ref}, building a base image")
            }
            ImageProgress::UsingLocalDisk { image_ref } => {
                format!("using local disk image for {image_ref}")
            }
            ImageProgress::PullingLayer { index, total } => {
                format!("pulling OCI layer {index}/{total}")
            }
            ImageProgress::ApplyingLayer { index, total } => {
                format!("unpacking layer {index}/{total} into ext4")
            }
            ImageProgress::WritingExt4 => "sealing ext4 base image".to_string(),
            ImageProgress::SavingBaseImage => "saving base image in the Bento cache".to_string(),
        });
    }

    pub(crate) fn success(mut self, message: impl Into<String>) {
        self.finished = true;
        self.bar.finish_with_message(message.into());
    }

    pub(crate) fn clear(mut self) {
        self.finished = true;
        self.bar.finish_and_clear();
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if !self.finished {
            self.bar.finish_and_clear();
        }
    }
}
