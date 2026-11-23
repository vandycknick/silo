//! Image progress semantics, separate from the reusable ordered-list renderer.

use console::Term;
use libvm::{ImageProgress, ImageProgressLayer, ImageProgressReceiver};
use tokio::task::JoinHandle;

use crate::progress_list::{Bar, ListModel, ListRenderer, ListRow};
use crate::ui::{progress_renderer, stderr_is_interactive, EchoGuard};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerStatus {
    Waiting,
    Downloading,
    Verifying,
    DownloadComplete,
    Extracting,
    PullComplete,
    AlreadyExists,
}

impl LayerStatus {
    fn text(self) -> &'static str {
        match self {
            Self::Waiting => "Waiting",
            Self::Downloading => "Downloading",
            Self::Verifying => "Verifying",
            Self::DownloadComplete => "Download complete",
            Self::Extracting => "Extracting",
            Self::PullComplete => "Pull complete",
            Self::AlreadyExists => "Already exists",
        }
    }

    fn is_final(self) -> bool {
        matches!(self, Self::PullComplete | Self::AlreadyExists)
    }
}

struct PullLayer {
    label: String,
    status: LayerStatus,
    downloaded: u64,
    size: u64,
    skipped: bool,
}

impl From<ImageProgressLayer> for PullLayer {
    fn from(layer: ImageProgressLayer) -> Self {
        let label = layer.digest.as_bytes().iter().take(6).fold(
            String::with_capacity(12),
            |mut label, byte| {
                use std::fmt::Write as _;
                let _ = write!(label, "{byte:02x}");
                label
            },
        );
        Self {
            label,
            status: LayerStatus::Waiting,
            downloaded: 0,
            size: layer.size_bytes,
            skipped: false,
        }
    }
}

impl ListRow for PullLayer {
    fn label(&self) -> &str {
        &self.label
    }
    fn status(&self) -> &str {
        self.status.text()
    }
    fn is_final(&self) -> bool {
        self.status.is_final()
    }
    fn is_active(&self) -> bool {
        matches!(
            self.status,
            LayerStatus::Downloading | LayerStatus::Verifying | LayerStatus::Extracting
        )
    }
    fn is_unstarted(&self) -> bool {
        self.status == LayerStatus::Waiting
    }
    fn bar(&self) -> Option<Bar> {
        (self.status == LayerStatus::Downloading).then_some(Bar {
            position: self.downloaded,
            length: self.size,
        })
    }
    fn counts(&self) -> Option<String> {
        (self.status == LayerStatus::Downloading).then(|| {
            format!(
                "{}/{}",
                indicatif::HumanBytes(self.downloaded),
                indicatif::HumanBytes(self.size)
            )
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum PullPhase {
    Resolving,
    Pulling,
    Checking,
    Cached,
    Using,
    Writing,
    Saving,
    Pulled,
}

impl PullPhase {
    fn word(self) -> &'static str {
        match self {
            Self::Resolving => "Resolving",
            Self::Pulling => "Pulling",
            Self::Checking => "Checking",
            Self::Cached => "Cached",
            Self::Using => "Using",
            Self::Writing => "Writing",
            Self::Saving => "Saving",
            Self::Pulled => "Pulled",
        }
    }
}

struct PullProgressState {
    reference: String,
    phase: PullPhase,
    manifest_known: bool,
    layers: Vec<PullLayer>,
}

impl PullProgressState {
    fn new(reference: &str) -> Self {
        Self {
            reference: reference.into(),
            phase: PullPhase::Pulling,
            manifest_known: false,
            layers: Vec::new(),
        }
    }

    fn layer_mut(&mut self, index: usize, total: usize) -> Option<&mut PullLayer> {
        if total != self.layers.len() {
            return None;
        }
        index
            .checked_sub(1)
            .and_then(|index| self.layers.get_mut(index))
    }

    fn finish_before(&mut self, end: usize) {
        for layer in self.layers.iter_mut().take(end) {
            if !layer.status.is_final() {
                // A skip without an actual ingest reused an already retained
                // result. Cached compressed blobs instead receive ApplyingLayer.
                layer.status = if layer.skipped && layer.status != LayerStatus::Extracting {
                    LayerStatus::AlreadyExists
                } else {
                    LayerStatus::PullComplete
                };
            }
        }
    }

    fn handle_event(&mut self, event: ImageProgress) {
        match event {
            ImageProgress::ResolvingManifest { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Resolving;
            }
            ImageProgress::ResolvedManifest {
                image_ref, layers, ..
            } => {
                self.reference = image_ref;
                self.phase = PullPhase::Pulling;
                self.manifest_known = true;
                self.layers = layers.into_iter().map(PullLayer::from).collect();
            }
            ImageProgress::CheckingCache { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Checking;
            }
            ImageProgress::CacheHit { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Cached;
                // A whole-image cache hit bypasses per-layer preflight entirely.
                for layer in &mut self.layers {
                    layer.status = LayerStatus::AlreadyExists;
                }
            }
            ImageProgress::CacheMiss { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Pulling;
            }
            ImageProgress::UsingLocalDisk { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Using;
            }
            ImageProgress::LayerDownloadStarted { index, total, .. } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if !layer.status.is_final() {
                        layer.status = LayerStatus::Downloading;
                    }
                }
            }
            ImageProgress::LayerDownloadProgress {
                index,
                total,
                downloaded_bytes,
                ..
            } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if !layer.status.is_final() {
                        layer.status = LayerStatus::Downloading;
                        layer.downloaded = layer.downloaded.max(downloaded_bytes).min(layer.size);
                    }
                }
            }
            ImageProgress::LayerDownloadVerifying { index, total, .. } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if !layer.status.is_final() {
                        layer.status = LayerStatus::Verifying;
                        layer.downloaded = layer.size;
                    }
                }
            }
            ImageProgress::LayerDownloadFinished { index, total, .. } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if !layer.status.is_final() {
                        layer.status = LayerStatus::DownloadComplete;
                        layer.downloaded = layer.size;
                    }
                }
            }
            ImageProgress::LayerDownloadSkipped { index, total, .. } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if !layer.status.is_final() {
                        layer.skipped = true;
                        layer.status = LayerStatus::DownloadComplete;
                    }
                }
            }
            ImageProgress::ApplyingLayer { index, total, .. } => {
                if total != self.layers.len() || index == 0 || index > total {
                    return;
                }
                self.finish_before(index - 1);
                if let Some(layer) = self.layer_mut(index, total) {
                    if !layer.status.is_final() {
                        layer.status = LayerStatus::Extracting;
                    }
                }
            }
            ImageProgress::MaterializingRootfs => {
                self.finish_before(self.layers.len());
                self.phase = PullPhase::Writing;
            }
            ImageProgress::PublishingRootfs => self.phase = PullPhase::Saving,
            ImageProgress::Complete => {
                self.finish_before(self.layers.len());
                self.phase = PullPhase::Pulled;
            }
        }
    }

    fn done(&self) -> usize {
        self.layers
            .iter()
            .filter(|layer| layer.status.is_final())
            .count()
    }

    fn byte_totals(&self) -> (u64, u64) {
        self.layers
            .iter()
            .fold((0_u64, 0_u64), |(downloaded, total), layer| {
                (
                    downloaded.saturating_add(layer.downloaded.min(layer.size)),
                    total.saturating_add(layer.size),
                )
            })
    }

    fn header(&self, width: usize) -> String {
        let phase = format!("{:<12} ", self.phase.word());
        let done = if self.manifest_known {
            format!("  {}/{} layers", self.done(), self.layers.len())
        } else {
            String::new()
        };
        let (downloaded, total) = self.byte_totals();
        let bytes = format!(
            "  {} / {}",
            indicatif::HumanBytes(downloaded),
            indicatif::HumanBytes(total)
        );
        let prefix_width = console::measure_text_width(&phase) + console::measure_text_width(&done);
        let suffix = if self.manifest_known
            && total > 0
            && prefix_width + console::measure_text_width(&bytes) + 12 <= width
        {
            format!("{done}{bytes}")
        } else {
            done
        };
        let reference_width = width.saturating_sub(
            console::measure_text_width(&phase) + console::measure_text_width(&suffix),
        );
        let reference = crate::progress_list::fit_line(&self.reference, reference_width);
        crate::progress_list::fit_line(&format!("{phase}{reference}{suffix}"), width)
    }

    fn summary(&self, range: std::ops::Range<usize>) -> String {
        let count = range.len();
        let noun = if count == 1 { "layer" } else { "layers" };
        let all = |status: LayerStatus| {
            self.layers
                .get(range.clone())
                .is_some_and(|layers| layers.iter().all(|layer| layer.status == status))
        };
        if range.start == 0 {
            format!("     … {count} {noun} complete")
        } else if all(LayerStatus::Waiting) {
            format!("     … {count} more {noun} waiting")
        } else if range.end < self.layers.len() && all(LayerStatus::DownloadComplete) {
            format!("     … {count} {noun} downloaded")
        } else {
            format!("     … {count} more {noun}")
        }
    }
}

pub(crate) struct PullProgressDisplay {
    renderer: Option<ListRenderer>,
    model: ListModel,
    state: PullProgressState,
    _echo_guard: Option<EchoGuard>,
}

impl PullProgressDisplay {
    fn new(reference: &str) -> Self {
        let interactive = stderr_is_interactive();
        let mut display = Self {
            renderer: interactive.then(|| ListRenderer::new(progress_renderer())),
            model: ListModel::default(),
            state: PullProgressState::new(reference),
            _echo_guard: if interactive {
                EchoGuard::acquire()
            } else {
                None
            },
        };
        display.draw();
        display
    }

    fn handle_event(&mut self, event: ImageProgress) {
        if matches!(event, ImageProgress::ResolvedManifest { .. }) {
            self.model = ListModel::default();
        }
        self.state.handle_event(event);
        self.draw();
    }

    fn draw(&mut self) {
        if let Some(renderer) = &mut self.renderer {
            let (height, columns) = Term::stderr().size();
            let width = usize::from(columns).saturating_sub(1);
            let window = self.model.window(&self.state.layers, height);
            let prefix = if width >= 5 {
                5
            } else {
                usize::from(width > 0)
            };
            renderer.draw(
                &self.state.header(width.saturating_sub(prefix)),
                &self.state.layers,
                window,
                width,
                17,
                |range| self.state.summary(range),
            );
        }
    }
}

pub(crate) fn watch_image_progress(
    reference: impl Into<String>,
    mut events: ImageProgressReceiver,
) -> JoinHandle<()> {
    let reference = reference.into();
    tokio::spawn(async move {
        let mut display = PullProgressDisplay::new(&reference);
        while let Some(event) = events.recv().await {
            display.handle_event(event);
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::progress_list::{ListModel, Window};
    use crate::pull_progress::{LayerStatus, PullProgressState};
    use libvm::{ImageProgress, ImageProgressLayer, ObjectDigest};

    fn state(total: usize) -> PullProgressState {
        let mut state = PullProgressState::new("docker.io/nixos/nix:latest");
        state.handle_event(ImageProgress::ResolvedManifest {
            image_ref: state.reference.clone(),
            manifest_digest: "sha256:manifest".into(),
            layers: (0..total)
                .map(|index| ImageProgressLayer {
                    digest: ObjectDigest::of_bytes(&index.to_le_bytes()),
                    size_bytes: 100,
                })
                .collect(),
        });
        state
    }
    fn started(index: usize, total: usize) -> ImageProgress {
        ImageProgress::LayerDownloadStarted {
            index,
            total,
            digest: "ignored".into(),
            size_bytes: Some(100),
        }
    }
    fn apply(index: usize, total: usize) -> ImageProgress {
        ImageProgress::ApplyingLayer {
            index,
            total,
            digest: None,
        }
    }
    fn skipped(index: usize, total: usize) -> ImageProgress {
        ImageProgress::LayerDownloadSkipped {
            index,
            total,
            digest: "ignored".into(),
        }
    }

    #[test]
    fn sixty_nine_layers_interleave_three_downloads_and_finish_ordered_unpack() {
        let mut state = state(69);
        let labels: Vec<_> = state
            .layers
            .iter()
            .map(|layer| layer.label.clone())
            .collect();
        for index in 1..=3 {
            state.handle_event(started(index, 69));
        }
        for index in 1..=69 {
            for active in index..=(index + 2).min(69) {
                state.handle_event(ImageProgress::LayerDownloadProgress {
                    index: active,
                    total: 69,
                    digest: "ignored".into(),
                    downloaded_bytes: 25,
                    size_bytes: Some(100),
                });
            }
            state.handle_event(ImageProgress::LayerDownloadVerifying {
                index,
                total: 69,
                digest: "ignored".into(),
            });
            state.handle_event(ImageProgress::LayerDownloadFinished {
                index,
                total: 69,
                digest: "ignored".into(),
            });
            assert_eq!(
                state.layers[index - 1].status,
                LayerStatus::DownloadComplete
            );
            state.handle_event(apply(index, 69));
            assert_eq!(state.done(), index - 1);
            if index + 3 <= 69 {
                state.handle_event(started(index + 3, 69));
            }
            let (downloaded, total) = state.byte_totals();
            assert!(downloaded <= total);
            assert_eq!(
                state
                    .layers
                    .iter()
                    .map(|layer| layer.label.clone())
                    .collect::<Vec<_>>(),
                labels
            );
        }
        state.handle_event(ImageProgress::MaterializingRootfs);
        assert_eq!(state.done(), 69);
        state.handle_event(ImageProgress::PublishingRootfs);
        state.handle_event(ImageProgress::Complete);
        assert!(state
            .layers
            .iter()
            .all(|layer| layer.status == LayerStatus::PullComplete));
        assert_eq!(state.byte_totals(), (6900, 6900));
    }

    #[test]
    fn skipped_retained_results_and_cached_blobs_have_distinct_final_states() {
        let mut state = state(4);
        for index in 1..=4 {
            state.handle_event(skipped(index, 4));
        }
        assert_eq!(state.layers[1].status, LayerStatus::DownloadComplete);
        state.handle_event(apply(2, 4));
        assert_eq!(state.layers[0].status, LayerStatus::AlreadyExists);
        assert_eq!(state.layers[1].status, LayerStatus::Extracting);
        state.handle_event(ImageProgress::MaterializingRootfs);
        assert_eq!(state.layers[1].status, LayerStatus::PullComplete);
        assert_eq!(state.layers[2].status, LayerStatus::AlreadyExists);
        assert_eq!(state.layers[3].status, LayerStatus::AlreadyExists);
        assert_eq!(state.done(), 4);
        let mut cached = state_for_cache();
        cached.handle_event(ImageProgress::CacheHit {
            image_ref: "image".into(),
        });
        cached.handle_event(ImageProgress::Complete);
        assert!(cached
            .layers
            .iter()
            .all(|layer| layer.status == LayerStatus::AlreadyExists));
    }

    fn state_for_cache() -> PullProgressState {
        state(5)
    }

    #[test]
    fn resumed_download_without_started_is_bounded_and_label_is_immutable() {
        let mut state = state(1);
        let label = state.layers[0].label.clone();
        for bytes in [60, 20, u64::MAX] {
            state.handle_event(ImageProgress::LayerDownloadProgress {
                index: 1,
                total: 1,
                digest: "different".into(),
                downloaded_bytes: bytes,
                size_bytes: Some(u64::MAX),
            });
            assert!(state.byte_totals().0 <= state.byte_totals().1);
        }
        assert_eq!(state.layers[0].downloaded, 100);
        assert_eq!(state.layers[0].status, LayerStatus::Downloading);
        assert_eq!(state.layers[0].label, label);
        state.handle_event(ImageProgress::Complete);
        assert_eq!(state.done(), 1);
    }

    #[test]
    fn invalid_indexes_are_ignored_and_empty_manifests_finish() {
        let mut state = state(2);
        for (index, total) in [(0, 2), (3, 2), (usize::MAX, 2), (1, 3)] {
            for event in [
                started(index, total),
                apply(index, total),
                skipped(index, total),
                ImageProgress::LayerDownloadProgress {
                    index,
                    total,
                    digest: "ignored".into(),
                    downloaded_bytes: 99,
                    size_bytes: Some(100),
                },
            ] {
                state.handle_event(event);
            }
        }
        assert!(state
            .layers
            .iter()
            .all(|layer| layer.status == LayerStatus::Waiting));
        assert_eq!(state.byte_totals(), (0, 200));
        let mut empty = state_for_empty();
        empty.handle_event(ImageProgress::MaterializingRootfs);
        empty.handle_event(ImageProgress::Complete);
        assert_eq!(empty.done(), 0);
        assert_eq!(empty.byte_totals(), (0, 0));
    }
    fn state_for_empty() -> PullProgressState {
        state(0)
    }

    #[test]
    fn header_and_hidden_summary_fit_and_describe_actual_hidden_rows() {
        let mut state = state(69);
        for width in 0..160 {
            assert!(console::measure_text_width(&state.header(width)) <= width);
        }
        assert!(state.header(120).contains("0/69 layers"));
        assert!(state.summary(17..69).contains("52 more layers waiting"));
        state.handle_event(started(69, 69));
        assert_eq!(state.summary(17..69), "     … 52 more layers");
        assert_eq!(state.summary(0..38), "     … 38 layers complete");
        assert!(state.layers.iter().all(|layer| layer.label.len() == 12));
    }

    #[test]
    fn header_hides_unknown_counts_and_zero_byte_totals() {
        let mut progress = PullProgressState::new("image");
        progress.handle_event(ImageProgress::ResolvingManifest {
            image_ref: "image".into(),
        });
        let header = progress.header(120);
        assert!(header.starts_with("Resolving"));
        assert!(!header.contains("layers"));
        assert!(!header.contains(" B"));
        progress.handle_event(ImageProgress::ResolvedManifest {
            image_ref: "image".into(),
            manifest_digest: "manifest".into(),
            layers: Vec::new(),
        });
        let header = progress.header(120);
        assert!(header.contains("0/0 layers"));
        assert!(!header.contains(" B"));
        progress.handle_event(ImageProgress::ResolvedManifest {
            image_ref: "image".into(),
            manifest_digest: "manifest".into(),
            layers: vec![ImageProgressLayer {
                digest: ObjectDigest::of_bytes(b"empty"),
                size_bytes: 0,
            }],
        });
        let header = progress.header(120);
        assert!(header.contains("0/1 layers"));
        assert!(!header.contains(" B"));
    }

    #[test]
    fn cache_miss_keeps_registry_acquisition_pulling_until_rootfs_materialization() {
        let mut progress = state(1);
        progress.handle_event(ImageProgress::CheckingCache {
            image_ref: "image".into(),
        });
        assert!(progress.header(120).starts_with("Checking"));
        for event in [
            ImageProgress::CacheMiss {
                image_ref: "image".into(),
            },
            started(1, 1),
            ImageProgress::LayerDownloadFinished {
                index: 1,
                total: 1,
                digest: "ignored".into(),
            },
            apply(1, 1),
        ] {
            progress.handle_event(event);
            assert!(progress.header(120).starts_with("Pulling"));
        }
        for (event, word) in [
            (ImageProgress::MaterializingRootfs, "Writing"),
            (ImageProgress::PublishingRootfs, "Saving"),
            (ImageProgress::Complete, "Pulled"),
        ] {
            progress.handle_event(event);
            assert!(progress.header(120).starts_with(word));
        }
    }

    #[test]
    fn gap_summaries_only_call_fully_downloaded_ranges_downloaded() {
        let mut progress = state(69);
        for index in 10..=40 {
            progress.handle_event(ImageProgress::LayerDownloadFinished {
                index,
                total: 69,
                digest: "ignored".into(),
            });
        }
        assert_eq!(progress.summary(9..40), "     … 31 layers downloaded");
        progress.handle_event(started(20, 69));
        assert_eq!(progress.summary(9..40), "     … 31 more layers");
    }

    fn frame(state: &PullProgressState, window: Window) -> String {
        let mut lines = vec![format!("   ⠋ {}", state.header(114))];
        for slot in 0..window.slots {
            lines.push(
                console::strip_ansi_codes(
                    &window.line(slot, &state.layers, 17, 119, |range| state.summary(range)),
                )
                .into_owned(),
            );
        }
        lines.join("\n")
    }

    #[test]
    fn sample_frames_show_separated_fronts_merge_and_unpack_tail() {
        let mut state = state(69);
        for layer in &mut state.layers {
            layer.size = 2_500_000;
        }
        let mut model = ListModel::default();
        for index in 1..=54 {
            state.handle_event(ImageProgress::LayerDownloadFinished {
                index,
                total: 69,
                digest: "ignored".into(),
            });
        }
        for index in 1..=15 {
            state.handle_event(apply(index, 69));
        }
        state.handle_event(ImageProgress::LayerDownloadVerifying {
            index: 55,
            total: 69,
            digest: "ignored".into(),
        });
        for index in 56..=57 {
            state.handle_event(started(index, 69));
            state.handle_event(ImageProgress::LayerDownloadProgress {
                index,
                total: 69,
                digest: "ignored".into(),
                downloaded_bytes: 875_000,
                size_bytes: Some(2_500_000),
            });
        }
        let window = model.window(&state.layers, 20);
        assert!(window.tail.is_some());
        let separated = frame(&state, window);
        assert_eq!(separated.split('\n').count(), 19);
        assert!(separated.contains("14/69 layers"));
        assert!(separated.contains("36 layers downloaded"));
        assert!(separated.contains("Verifying"));
        assert!(separated.contains("Downloading"));
        println!("DOWNLOAD FAR AHEAD\n{separated}");
        for index in 16..=49 {
            state.handle_event(apply(index, 69));
        }
        let window = model.window(&state.layers, 20);
        assert!(window.tail.is_none());
        let merged = frame(&state, window);
        assert_eq!(merged.split('\n').count(), 19);
        assert!(merged.contains("48/69 layers"));
        assert!(merged.contains("Verifying"));
        assert!(merged.contains("Downloading"));
        println!("FRONTS MERGED\n{merged}");
        for index in 55..=69 {
            state.handle_event(ImageProgress::LayerDownloadFinished {
                index,
                total: 69,
                digest: "ignored".into(),
            });
        }
        for index in 50..=68 {
            state.handle_event(apply(index, 69));
        }
        let window = model.window(&state.layers, 20);
        assert!(window.tail.is_none());
        let tail = frame(&state, window);
        assert_eq!(tail.split('\n').count(), 19);
        assert!(tail.contains("67/69 layers"));
        assert!(tail.contains("66 layers complete"));
        assert!(tail.contains("Extracting"));
        assert!(!tail.contains("more layers"));
        println!("UNPACK TAIL\n{tail}");
    }
}
