use std::fmt;
use std::sync::Arc;

/// One manifest-ordered occurrence of a compressed source blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestLayer {
    pub digest: crate::changeset::ContentDigest,
    pub size_bytes: u64,
}

/// After manifest resolution, up to three layer downloads may interleave.
/// For each 1-based index, downloads emit either `LayerDownloadSkipped` or
/// `LayerDownloadStarted`, zero or more progress events, verifying, finished.
/// A complete resumed partial file may emit only verifying and finished.
/// Before downloads start, libvm emits skipped events for every retained or
/// repeated occurrence that needs no source I/O. Cached blobs also emit skipped,
/// but may subsequently be applied. `total` is the manifest's layer count.
///
/// `ApplyingLayer` is emitted only when ingest actually starts, sequentially in
/// ascending index order, and may overlap later downloads. Its unpack ends at
/// the next applying index or `MaterializingRootfs`. At materialization or
/// completion every occurrence is final, including skipped occurrences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvent {
    ResolvingManifest {
        image_ref: String,
    },
    ResolvedManifest {
        image_ref: String,
        manifest_digest: String,
        layers: Vec<ManifestLayer>,
    },
    LayerDownloadStarted {
        index: usize,
        total: usize,
        digest: String,
        size_bytes: Option<u64>,
    },
    LayerDownloadProgress {
        index: usize,
        total: usize,
        digest: String,
        downloaded_bytes: u64,
        size_bytes: Option<u64>,
    },
    LayerDownloadVerifying {
        index: usize,
        total: usize,
        digest: String,
    },
    LayerDownloadFinished {
        index: usize,
        total: usize,
        digest: String,
    },
    LayerDownloadSkipped {
        index: usize,
        total: usize,
        digest: String,
    },
    ApplyingLayer {
        index: usize,
        total: usize,
        digest: Option<String>,
    },
    MaterializingRootfs,
}

#[derive(Clone)]
pub struct ProgressReporter(Arc<dyn Fn(ProgressEvent) + Send + Sync>);

impl fmt::Debug for ProgressReporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ProgressReporter").finish()
    }
}

impl ProgressReporter {
    pub fn new(callback: impl Fn(ProgressEvent) + Send + Sync + 'static) -> Self {
        Self(Arc::new(callback))
    }

    pub fn report(&self, event: ProgressEvent) {
        (self.0)(event);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::progress::{ProgressEvent, ProgressReporter};

    #[test]
    fn cloneable_reporter_calls_its_callback() {
        let reported = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::clone(&reported);
        let reporter =
            ProgressReporter::new(move |event| received.lock().expect("lock events").push(event));

        reporter.clone().report(ProgressEvent::MaterializingRootfs);

        assert_eq!(
            *reported.lock().expect("lock events"),
            vec![ProgressEvent::MaterializingRootfs]
        );
    }
}
