use std::fmt;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvent {
    ResolvingManifest {
        image_ref: String,
    },
    ResolvedManifest {
        image_ref: String,
        manifest_digest: String,
        layer_count: usize,
        total_download_bytes: Option<u64>,
    },
    CheckingCache {
        image_ref: String,
    },
    CacheHit {
        image_ref: String,
    },
    CacheMiss {
        image_ref: String,
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
    PublishingRootfs,
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
