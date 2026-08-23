use tokio::sync::mpsc;

const DEFAULT_PROGRESS_BUFFER: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageProgress {
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
    UsingLocalDisk {
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
    Complete,
}

pub type ImageProgressReceiver = mpsc::Receiver<ImageProgress>;

#[derive(Debug, Clone)]
pub struct ImageProgressSender {
    tx: mpsc::Sender<ImageProgress>,
}

impl ImageProgressSender {
    pub fn channel(bound: usize) -> (Self, ImageProgressReceiver) {
        let (tx, rx) = mpsc::channel(bound.max(1));
        (Self { tx }, rx)
    }

    pub fn default_channel() -> (Self, ImageProgressReceiver) {
        Self::channel(DEFAULT_PROGRESS_BUFFER)
    }

    pub fn send(&self, event: ImageProgress) {
        let _ = self.tx.try_send(event);
    }
}

pub(crate) fn oci_progress_reporter(
    sender: Option<ImageProgressSender>,
) -> Option<oci::ProgressReporter> {
    sender.map(|sender| oci::ProgressReporter::new(move |event| sender.send(event.into())))
}

impl From<oci::ProgressEvent> for ImageProgress {
    fn from(event: oci::ProgressEvent) -> Self {
        match event {
            oci::ProgressEvent::ResolvingManifest { image_ref } => {
                Self::ResolvingManifest { image_ref }
            }
            oci::ProgressEvent::ResolvedManifest {
                image_ref,
                manifest_digest,
                layer_count,
                total_download_bytes,
            } => Self::ResolvedManifest {
                image_ref,
                manifest_digest,
                layer_count,
                total_download_bytes,
            },
            oci::ProgressEvent::CheckingCache { image_ref } => Self::CheckingCache { image_ref },
            oci::ProgressEvent::CacheHit { image_ref } => Self::CacheHit { image_ref },
            oci::ProgressEvent::CacheMiss { image_ref } => Self::CacheMiss { image_ref },
            oci::ProgressEvent::LayerDownloadStarted {
                index,
                total,
                digest,
                size_bytes,
            } => Self::LayerDownloadStarted {
                index,
                total,
                digest,
                size_bytes,
            },
            oci::ProgressEvent::LayerDownloadProgress {
                index,
                total,
                digest,
                downloaded_bytes,
                size_bytes,
            } => Self::LayerDownloadProgress {
                index,
                total,
                digest,
                downloaded_bytes,
                size_bytes,
            },
            oci::ProgressEvent::LayerDownloadVerifying {
                index,
                total,
                digest,
            } => Self::LayerDownloadVerifying {
                index,
                total,
                digest,
            },
            oci::ProgressEvent::LayerDownloadFinished {
                index,
                total,
                digest,
            } => Self::LayerDownloadFinished {
                index,
                total,
                digest,
            },
            oci::ProgressEvent::LayerDownloadSkipped {
                index,
                total,
                digest,
            } => Self::LayerDownloadSkipped {
                index,
                total,
                digest,
            },
            oci::ProgressEvent::ApplyingLayer {
                index,
                total,
                digest,
            } => Self::ApplyingLayer {
                index,
                total,
                digest,
            },
            oci::ProgressEvent::MaterializingRootfs => Self::MaterializingRootfs,
            oci::ProgressEvent::PublishingRootfs => Self::PublishingRootfs,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::image::progress::{ImageProgress, ImageProgressSender};

    #[test]
    fn bounded_sender_drops_when_receiver_lags() {
        let (sender, mut receiver) = ImageProgressSender::channel(1);
        sender.send(ImageProgress::MaterializingRootfs);
        sender.send(ImageProgress::PublishingRootfs);
        drop(sender);

        assert_eq!(
            receiver.try_recv().expect("first event"),
            ImageProgress::MaterializingRootfs
        );
        assert!(receiver.try_recv().is_err());
    }
}
