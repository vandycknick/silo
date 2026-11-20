use tokio::sync::mpsc;

const DEFAULT_PROGRESS_BUFFER: usize = 256;

/// One manifest-ordered occurrence, including repeated compressed blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageProgressLayer {
    pub digest: crate::storage::identity::ObjectDigest,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageProgress {
    ResolvingManifest {
        image_ref: String,
    },
    ResolvedManifest {
        image_ref: String,
        manifest_digest: String,
        layers: Vec<ImageProgressLayer>,
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
                layers,
            } => Self::ResolvedManifest {
                image_ref,
                manifest_digest,
                layers: layers
                    .into_iter()
                    .map(|layer| ImageProgressLayer {
                        digest: crate::storage::identity::ObjectDigest::from_sha256(
                            *layer.digest.as_bytes(),
                        ),
                        size_bytes: layer.size_bytes,
                    })
                    .collect(),
            },
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

    #[test]
    fn resolved_manifest_keeps_ordered_digests_sizes_and_repeats() {
        let layers = [
            b"first".as_slice(),
            b"second".as_slice(),
            b"first".as_slice(),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| oci::ManifestLayer {
            digest: oci::changeset::ContentDigest::of_bytes(bytes),
            size_bytes: index as u64,
        })
        .collect::<Vec<_>>();
        let converted = ImageProgress::from(oci::ProgressEvent::ResolvedManifest {
            image_ref: "image".into(),
            manifest_digest: "manifest".into(),
            layers: layers.clone(),
        });
        let ImageProgress::ResolvedManifest {
            layers: received, ..
        } = converted
        else {
            panic!("expected resolved manifest");
        };
        assert_eq!(received.len(), layers.len());
        for (received, original) in received.iter().zip(layers) {
            assert_eq!(received.digest.as_bytes(), original.digest.as_bytes());
            assert_eq!(received.size_bytes, original.size_bytes);
        }
    }
}
