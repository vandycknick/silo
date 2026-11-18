use std::future::Future;

use crate::daemon::control::{conversion, id, native, Service, Stream};
use silo_vm_control::{images, policy, values, ConversionError};
use silod_spec::daemon::v1 as w;
use tonic::{Request, Response, Status};

fn image_reference(value: &str) -> Result<(), Status> {
    if value.is_empty() || value.contains('\0') || value.len() > 4096 {
        Err(Status::invalid_argument("invalid image reference"))
    } else {
        Ok(())
    }
}

impl Service {
    /// Runs one image operation to completion independently of the response
    /// consumer: progress first, then exactly one terminal event.
    async fn image_operation<T, E, F, Fut>(
        &self,
        progress_event: fn(&libvm::ImageProgress) -> Result<E, ConversionError>,
        terminal_event: fn(&T) -> Result<E, ConversionError>,
        work: F,
    ) -> Result<Response<Stream<E>>, Status>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(Service, libvm::ImageProgressSender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, Status>> + Send + 'static,
    {
        let permit = self.admit().await?;
        let state = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (progress, mut events) = libvm::ImageProgressSender::channel(8);
        let events_tx = tx.clone();
        let forwarding = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let event = progress_event(&event).map_err(conversion);
                if events_tx.send(event).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let result = async {
                let value = work(state, progress).await?;
                terminal_event(&value).map_err(conversion)
            }
            .await;
            // Drain counts native work, not a slow or canceled response consumer.
            drop(permit);
            let _ = forwarding.await;
            let _ = tx.send(result).await;
        });
        Ok(Response::new(self.response_stream(rx)))
    }
}

#[tonic::async_trait]
impl w::runtime_service_server::RuntimeService for Service {
    type ResolveImageStream = Stream<w::ResolveImageEvent>;
    type PullImageStream = Stream<w::PullImageEvent>;
    type ImportImageStream = Stream<w::StoredImageEvent>;
    type ConvertImageStream = Stream<w::StoredImageEvent>;

    async fn inspect_artifact(
        &self,
        r: Request<w::InspectArtifactRequest>,
    ) -> Result<Response<w::ArtifactInspection>, Status> {
        let reference = r.into_inner().reference;
        silo_vm_control::artifacts::validate_reference(&reference).map_err(conversion)?;
        let report = self
            .runtime()
            .await?
            .images()
            .inspect_artifact(&reference)
            .await
            .map_err(native)?;
        Ok(Response::new(
            silo_vm_control::artifacts::inspection_to_wire(&report).map_err(conversion)?,
        ))
    }

    async fn acquire_artifact(
        &self,
        r: Request<w::AcquireArtifactRequest>,
    ) -> Result<Response<w::ArtifactAcquireReport>, Status> {
        let request =
            silo_vm_control::artifacts::acquire_from_wire(r.into_inner()).map_err(conversion)?;
        let permit = self.admit().await?;
        let state = self.clone();
        // The task retains the mutation permit and operation even if the RPC disappears.
        let result = tokio::spawn(async move {
            let _permit = permit;
            let report = state
                .runtime()
                .await?
                .images()
                .acquire_artifact(request)
                .await
                .map_err(native)?;
            silo_vm_control::artifacts::acquired_to_wire(&report).map_err(conversion)
        })
        .await
        .map_err(|error| {
            Status::internal(format!("artifact acquisition task failed: {error}"))
        })??;
        Ok(Response::new(result))
    }

    async fn publish_artifact(
        &self,
        r: Request<w::PublishArtifactRequest>,
    ) -> Result<Response<w::ArtifactPublishReport>, Status> {
        let request =
            silo_vm_control::artifacts::publish_from_wire(r.into_inner()).map_err(conversion)?;
        let permit = self.admit().await?;
        let state = self.clone();
        let result = tokio::spawn(async move {
            let _permit = permit;
            let report = state
                .runtime()
                .await?
                .images()
                .publish_artifact(request)
                .await
                .map_err(native)?;
            silo_vm_control::artifacts::published_to_wire(&report).map_err(conversion)
        })
        .await
        .map_err(|error| {
            Status::internal(format!("artifact publication task failed: {error}"))
        })??;
        Ok(Response::new(result))
    }

    async fn import_image(
        &self,
        r: Request<w::DiskImportRequest>,
    ) -> Result<Response<Self::ImportImageStream>, Status> {
        let request =
            silo_vm_control::boot::import_request_from_wire(r.into_inner()).map_err(conversion)?;
        self.image_operation(
            images::stored_event_progress,
            images::stored_event_image,
            move |state, progress| async move {
                let admitted = request.admit().await.map_err(native)?;
                let runtime = state.runtime().await?.with_image_progress(progress);
                runtime
                    .images()
                    .import_admitted_disk(admitted)
                    .await
                    .map_err(native)
            },
        )
        .await
    }

    /// Converts exactly the selected immutable identity: re-resolution must
    /// reproduce manifest, config and platform, never follow a moved tag.
    async fn convert_image(
        &self,
        r: Request<w::ConvertImageRequest>,
    ) -> Result<Response<Self::ConvertImageStream>, Status> {
        let (identity, options) =
            images::convert_request_from_wire(r.into_inner()).map_err(conversion)?;
        image_reference(&identity.selected_reference)?;
        let resolve = identity.resolve_options().map_err(conversion)?;
        self.image_operation(
            images::stored_event_progress,
            images::stored_event_image,
            move |state, progress| async move {
                let runtime = state.runtime().await?.with_image_progress(progress);
                let images = runtime
                    .with_image_pull_policy(identity.pull_policy)
                    .images();
                let mut image = images
                    .resolve_with(identity.selected_reference.clone(), resolve)
                    .await
                    .map_err(native)?;
                identity.verify(&image).map_err(conversion)?;
                image.requested_reference = identity.requested_reference;
                images.convert(&image, options).await.map_err(native)
            },
        )
        .await
    }

    async fn list_images(&self, _: Request<()>) -> Result<Response<w::ImageList>, Status> {
        let images = self
            .runtime()
            .await?
            .images()
            .list()
            .await
            .map_err(native)?;
        Ok(Response::new(
            images::image_list_to_wire(&images).map_err(conversion)?,
        ))
    }

    /// Inspection is observation, not a content lease.
    async fn inspect_image(
        &self,
        r: Request<w::ImageRef>,
    ) -> Result<Response<w::ImageInfo>, Status> {
        let reference = images::image_ref_from_wire(r.into_inner()).map_err(conversion)?;
        let info = self
            .runtime()
            .await?
            .images()
            .inspect(&reference)
            .await
            .map_err(native)?;
        Ok(Response::new(
            images::image_info_to_wire(&info).map_err(conversion)?,
        ))
    }

    async fn remove_image(
        &self,
        r: Request<w::ImageRef>,
    ) -> Result<Response<w::ImageRemoval>, Status> {
        let reference = images::image_ref_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let removal = self
            .mutate(async move {
                let removal = state
                    .runtime()
                    .await?
                    .images()
                    .remove(&reference)
                    .await
                    .map_err(native)?;
                images::image_removal_to_wire(&removal).map_err(conversion)
            })
            .await?;
        Ok(Response::new(removal))
    }

    async fn prune_images(&self, _: Request<()>) -> Result<Response<w::ImagePruneReport>, Status> {
        let state = self.clone();
        let report = self
            .mutate(async move {
                let report = state
                    .runtime()
                    .await?
                    .images()
                    .prune()
                    .await
                    .map_err(native)?;
                Ok(images::prune_report_to_wire(&report))
            })
            .await?;
        Ok(Response::new(report))
    }

    async fn restore_snapshot(
        &self,
        r: Request<w::RestoreSnapshotRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let (source, options) = silo_vm_control::stopped::restore_request_from_wire(r.into_inner())
            .map_err(conversion)?;
        // A registry reference may need a pull first; libvm checks it in restore.
        if let libvm::RestoreSource::Local(reference) = &source {
            let query = match self.runtime.get() {
                Some(runtime) => runtime.live_capability_query(),
                None => {
                    self.live_query
                        .get_or_try_init(|| async {
                            libvm::LiveCapabilityQuery::open(&self.config).map_err(native)
                        })
                        .await?
                }
            };
            libvm::preflight_restore_snapshot(&self.config, query, reference, &options)
                .await
                .map_err(native)?;
        }
        let state = self.clone();
        let result = self
            .mutate(async move {
                let machine = state
                    .runtime()
                    .await?
                    .restore(source, options, None)
                    .await
                    .map_err(native)?;
                silo_vm_control::snapshots::snapshot_to_wire(
                    &machine.inspect().await.map_err(native)?,
                )
                .map_err(conversion)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn inspect_storage_snapshot(
        &self,
        r: Request<w::StorageSnapshotRef>,
    ) -> Result<Response<w::StorageSnapshotInfo>, Status> {
        let reference =
            silo_vm_control::stopped::reference_from_wire(r.into_inner()).map_err(conversion)?;
        let info = self
            .runtime()
            .await?
            .snapshots()
            .inspect(&reference)
            .await
            .map_err(native)?;
        Ok(Response::new(
            silo_vm_control::stopped::info_to_wire(&info).map_err(conversion)?,
        ))
    }

    async fn verify_storage_snapshot(
        &self,
        r: Request<w::StorageSnapshotRef>,
    ) -> Result<Response<w::SnapshotVerificationResult>, Status> {
        let reference =
            silo_vm_control::stopped::reference_from_wire(r.into_inner()).map_err(conversion)?;
        let result = self.runtime().await?.snapshots().verify(&reference).await;
        let result = match result {
            Ok(report) => silo_vm_control::snapshots::verification_to_wire(Ok(&report)),
            Err(libvm::LibVmError::SnapshotVerification(error)) => {
                silo_vm_control::snapshots::verification_to_wire(Err(&error))
            }
            Err(error) => return Err(native(error)),
        };
        Ok(Response::new(result))
    }

    async fn list_storage_snapshots(
        &self,
        _: Request<()>,
    ) -> Result<Response<w::StorageSnapshotList>, Status> {
        let infos = self
            .runtime()
            .await?
            .snapshots()
            .list()
            .await
            .map_err(native)?;
        let snapshots = infos
            .iter()
            .map(silo_vm_control::stopped::info_to_wire)
            .collect::<Result<_, _>>()
            .map_err(conversion)?;
        Ok(Response::new(w::StorageSnapshotList { snapshots }))
    }

    async fn remove_snapshot(
        &self,
        r: Request<w::StorageSnapshotRef>,
    ) -> Result<Response<w::SnapshotRemoval>, Status> {
        let reference =
            silo_vm_control::stopped::reference_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let removal = self
            .mutate(async move {
                let removal = state
                    .runtime()
                    .await?
                    .snapshots()
                    .remove(&reference)
                    .await
                    .map_err(native)?;
                silo_vm_control::stopped::removal_to_wire(&removal).map_err(conversion)
            })
            .await?;
        Ok(Response::new(removal))
    }

    /// Operation-scoped observation; never resolved through the source machine.
    async fn get_fork(
        &self,
        r: Request<w::ForkOperationRef>,
    ) -> Result<Response<w::LiveForkResult>, Status> {
        let operation_id =
            silo_vm_control::fork::operation_from_wire(r.into_inner()).map_err(conversion)?;
        let result = self
            .runtime()
            .await?
            .inspect_fork(operation_id)
            .await
            .map_err(native)?;
        Ok(Response::new(
            silo_vm_control::fork::result_to_wire(&result).map_err(conversion)?,
        ))
    }

    /// Durable cancellation intent.
    async fn cancel_fork(
        &self,
        r: Request<w::ForkOperationRef>,
    ) -> Result<Response<w::LiveForkResult>, Status> {
        let operation_id =
            silo_vm_control::fork::operation_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let result = self
            .mutate(async move {
                let runtime = state.runtime().await?;
                let result = runtime.cancel_fork(operation_id).await.map_err(native)?;
                silo_vm_control::fork::result_to_wire(&result).map_err(conversion)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn resolve_image(
        &self,
        r: Request<w::ResolveImageRequest>,
    ) -> Result<Response<Self::ResolveImageStream>, Status> {
        let v = r.into_inner();
        image_reference(&v.reference)?;
        let options = images::resolve_options_from_wire(&v).map_err(conversion)?;
        let policy = images::pull_policy_from_wire(v.pull_policy).map_err(conversion)?;
        // Resolution can fetch/cache artifacts. It has the same lifetime and admission
        // rules as other mutations, even when the progress consumer disconnects.
        let permit = self.admit().await?;
        let state = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (progress, mut events) = libvm::ImageProgressSender::channel(8);
        let events_tx = tx.clone();
        let forwarding = tokio::spawn(async move {
            while let Some(e) = events.recv().await {
                let event = images::progress_to_wire(&e)
                    .map(|v| w::ResolveImageEvent {
                        event: Some(w::resolve_image_event::Event::Progress(v)),
                    })
                    .map_err(conversion);
                if events_tx.send(event).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let result = async {
                let runtime = state.runtime().await?.with_image_progress(progress);
                let image = runtime
                    .images()
                    .resolve_with(v.reference, options)
                    .await
                    .map_err(native)?;
                images::resolved_image_to_wire(&image, policy).map_err(conversion)
            }
            .await;
            // Drain counts native work, not a slow or canceled response consumer.
            drop(permit);
            let _ = forwarding.await;
            let terminal = result.map(|v| w::ResolveImageEvent {
                event: Some(w::resolve_image_event::Event::Image(v)),
            });
            let _ = tx.send(terminal).await;
        });
        Ok(Response::new(self.response_stream(rx)))
    }

    async fn pull_image(
        &self,
        r: Request<w::PullImageRequest>,
    ) -> Result<Response<Self::PullImageStream>, Status> {
        let (reference, options) =
            images::pull_request_from_wire(r.into_inner()).map_err(conversion)?;
        self.image_operation(
            images::pull_event_progress,
            images::pull_event_image,
            move |state, progress| async move {
                state
                    .runtime()
                    .await?
                    .with_image_progress(progress)
                    .images()
                    .pull_with(reference, options)
                    .await
                    .map_err(native)
            },
        )
        .await
    }

    async fn propose_machine_name(&self, _: Request<()>) -> Result<Response<w::Name>, Status> {
        Ok(Response::new(w::Name {
            name: libvm::planning::propose_machine_name().map_err(native)?,
        }))
    }
    async fn parse_resource(
        &self,
        r: Request<w::ParseResourceRequest>,
    ) -> Result<Response<w::Size>, Status> {
        Ok(Response::new(
            silo_vm_control::requests::parse_resource(r.into_inner()).map_err(conversion)?,
        ))
    }
    async fn normalize_policy(
        &self,
        r: Request<w::NormalizePolicyRequest>,
    ) -> Result<Response<w::PolicyDocument>, Status> {
        Ok(Response::new(
            policy::normalize_policy(r.into_inner()).map_err(conversion)?,
        ))
    }
    async fn check_policy_secrets(
        &self,
        r: Request<w::CheckPolicySecretsRequest>,
    ) -> Result<Response<w::PolicySecretsResult>, Status> {
        let v = r.into_inner();
        let secret_scope = silo_vm_control::requests::secret_scope_from_wire(v.secret_scope)
            .map_err(conversion)?;
        let policy = values::policy_from_wire(&v.policy_json).map_err(conversion)?;
        let reference = v.machine_id.as_deref().map(id).transpose()?;
        let result = self
            .runtime()
            .await?
            .check_policy_secrets(
                &policy,
                reference.as_ref(),
                secret_scope,
                &libvm::EgressCredentials::new(),
            )
            .await
            .map_err(native)?;
        Ok(Response::new(silo_vm_control::policy::secrets_to_wire(
            &result,
        )))
    }
}
