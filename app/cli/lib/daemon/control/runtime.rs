use std::future::Future;

use crate::daemon::control::{conversion, id, native, Service, Stream};
use silo_vm_control::{images, policy, values};
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
    /// Runs one managed-image publication to completion independently of the
    /// response consumer: progress first, then exactly one terminal image.
    async fn managed_image_operation<R, F, Fut>(
        &self,
        r: &Request<R>,
        work: F,
    ) -> Result<Response<Stream<w::ManagedImageEvent>>, Status>
    where
        F: FnOnce(Service, libvm::ImageProgressSender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<libvm::ManagedImageInfo, Status>> + Send + 'static,
    {
        let permit = self.admit(r, true).await?;
        let state = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (progress, mut events) = libvm::ImageProgressSender::channel(8);
        let events_tx = tx.clone();
        let forwarding = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let event = images::managed_event_progress(&event).map_err(conversion);
                if events_tx.send(event).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let result = async {
                let image = work(state, progress).await?;
                images::managed_event_image(&image).map_err(conversion)
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
    type PullImageStream = Stream<w::ImageProgress>;
    type ImportImageStream = Stream<w::ManagedImageEvent>;
    type ConvertImageStream = Stream<w::ManagedImageEvent>;

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
        let request = silo_vm_control::artifacts::acquire_from_wire(r.get_ref().clone())
            .map_err(conversion)?;
        let permit = self.admit(&r, true).await?;
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
        let request = silo_vm_control::artifacts::publish_from_wire(r.get_ref().clone())
            .map_err(conversion)?;
        let permit = self.admit(&r, true).await?;
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
        let request = silo_vm_control::boot::import_request_from_wire(r.get_ref().clone())
            .map_err(conversion)?;
        self.managed_image_operation(&r, move |state, progress| async move {
            let admitted = request.admit().await.map_err(native)?;
            let runtime = state.runtime().await?.with_image_progress(progress);
            runtime
                .images()
                .import_admitted_disk(admitted)
                .await
                .map_err(native)
        })
        .await
    }

    /// Converts exactly the selected immutable identity: re-resolution must
    /// reproduce manifest, config and platform, never follow a moved tag.
    async fn convert_image(
        &self,
        r: Request<w::ConvertImageRequest>,
    ) -> Result<Response<Self::ConvertImageStream>, Status> {
        let (identity, options) =
            images::convert_request_from_wire(r.get_ref().clone()).map_err(conversion)?;
        image_reference(&identity.selected_reference)?;
        let resolve = identity.resolve_options().map_err(conversion)?;
        self.managed_image_operation(&r, move |state, progress| async move {
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
        })
        .await
    }

    async fn resolve_managed_digest(
        &self,
        r: Request<w::ManagedDigest>,
    ) -> Result<Response<w::ManagedSourceId>, Status> {
        let digest = images::managed_digest_from_wire(r.into_inner()).map_err(conversion)?;
        let id = self
            .runtime()
            .await?
            .images()
            .resolve_managed_digest(&digest)
            .await
            .map_err(native)?;
        Ok(Response::new(images::managed_id_to_wire(&id)))
    }

    /// Inspection is observation, not a content lease.
    async fn inspect_managed_image(
        &self,
        r: Request<w::ManagedSourceRef>,
    ) -> Result<Response<w::ManagedSourceInfo>, Status> {
        let reference = images::managed_ref_from_wire(r.into_inner()).map_err(conversion)?;
        let info = self
            .runtime()
            .await?
            .images()
            .inspect_managed(&reference)
            .await
            .map_err(native)?;
        Ok(Response::new(
            images::managed_info_to_wire(&info).map_err(conversion)?,
        ))
    }

    async fn list_managed_images(
        &self,
        _: Request<()>,
    ) -> Result<Response<w::ManagedSourceList>, Status> {
        let infos = self
            .runtime()
            .await?
            .images()
            .list_managed()
            .await
            .map_err(native)?;
        Ok(Response::new(
            images::managed_list_to_wire(&infos).map_err(conversion)?,
        ))
    }

    async fn release_image_retention(
        &self,
        r: Request<w::ManagedSourceRef>,
    ) -> Result<Response<()>, Status> {
        let reference = images::managed_ref_from_wire(r.get_ref().clone()).map_err(conversion)?;
        let state = self.clone();
        self.mutate(&r, true, async move {
            state
                .runtime()
                .await?
                .images()
                .release_retention(&reference)
                .await
                .map_err(native)?;
            Ok(())
        })
        .await?;
        Ok(Response::new(()))
    }
    async fn restore_snapshot(
        &self,
        r: Request<w::RestoreStorageSnapshotRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let value = r.get_ref().clone();
        let reference = silo_vm_control::stopped::reference_from_wire(
            crate::daemon::control::required(value.snapshot)?,
        )
        .map_err(conversion)?;
        let options = libvm::RestoreOptions {
            name: silo_vm_control::stopped::name(value.name).map_err(conversion)?,
            external_resources: silo_vm_control::stopped::policy_from_wire(
                crate::daemon::control::required(value.external_resources)?,
            )
            .map_err(conversion)?,
            activation_hook: value
                .activation_hook
                .map(silo_vm_control::stopped::hook_from_wire)
                .transpose()
                .map_err(conversion)?,
            resources: silo_vm_control::stopped::restore_resources_from_wire(value.resources)
                .map_err(conversion)?,
        };
        libvm::preflight_restore_snapshot(&self.config, &reference, &options.external_resources)
            .await
            .map_err(native)?;
        let state = self.clone();
        let result = self
            .mutate(&r, true, async move {
                let machine = state
                    .runtime()
                    .await?
                    .restore_snapshot(reference, options)
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

    async fn recover_checkpoint_disks(
        &self,
        r: Request<w::RecoverCheckpointDisksRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let value = r.get_ref().clone();
        let reference = silo_vm_control::stopped::reference_from_wire(
            crate::daemon::control::required(value.snapshot)?,
        )
        .map_err(conversion)?;
        let options = libvm::RecoverDisksOptions {
            name: silo_vm_control::stopped::name(value.name).map_err(conversion)?,
            external_resources: silo_vm_control::stopped::policy_from_wire(
                crate::daemon::control::required(value.external_resources)?,
            )
            .map_err(conversion)?,
        };
        libvm::preflight_recover_checkpoint_disks(
            &self.config,
            &reference,
            &options.external_resources,
        )
        .await
        .map_err(native)?;
        let state = self.clone();
        let result = self
            .mutate(&r, true, async move {
                let machine = state
                    .runtime()
                    .await?
                    .recover_checkpoint_disks(reference, options)
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
        let runtime = self.runtime().await?;
        let info = libvm::SnapshotStore::open(runtime.local_home())
            .await
            .map_err(native)?
            .inspect(&reference)
            .await
            .map_err(native)?;
        Ok(Response::new(
            silo_vm_control::stopped::info_to_wire(&info).map_err(conversion)?,
        ))
    }

    async fn list_storage_snapshots(
        &self,
        _: Request<()>,
    ) -> Result<Response<w::StorageSnapshotList>, Status> {
        let runtime = self.runtime().await?;
        let infos = libvm::SnapshotStore::open(runtime.local_home())
            .await
            .map_err(native)?
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

    async fn release_snapshot_retention(
        &self,
        r: Request<w::StorageSnapshotRef>,
    ) -> Result<Response<()>, Status> {
        let reference = silo_vm_control::stopped::reference_from_wire(r.get_ref().clone())
            .map_err(conversion)?;
        let state = self.clone();
        self.mutate(&r, true, async move {
            let runtime = state.runtime().await?;
            libvm::SnapshotStore::open(runtime.local_home())
                .await
                .map_err(native)?
                .release_retention(&reference)
                .await
                .map_err(native)?;
            Ok(())
        })
        .await?;
        Ok(Response::new(()))
    }

    /// Removes one name from the single image/snapshot namespace; explicit
    /// retention of its target is unaffected.
    async fn remove_image_alias(&self, r: Request<w::Name>) -> Result<Response<()>, Status> {
        let alias = silo_vm_control::stopped::alias(&r.get_ref().name).map_err(conversion)?;
        let state = self.clone();
        self.mutate(&r, true, async move {
            state
                .runtime()
                .await?
                .images()
                .remove_alias(&alias)
                .await
                .map_err(native)?;
            Ok(())
        })
        .await?;
        Ok(Response::new(()))
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

    /// Durable cancellation intent. Like stop/kill it stays admitted while
    /// host shutdown seals new protected work.
    async fn cancel_fork(
        &self,
        r: Request<w::ForkOperationRef>,
    ) -> Result<Response<w::LiveForkResult>, Status> {
        let operation_id =
            silo_vm_control::fork::operation_from_wire(r.get_ref().clone()).map_err(conversion)?;
        let state = self.clone();
        let result = self
            .mutate(&r, false, async move {
                let result = state
                    .runtime()
                    .await?
                    .cancel_fork(operation_id)
                    .await
                    .map_err(native)?;
                silo_vm_control::fork::result_to_wire(&result).map_err(conversion)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn resolve_image(
        &self,
        r: Request<w::ResolveImageRequest>,
    ) -> Result<Response<Self::ResolveImageStream>, Status> {
        let v = r.get_ref().clone();
        image_reference(&v.reference)?;
        let options = images::resolve_options_from_wire(&v).map_err(conversion)?;
        let policy = images::pull_policy_from_wire(v.pull_policy).map_err(conversion)?;
        // Resolution can fetch/cache artifacts. It has the same lifetime and admission
        // rules as other mutations, even when the progress consumer disconnects.
        let permit = self.admit(&r, false).await?;
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
        let reference = r.get_ref().reference.clone();
        image_reference(&reference)?;
        let permit = self.admit(&r, false).await?;
        let state = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (progress, mut events) = libvm::ImageProgressSender::channel(8);
        let progress_tx = tx.clone();
        let forwarding = tokio::spawn(async move {
            while let Some(e) = events.recv().await {
                if progress_tx
                    .send(images::progress_to_wire(&e).map_err(conversion))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let result = async {
                state
                    .runtime()
                    .await?
                    .with_image_progress(progress)
                    .images()
                    .pull(reference)
                    .await
                    .map_err(native)?;
                Ok::<_, Status>(())
            }
            .await;
            drop(permit);
            let _ = forwarding.await;
            if let Err(e) = result {
                let _ = tx.send(Err(e)).await;
            }
        });
        Ok(Response::new(self.response_stream(rx)))
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
        let policy = values::policy_from_wire(&v.policy_json).map_err(conversion)?;
        let reference = v.machine_id.as_deref().map(id).transpose()?;
        let result = self
            .runtime()
            .await?
            .check_policy_secrets(
                &policy,
                reference.as_ref(),
                &libvm::EgressCredentials::new(),
            )
            .await
            .map_err(native)?;
        Ok(Response::new(silo_vm_control::policy::secrets_to_wire(
            &result,
        )))
    }
}
