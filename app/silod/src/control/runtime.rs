use crate::control::{conversion, id, native, Service, Stream};
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

#[tonic::async_trait]
impl w::runtime_service_server::RuntimeService for Service {
    type ResolveImageStream = Stream<w::ResolveImageEvent>;
    type PullImageStream = Stream<w::ImageProgress>;

    async fn resolve_image(
        &self,
        r: Request<w::ResolveImageRequest>,
    ) -> Result<Response<Self::ResolveImageStream>, Status> {
        let v = r.get_ref().clone();
        image_reference(&v.reference)?;
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
                    .resolve_with(
                        v.reference,
                        libvm::ImageResolveOptions {
                            policy: Some(policy),
                        },
                    )
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
