//! Bounded same-user handoff adapters. Durable transitions outlive RPC waiters.
use crate::daemon::control::{conversion, native, reference, required, Service};
use libvm::handoff::service::HandoffService;
use silo_vm_control::handoff as c;
use silod_spec::daemon::v1 as w;
use tonic::{Request, Response, Status};

const FRAME_BYTES: usize = 1024 * 1024;
const STREAM_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

impl Service {
    async fn handoff_backend(&self) -> Result<&HandoffService, Status> {
        self.handoff
            .get_or_try_init(|| async { Ok(HandoffService::new(self.runtime().await?)) })
            .await
    }
}

#[tonic::async_trait]
impl w::handoff_service_server::HandoffService for Service {
    async fn get_capabilities(
        &self,
        _: Request<()>,
    ) -> Result<Response<w::HandoffCapabilities>, Status> {
        let value = self
            .handoff_backend()
            .await?
            .capabilities()
            .await
            .map_err(native)?;
        Ok(Response::new(
            c::capabilities_to_wire(&value).map_err(conversion)?,
        ))
    }

    async fn observe_source(
        &self,
        r: Request<w::MachineRef>,
    ) -> Result<Response<w::HandoffDocument>, Status> {
        let machine = reference(Some(r.into_inner()))?;
        let value = self
            .handoff_backend()
            .await?
            .observe_source(&machine)
            .await
            .map_err(native)?;
        Ok(Response::new(
            c::observation_to_wire(&value).map_err(conversion)?,
        ))
    }

    async fn preflight_destination(
        &self,
        r: Request<w::HandoffPreflightRequest>,
    ) -> Result<Response<w::HandoffProposal>, Status> {
        let (observation, destination) =
            c::preflight_from_wire(r.into_inner()).map_err(conversion)?;
        let value = self
            .handoff_backend()
            .await?
            .preflight_destination(&observation, &destination)
            .await
            .map_err(native)?;
        Ok(Response::new(
            c::proposal_to_wire(&value).map_err(conversion)?,
        ))
    }

    async fn get_status(
        &self,
        r: Request<w::HandoffOperationRef>,
    ) -> Result<Response<w::HandoffStatus>, Status> {
        let operation = c::operation_from_wire(&r.into_inner().operation).map_err(conversion)?;
        let value = self
            .handoff_backend()
            .await?
            .status(operation)
            .await
            .map_err(native)?;
        Ok(Response::new(
            c::status_to_wire(value.as_ref()).map_err(conversion)?,
        ))
    }

    async fn get_plan(
        &self,
        r: Request<w::HandoffOperationRef>,
    ) -> Result<Response<w::HandoffDocument>, Status> {
        let operation = c::operation_from_wire(&r.into_inner().operation).map_err(conversion)?;
        let value = self
            .handoff_backend()
            .await?
            .plan(operation)
            .await
            .map_err(native)?;
        Ok(Response::new(
            c::document_to_wire(value.document()).map_err(conversion)?,
        ))
    }

    async fn begin_source(
        &self,
        r: Request<w::HandoffReceiveRequest>,
    ) -> Result<Response<w::HandoffStatus>, Status> {
        let plan = c::receive_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .begin_source(&plan)
                    .await
                    .map_err(native)?;
                c::status_to_wire(Some(&value)).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }

    async fn capture_source(
        &self,
        r: Request<w::HandoffCaptureRequest>,
    ) -> Result<Response<w::HandoffCaptureOffer>, Status> {
        let (plan, stop) = c::capture_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .capture_source(&plan, stop)
                    .await
                    .map_err(native)?;
                c::offer_to_wire(&value).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }

    async fn receive(
        &self,
        r: Request<w::HandoffReceiveRequest>,
    ) -> Result<Response<w::HandoffStatus>, Status> {
        let plan = c::receive_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .receive(&plan)
                    .await
                    .map_err(native)?;
                c::status_to_wire(Some(&value)).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }

    async fn offer_capture(
        &self,
        r: Request<w::HandoffCaptureOffer>,
    ) -> Result<Response<w::HandoffStatus>, Status> {
        let offer = c::offer_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .offer_capture(&offer)
                    .await
                    .map_err(native)?;
                c::status_to_wire(Some(&value)).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }

    async fn list_needs(
        &self,
        r: Request<w::HandoffNeedsRequest>,
    ) -> Result<Response<w::HandoffNeedsPage>, Status> {
        let (operation, cursor, limit) = c::needs_from_wire(r.into_inner()).map_err(conversion)?;
        let value = self
            .handoff_backend()
            .await?
            .list_needs(operation, cursor, limit)
            .await
            .map_err(native)?;
        Ok(Response::new(c::needs_to_wire(&value).map_err(conversion)?))
    }

    async fn read_payload(
        &self,
        r: Request<w::HandoffReadRequest>,
    ) -> Result<Response<w::HandoffPayloadFrame>, Status> {
        let (operation, descriptor, offset, max_bytes) =
            c::read_from_wire(r.into_inner()).map_err(conversion)?;
        let value = self
            .handoff_backend()
            .await?
            .read_payload(operation, descriptor, offset, max_bytes)
            .await
            .map_err(native)?;
        Ok(Response::new(c::frame_to_wire(value).map_err(conversion)?))
    }

    async fn write_payload(
        &self,
        r: Request<tonic::Streaming<w::HandoffWriteRequest>>,
    ) -> Result<Response<w::HandoffPayloadReceipt>, Status> {
        let permit = self.admit().await?;
        let mut stream = r.into_inner();
        let shutdown = self.stream_shutdown.clone();
        let first = next_message(&mut stream, &shutdown)
            .await?
            .ok_or_else(|| Status::invalid_argument("payload header is required"))?;
        let header = match first.part {
            Some(w::handoff_write_request::Part::Header(header)) => header,
            _ => {
                return Err(Status::invalid_argument(
                    "first payload message must be a header",
                ))
            }
        };
        let operation = c::operation_from_wire(&header.operation).map_err(conversion)?;
        let descriptor =
            c::descriptor_from_wire(required(header.descriptor)?).map_err(conversion)?;
        c::validate_payload_length(&descriptor, header.length).map_err(conversion)?;
        let mut remaining = header.length;
        let mut writer = self
            .handoff_backend()
            .await?
            .open_payload(operation, descriptor)
            .await
            .map_err(native)?;
        // The RPC owns only a bounded partial, never an ownership decision. Dropping
        // the writer on error, disconnect, idle expiry or shutdown removes it.
        while let Some(message) = next_message(&mut stream, &shutdown).await? {
            let frame = match message.part {
                Some(w::handoff_write_request::Part::Frame(frame)) => frame,
                _ => {
                    return Err(Status::invalid_argument(
                        "payload header may appear only once",
                    ))
                }
            };
            accept_frame(&mut remaining, frame.len())?;
            writer.write_frame(&frame).map_err(native)?;
        }
        if remaining != 0 {
            return Err(Status::invalid_argument(
                "payload ended before its declared length",
            ));
        }
        // Once a complete stream is accepted, durable verification/publication owns
        // the permit independently of the response consumer.
        let value = tokio::spawn(async move {
            let _permit = permit;
            let receipt = writer.finish().await.map_err(native)?;
            if receipt.bytes != header.length {
                return Err(Status::internal(
                    "published payload length differs from accepted stream",
                ));
            }
            c::payload_receipt_to_wire(&receipt).map_err(conversion)
        })
        .await
        .map_err(|error| Status::internal(format!("payload publication task failed: {error}")))??;
        Ok(Response::new(value))
    }

    async fn prepare(
        &self,
        r: Request<w::HandoffBinding>,
    ) -> Result<Response<w::HandoffPreparedReceipt>, Status> {
        let binding = c::binding_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .prepare(&binding)
                    .await
                    .map_err(native)?;
                c::prepared_to_wire(&value).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }

    async fn fence_source(
        &self,
        r: Request<w::HandoffPreparedReceipt>,
    ) -> Result<Response<w::HandoffCommitAuthorization>, Status> {
        let receipt = c::prepared_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .fence_source(&receipt)
                    .await
                    .map_err(native)?;
                c::authorization_to_wire(&value).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }

    async fn commit(
        &self,
        r: Request<w::HandoffCommitAuthorization>,
    ) -> Result<Response<w::HandoffTerminalReceipt>, Status> {
        let authorization = c::authorization_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .commit(&authorization)
                    .await
                    .map_err(native)?;
                c::terminal_to_wire(&value).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }

    async fn abort(
        &self,
        r: Request<w::HandoffIntent>,
    ) -> Result<Response<w::HandoffTerminalReceipt>, Status> {
        let intent = c::intent_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .abort(&intent)
                    .await
                    .map_err(native)?;
                c::terminal_to_wire(&value).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }

    async fn resolve_source(
        &self,
        r: Request<w::HandoffTerminalReceipt>,
    ) -> Result<Response<w::HandoffStatus>, Status> {
        let receipt = c::terminal_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let value = self
            .mutate(async move {
                let value = state
                    .handoff_backend()
                    .await?
                    .resolve_source(&receipt)
                    .await
                    .map_err(native)?;
                c::status_to_wire(Some(&value)).map_err(conversion)
            })
            .await?;
        Ok(Response::new(value))
    }
}

async fn next_message(
    stream: &mut tonic::Streaming<w::HandoffWriteRequest>,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<Option<w::HandoffWriteRequest>, Status> {
    tokio::select! {
        _ = shutdown.cancelled() => Err(Status::unavailable("daemon stream shutdown")),
        value = tokio::time::timeout(STREAM_IDLE, stream.message()) => {
            value.map_err(|_| Status::deadline_exceeded("payload stream idle timeout"))?
        }
    }
}

fn accept_frame(remaining: &mut u64, length: usize) -> Result<(), Status> {
    if length == 0 || length > FRAME_BYTES {
        return Err(Status::invalid_argument(
            "payload frames must contain 1..=1MiB bytes",
        ));
    }
    *remaining = remaining
        .checked_sub(length as u64)
        .ok_or_else(|| Status::invalid_argument("payload exceeds its declared length"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::daemon::control::handoff::{accept_frame, FRAME_BYTES};

    #[test]
    fn payload_frames_enforce_bounds_and_exact_declared_length() {
        let mut remaining = FRAME_BYTES as u64 + 3;
        accept_frame(&mut remaining, FRAME_BYTES).unwrap();
        assert_eq!(remaining, 3);
        accept_frame(&mut remaining, 3).unwrap();
        assert_eq!(remaining, 0);
        assert!(accept_frame(&mut remaining, 1).is_err());
        assert_eq!(remaining, 0);
        assert!(accept_frame(&mut remaining, 0).is_err());
        assert!(accept_frame(&mut remaining, FRAME_BYTES + 1).is_err());
    }
}
