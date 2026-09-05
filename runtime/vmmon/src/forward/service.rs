use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use protocol::v1::vm_forward_service_server::VmForwardService;
use protocol::v1::{
    ErrorCode, ForwardDirection, ForwardScope as WireScope, ForwardState as WireState,
    ForwardStatus, ListForwardsRequest, ListForwardsResponse, OpenForwardRequest,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::forward::{ForwardEntry, ForwardScope, ForwardState, ForwardTable, OpenError};

#[derive(Clone)]
pub(crate) struct ForwardService {
    table: Arc<ForwardTable>,
}

impl ForwardService {
    pub(crate) fn new(table: Arc<ForwardTable>) -> Self {
        Self { table }
    }
}

type OpenStream = Pin<Box<dyn Stream<Item = Result<ForwardStatus, Status>> + Send>>;

#[tonic::async_trait]
impl VmForwardService for ForwardService {
    type OpenStream = OpenStream;

    async fn open(
        &self,
        request: Request<OpenForwardRequest>,
    ) -> Result<Response<Self::OpenStream>, Status> {
        let request = request.into_inner();
        let forward = parse_forward(request.forward.ok_or_else(|| {
            forward_status(
                tonic::Code::InvalidArgument,
                ErrorCode::ForwardInvalid,
                "forward is required",
            )
        })?)?;
        let entry = self
            .table
            .add_session(forward)
            .await
            .map_err(map_open_error)?;
        let mut snapshots = entry.status.subscribe();
        let (tx, rx) = mpsc::channel(8);
        let table = self.table.clone();
        if tx.send(Ok(render(&entry))).await.is_err() {
            table.remove(entry.id()).await;
            return Err(Status::cancelled(
                "forward session receiver closed during setup",
            ));
        }
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tx.closed() => break,
                    _ = table.shutdown.cancelled() => {
                        let _ = tx.try_send(Err(forward_status(
                            tonic::Code::Unavailable,
                            ErrorCode::MonitorStopping,
                            "monitor is stopping",
                        )));
                        break;
                    }
                    changed = snapshots.changed() => {
                        if changed.is_err() || tx.send(Ok(render(&entry))).await.is_err() {
                            break;
                        }
                    }
                }
            }
            table.remove(entry.id()).await;
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn list(
        &self,
        _: Request<ListForwardsRequest>,
    ) -> Result<Response<ListForwardsResponse>, Status> {
        if self.table.shutdown.is_cancelled() {
            return Err(forward_status(
                tonic::Code::Unavailable,
                ErrorCode::MonitorStopping,
                "monitor is stopping",
            ));
        }
        Ok(Response::new(ListForwardsResponse {
            forwards: self
                .table
                .entries()
                .iter()
                .map(|entry| render(entry))
                .collect(),
        }))
    }
}

fn parse_forward(value: protocol::v1::Forward) -> Result<forward_spec::Forward, Status> {
    let listen = value.listen.parse().map_err(|error| {
        forward_status(
            tonic::Code::InvalidArgument,
            ErrorCode::ForwardInvalid,
            format!("invalid listen endpoint: {error}"),
        )
    })?;
    let connect = value.connect.parse().map_err(|error| {
        forward_status(
            tonic::Code::InvalidArgument,
            ErrorCode::ForwardInvalid,
            format!("invalid connect endpoint: {error}"),
        )
    })?;
    let mode = value
        .unix_mode
        .map(forward_spec::UnixMode::try_from)
        .transpose()
        .map_err(|error| {
            forward_status(
                tonic::Code::InvalidArgument,
                ErrorCode::ForwardInvalid,
                error.to_string(),
            )
        })?;
    let forward = forward_spec::Forward {
        name: value.name,
        listen,
        connect,
        mode,
    };
    forward.validate().map_err(|error| {
        forward_status(
            tonic::Code::InvalidArgument,
            ErrorCode::ForwardInvalid,
            error.to_string(),
        )
    })?;
    Ok(forward)
}

fn render(entry: &ForwardEntry) -> ForwardStatus {
    let snapshot = entry.snapshot();
    let direction = match entry.shape.direction() {
        forward_spec::Direction::Inbound => ForwardDirection::Inbound,
        forward_spec::Direction::Outbound => ForwardDirection::Outbound,
    };
    let scope = match entry.scope {
        ForwardScope::Machine => WireScope::Machine,
        ForwardScope::Session => WireScope::Session,
    };
    let state = match snapshot.state {
        ForwardState::Pending => WireState::Pending,
        ForwardState::Active => WireState::Active,
        ForwardState::Unsupported => WireState::Unsupported,
        ForwardState::Closed => WireState::Closed,
    };
    ForwardStatus {
        forward: Some(protocol::v1::Forward {
            name: entry.spec.name.clone(),
            listen: entry.spec.listen.to_string(),
            connect: entry.spec.connect.to_string(),
            unix_mode: entry.spec.mode.map(forward_spec::UnixMode::get),
        }),
        direction: Some(direction as i32),
        scope: Some(scope as i32),
        state: Some(state as i32),
        bound: snapshot.bound.map(|endpoint| endpoint.to_string()),
        active_connections: Some(snapshot.active_connections),
        refused_connections: Some(snapshot.refused_connections),
        error: snapshot.error,
    }
}

fn map_open_error(error: OpenError) -> Status {
    match error {
        OpenError::Invalid(message) => forward_status(
            tonic::Code::InvalidArgument,
            ErrorCode::ForwardInvalid,
            message,
        ),
        OpenError::AddressInUse(message) => forward_status(
            tonic::Code::AlreadyExists,
            ErrorCode::ForwardAddressInUse,
            message,
        ),
        OpenError::Limit(message) => forward_status(
            tonic::Code::ResourceExhausted,
            ErrorCode::ForwardLimit,
            message,
        ),
        OpenError::NotRunning(message) => forward_status(
            tonic::Code::FailedPrecondition,
            ErrorCode::PreconditionFailed,
            message,
        ),
        OpenError::Unavailable(message) => forward_status(
            tonic::Code::Unavailable,
            ErrorCode::BackendUnavailable,
            message,
        ),
    }
}

fn forward_status(code: tonic::Code, detail: ErrorCode, message: impl AsRef<str>) -> Status {
    protocol::status_with_error(code, detail, message, None)
}
