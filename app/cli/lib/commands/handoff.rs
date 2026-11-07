use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use eyre::{ensure, Context as _};
use libvm::handoff::plan::{
    ApprovedPlan, DestinationRequest, HandoffPlan, HandoffProposal, PayloadDescriptor,
};
use libvm::handoff::types::{OperationId, RuntimeId};
use silo_vm_control::handoff as convert;
use silo_vm_control::transport::{self, Admission};
use silod_spec::daemon::v1::{self as w, handoff_service_client::HandoffServiceClient};
use tonic::transport::Channel;

use crate::commands::live::ExternalResources;
use crate::context::Context;

const FRAME_BYTES: u32 = 1024 * 1024;
const PAGE_ENTRIES: u32 = 256;
const MESSAGE_BYTES: usize = 16 * 1024 * 1024;
type Client = HandoffServiceClient<Channel>;

/// Transfer stopped storage between two explicitly selected Silo runtimes.
#[derive(Debug, Args)]
pub struct Cmd {
    #[command(subcommand)]
    command: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Propose the exact destination boot, storage and resource plan without stopping.
    Plan(PlanArgs),
    /// Execute an explicitly approved plan; neither endpoint starts automatically.
    Transfer {
        #[command(flatten)]
        plan: PlanArgs,
        #[arg(long, value_name = "SHA256")]
        approve_plan: libvm::ObjectDigest,
        /// Deliberately stop the source before taking its coherent storage cut.
        #[arg(long)]
        stop_running: bool,
    },
    /// Observe both durable journals. Unknown or unavailable never means aborted.
    Status(OperationArgs),
    /// Finish an interrupted handoff using its original operation and saved plan.
    Recover(OperationArgs),
    /// Obtain durable destination abort before releasing the source reservation.
    Abort(OperationArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    Fork,
    Relocate,
}

#[derive(Debug, Args)]
struct Destination {
    #[arg(long, value_name = "PATH")]
    destination_home: PathBuf,
    #[arg(long, value_name = "PATH")]
    destination_config: PathBuf,
    #[arg(long, value_name = "PATH")]
    destination_run_root: PathBuf,
}

#[derive(Debug, Args)]
struct PlanArgs {
    machine: String,
    #[arg(long, value_enum)]
    mode: Mode,
    /// Stable caller-selected operation UUID, shared by planning, transfer and recovery.
    #[arg(long, value_name = "UUID", value_parser = operation_id)]
    operation: OperationId,
    #[command(flatten)]
    destination: Destination,
    #[arg(long)]
    name: Option<String>,
    /// Explicit complete destination boot-bundle identity. Omission preserves the captured bundle.
    #[arg(long, value_name = "SHA256")]
    boot_bundle: Option<libvm::ObjectDigest>,
    #[command(flatten)]
    resources: ExternalResources,
}

#[derive(Debug, Args)]
struct OperationArgs {
    #[arg(value_parser = operation_id)]
    operation: OperationId,
    #[command(flatten)]
    destination: Destination,
}

fn operation_id(value: &str) -> Result<OperationId, String> {
    let id = uuid::Uuid::parse_str(value).map_err(|error| error.to_string())?;
    if id.to_string() != value {
        return Err("expected canonical lowercase hyphenated UUID".into());
    }
    OperationId::new(id).map_err(|error| error.to_string())
}

struct Sessions {
    source: Client,
    destination: Client,
    source_runtime: RuntimeId,
    destination_runtime: RuntimeId,
}

impl Sessions {
    async fn connect(selection: &Destination) -> eyre::Result<Self> {
        ensure!(
            selection.destination_home.is_absolute() && selection.destination_config.is_absolute(),
            "destination Home and config paths must be absolute"
        );
        let source_host = libvm::HostPaths::from_env()?;
        let destination_host =
            libvm::HostPaths::new(&selection.destination_home, &selection.destination_config);
        let source = transport::probe(&source_host, Admission::Ready)
            .await?
            .ok_or_else(|| {
                eyre::eyre!("handoff requires a running source daemon; start it explicitly")
            })?;
        let destination = transport::probe_selected(
            &destination_host,
            &selection.destination_run_root,
            Admission::Ready,
        )
        .await?
        .ok_or_else(|| {
            eyre::eyre!("handoff requires the explicitly selected destination daemon")
        })?;
        let mut source = Client::new(source.channel)
            .max_decoding_message_size(MESSAGE_BYTES)
            .max_encoding_message_size(MESSAGE_BYTES);
        let mut destination = Client::new(destination.channel)
            .max_decoding_message_size(MESSAGE_BYTES)
            .max_encoding_message_size(MESSAGE_BYTES);
        let source_caps =
            convert::capabilities_from_wire(source.get_capabilities(()).await?.into_inner())?;
        let destination_caps =
            convert::capabilities_from_wire(destination.get_capabilities(()).await?.into_inner())?;
        ensure!(
            source_caps.runtime != destination_caps.runtime,
            "source and destination have the same persistent runtime identity"
        );
        ensure!(
            source_caps.max_frame_bytes >= FRAME_BYTES
                && destination_caps.max_frame_bytes >= FRAME_BYTES
                && destination_caps.max_page_entries >= PAGE_ENTRIES,
            "peer does not admit the bounded handoff transport profile"
        );
        Ok(Self {
            source,
            destination,
            source_runtime: source_caps.runtime,
            destination_runtime: destination_caps.runtime,
        })
    }

    async fn status(&mut self, operation: OperationId) -> eyre::Result<OperationStatus> {
        let request = w::HandoffOperationRef {
            operation: operation.to_string(),
        };
        let source =
            convert::status_from_wire(self.source.get_status(request.clone()).await?.into_inner())?;
        let destination =
            convert::status_from_wire(self.destination.get_status(request).await?.into_inner())?;
        for record in source.iter().chain(destination.iter()) {
            ensure!(
                record.intent.operation == operation
                    && record.intent.source_runtime == self.source_runtime
                    && record.intent.destination_runtime == self.destination_runtime,
                "handoff journal belongs to a different operation or runtime pair"
            );
        }
        if let (Some(source), Some(destination)) = (&source, &destination) {
            ensure!(
                source.intent == destination.intent,
                "runtime journals disagree on immutable intent"
            );
        }
        Ok(OperationStatus {
            operation,
            source,
            destination,
        })
    }

    async fn transfer_missing(
        &mut self,
        operation: OperationId,
        counts: &mut TransferCounts,
        metadata: &mut TransferCounts,
    ) -> eyre::Result<()> {
        loop {
            let mut cursor = None;
            let mut transferred = false;
            loop {
                let page = self
                    .destination
                    .list_needs(w::HandoffNeedsRequest {
                        operation: operation.to_string(),
                        cursor,
                        limit: PAGE_ENTRIES,
                    })
                    .await?
                    .into_inner();
                ensure!(
                    page.needs.len() <= PAGE_ENTRIES as usize,
                    "peer exceeded the missing-payload page bound"
                );
                for descriptor in page.needs {
                    let native = convert::descriptor_from_wire(descriptor.clone())?;
                    let length = self
                        .transfer_payload(operation, descriptor, &native)
                        .await?;
                    if matches!(native, PayloadDescriptor::StreamMap { .. }) {
                        metadata.add(length)?;
                    } else {
                        counts.add(length)?;
                    }
                    transferred = true;
                }
                match page.next {
                    Some(next) => {
                        ensure!(
                            next > cursor.unwrap_or(0),
                            "peer returned a non-advancing missing-payload cursor"
                        );
                        cursor = Some(next);
                    }
                    None => break,
                }
            }
            // Received maps reveal additional chunk needs. A complete empty
            // pass, not the last page of one pass, proves transfer completion.
            if !transferred {
                return Ok(());
            }
        }
    }

    async fn transfer_payload(
        &mut self,
        operation: OperationId,
        descriptor: w::HandoffPayloadDescriptor,
        native: &PayloadDescriptor,
    ) -> eyre::Result<u64> {
        use w::handoff_write_request::Part;
        let first = self
            .source
            .read_payload(w::HandoffReadRequest {
                operation: operation.to_string(),
                descriptor: Some(descriptor.clone()),
                offset: 0,
                max_bytes: FRAME_BYTES,
            })
            .await?
            .into_inner();
        let length = first.total_length;
        convert::validate_payload_length(native, length)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let header = w::HandoffWriteRequest {
            part: Some(Part::Header(w::HandoffPayloadRequest {
                operation: operation.to_string(),
                descriptor: Some(descriptor.clone()),
                length,
            })),
        };
        let source = &mut self.source;
        let destination = &mut self.destination;
        let expected = descriptor.clone();
        let send = async move {
            sender
                .send(header)
                .await
                .context("destination closed payload stream before its header")?;
            let mut offset = 0u64;
            let mut frame = first;
            loop {
                ensure!(
                    frame.total_length == length
                        && !frame.content.is_empty()
                        && frame.content.len() <= FRAME_BYTES as usize,
                    "source returned inconsistent length or an empty/oversized payload frame"
                );
                offset = offset
                    .checked_add(frame.content.len() as u64)
                    .ok_or_else(|| eyre::eyre!("payload offset overflow"))?;
                ensure!(
                    offset <= length && frame.end == (offset == length),
                    "source payload frame violates exact descriptor length"
                );
                sender
                    .send(w::HandoffWriteRequest {
                        part: Some(Part::Frame(frame.content)),
                    })
                    .await
                    .context("destination closed payload stream")?;
                if offset == length {
                    break;
                }
                frame = source
                    .read_payload(w::HandoffReadRequest {
                        operation: operation.to_string(),
                        descriptor: Some(descriptor.clone()),
                        offset,
                        max_bytes: FRAME_BYTES,
                    })
                    .await?
                    .into_inner();
            }
            Ok::<_, eyre::Report>(())
        };
        let receive = async {
            let receipt = destination
                .write_payload(tokio_stream::wrappers::ReceiverStream::new(receiver))
                .await?
                .into_inner();
            ensure!(
                receipt.bytes == length && receipt.descriptor.as_ref() == Some(&expected),
                "destination receipt differs from the transferred payload"
            );
            Ok::<_, eyre::Report>(())
        };
        tokio::try_join!(send, receive)?;
        Ok(length)
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationStatus {
    operation: OperationId,
    source: Option<libvm::handoff::types::HandoffRecord>,
    destination: Option<libvm::handoff::types::HandoffRecord>,
}

#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferCounts {
    payloads: u64,
    payload_bytes: u64,
}

impl TransferCounts {
    fn add(&mut self, length: u64) -> eyre::Result<()> {
        self.payload_bytes = self
            .payload_bytes
            .checked_add(length)
            .ok_or_else(|| eyre::eyre!("payload byte counter overflow"))?;
        self.payloads = self
            .payloads
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("payload counter overflow"))?;
        Ok(())
    }
}

#[derive(Default, serde::Serialize)]
struct PayloadCounts {
    immutable: TransferCounts,
    mutable: TransferCounts,
    metadata: TransferCounts,
}

impl PlanArgs {
    fn request(&mut self) -> eyre::Result<DestinationRequest> {
        // Consume the shared CLI resource parser once, with no second mapping convention.
        let resources = std::mem::take(&mut self.resources).policy()?;
        Ok(DestinationRequest {
            operation: self.operation,
            mode: match self.mode {
                Mode::Fork => libvm::handoff::types::HandoffMode::Fork,
                Mode::Relocate => libvm::handoff::types::HandoffMode::Relocate,
            },
            name: self.name.clone(),
            boot_bundle: self.boot_bundle,
            resources,
        })
    }
}

impl Cmd {
    pub async fn run(self, _context: &mut Context) -> eyre::Result<()> {
        match self.command {
            Action::Plan(mut args) => {
                let request = args.request()?;
                let mut sessions = Sessions::connect(&args.destination).await?;
                let proposal = sessions.propose(&args.machine, &request).await?;
                print_json(&serde_json::json!({
                    "operation": args.operation,
                    "digest": proposal.plan.digest(),
                    "sourceRuntime": proposal.plan.source_runtime(),
                    "destinationRuntime": proposal.plan.destination_runtime(),
                    "plan": serde_json::from_slice::<serde_json::Value>(proposal.plan.document().bytes())?,
                    "estimate": proposal.estimate,
                }))
            }
            Action::Transfer {
                mut plan,
                approve_plan,
                stop_running,
            } => {
                let request = plan.request()?;
                let mut sessions = Sessions::connect(&plan.destination).await?;
                let status = sessions.status(plan.operation).await?;
                let approved = if status.source.is_some() || status.destination.is_some() {
                    let saved = sessions.saved_plan(plan.operation, &status).await?;
                    ensure!(
                        saved.digest() == approve_plan,
                        "approval does not match this operation's saved plan"
                    );
                    saved.plan().validate_request(&request)?;
                    validate_source_selector(&plan.machine, saved.plan())?;
                    saved
                } else {
                    let proposal = sessions.propose(&plan.machine, &request).await?;
                    proposal.plan.approve(approve_plan)?
                };
                let stop = if stop_running {
                    w::HandoffSourceStop::StopRunning
                } else {
                    w::HandoffSourceStop::Require
                };
                let operation = plan.operation;
                let report = sessions.complete(&approved, stop).await
                    .wrap_err_with(|| format!("handoff {operation} interrupted; inspect or recover this same operation, never infer abort from an unavailable peer"))?;
                print_json(&report)
            }
            Action::Status(args) => {
                let mut sessions = Sessions::connect(&args.destination).await?;
                print_json(&sessions.status(args.operation).await?)
            }
            Action::Recover(args) => {
                let mut sessions = Sessions::connect(&args.destination).await?;
                let status = sessions.status(args.operation).await?;
                if let Some(terminal) = status
                    .destination
                    .as_ref()
                    .and_then(|record| record.terminal.as_ref())
                {
                    if status.source.is_some() {
                        sessions
                            .source
                            .resolve_source(convert::terminal_to_wire(terminal)?)
                            .await?;
                    }
                    return print_json(
                        &sessions
                            .completion(args.operation, PayloadCounts::default())
                            .await?,
                    );
                }
                let plan = sessions.saved_plan(args.operation, &status).await?;
                let report = sessions.complete(&plan, w::HandoffSourceStop::Require).await
                    .wrap_err_with(|| format!("handoff {} remains unresolved; no source ownership was released without a durable peer decision", args.operation))?;
                print_json(&report)
            }
            Action::Abort(args) => {
                let mut sessions = Sessions::connect(&args.destination).await?;
                let status = sessions.status(args.operation).await?;
                let intent = status
                    .source
                    .as_ref()
                    .or(status.destination.as_ref())
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "unknown operation {}; absence is not durable abort evidence",
                            args.operation
                        )
                    })?
                    .intent
                    .clone();
                let terminal = convert::terminal_from_wire(
                    sessions
                        .destination
                        .abort(convert::intent_to_wire(&intent)?)
                        .await?
                        .into_inner(),
                )?;
                ensure!(
                    terminal.intent == intent,
                    "destination returned a decision for another intent"
                );
                if status.source.is_some() {
                    sessions
                        .source
                        .resolve_source(convert::terminal_to_wire(&terminal)?)
                        .await?;
                }
                // A commit that won the destination CAS is resolved as committed,
                // not presented as an abort that could allow a source restart.
                print_json(&sessions.status(args.operation).await?)
            }
        }
    }
}

fn validate_source_selector(selector: &str, plan: &HandoffPlan) -> eyre::Result<()> {
    let reference = libvm::MachineRef::parse(selector)?;
    let id = uuid::Uuid::from(plan.source_machine());
    let matches = if let Some(expected) = reference.id_uuid() {
        expected == id
    } else if let Some(name) = reference.name() {
        name == plan.source_name()
    } else if let Some(prefix) = reference.id_prefix() {
        id.simple().to_string().starts_with(prefix)
    } else {
        false
    };
    ensure!(
        matches,
        "source selector differs from the saved operation's machine"
    );
    Ok(())
}

impl Sessions {
    async fn propose(
        &mut self,
        machine: &str,
        request: &DestinationRequest,
    ) -> eyre::Result<HandoffProposal> {
        let reference = libvm::MachineRef::parse(machine)?;
        let observation = convert::observation_from_wire(
            self.source
                .observe_source(silo_vm_control::lifecycle::reference_to_wire(&reference)?)
                .await?
                .into_inner(),
        )?;
        ensure!(
            observation.runtime() == self.source_runtime,
            "source observation belongs to another runtime"
        );
        let proposal = convert::proposal_from_wire(
            self.destination
                .preflight_destination(w::HandoffPreflightRequest {
                    observation: Some(convert::document_to_wire(observation.document())?),
                    destination: Some(convert::destination_to_wire(request)?),
                })
                .await?
                .into_inner(),
        )?;
        ensure!(
            proposal.plan.operation() == request.operation
                && proposal.plan.source_runtime() == self.source_runtime
                && proposal.plan.destination_runtime() == self.destination_runtime
                && proposal.plan.source_machine() == observation.machine(),
            "destination proposal differs from the selected operation and source"
        );
        proposal.plan.validate_request(request)?;
        Ok(proposal)
    }

    async fn saved_plan(
        &mut self,
        operation: OperationId,
        status: &OperationStatus,
    ) -> eyre::Result<ApprovedPlan> {
        let client = if status.source.is_some() {
            &mut self.source
        } else if status.destination.is_some() {
            &mut self.destination
        } else {
            return Err(eyre::eyre!("unknown handoff operation {operation}"));
        };
        let plan = convert::approved_from_wire(
            client
                .get_plan(w::HandoffOperationRef {
                    operation: operation.to_string(),
                })
                .await?
                .into_inner(),
        )?;
        let intent = plan.intent()?;
        ensure!(
            intent.operation == operation
                && intent.source_runtime == self.source_runtime
                && intent.destination_runtime == self.destination_runtime,
            "saved plan belongs to another runtime pair or operation"
        );
        for record in status.source.iter().chain(status.destination.iter()) {
            ensure!(
                record.intent == intent,
                "saved plan contradicts the durable operation intent"
            );
        }
        Ok(plan)
    }

    async fn complete(
        &mut self,
        plan: &ApprovedPlan,
        stop: w::HandoffSourceStop,
    ) -> eyre::Result<Completion> {
        let intent = plan.intent()?;
        let operation = intent.operation;
        let status = self.status(operation).await?;
        let mut payload = PayloadCounts::default();
        if let Some(terminal) = status
            .destination
            .as_ref()
            .and_then(|record| record.terminal.as_ref())
        {
            ensure!(
                terminal.intent == intent,
                "terminal decision differs from approved plan"
            );
            if status.source.is_some() {
                self.source
                    .resolve_source(convert::terminal_to_wire(terminal)?)
                    .await?;
            }
            return self.completion(operation, payload).await;
        }
        ensure!(
            !status
                .source
                .as_ref()
                .is_some_and(|record| record.phase.is_terminal()),
            "source has a terminal decision but destination has no matching terminal receipt"
        );
        let request = w::HandoffReceiveRequest {
            operation: operation.to_string(),
            approved_plan: Some(convert::document_to_wire(plan.document())?),
        };
        self.source.begin_source(request.clone()).await?;
        self.destination.receive(request).await?;
        if status
            .source
            .as_ref()
            .and_then(|record| record.binding.as_ref())
            .is_none()
        {
            self.transfer_missing(operation, &mut payload.immutable, &mut payload.metadata)
                .await?;
        }
        let offer = convert::offer_from_wire(
            self.source
                .capture_source(w::HandoffCaptureRequest {
                    operation: operation.to_string(),
                    approved_plan: Some(convert::document_to_wire(plan.document())?),
                    stop: stop as i32,
                })
                .await?
                .into_inner(),
        )?;
        ensure!(
            offer.binding().intent == intent,
            "captured cut differs from approved intent"
        );
        self.destination
            .offer_capture(convert::offer_to_wire(&offer)?)
            .await?;
        self.transfer_missing(operation, &mut payload.mutable, &mut payload.metadata)
            .await?;
        let prepared = convert::prepared_from_wire(
            self.destination
                .prepare(convert::binding_to_wire(offer.binding())?)
                .await?
                .into_inner(),
        )?;
        ensure!(
            prepared.binding == *offer.binding(),
            "prepared receipt names a different capture"
        );
        let authorization = convert::authorization_from_wire(
            self.source
                .fence_source(convert::prepared_to_wire(&prepared)?)
                .await?
                .into_inner(),
        )?;
        ensure!(
            authorization.prepared == prepared,
            "source authorization names another prepared receipt"
        );
        let terminal = convert::terminal_from_wire(
            self.destination
                .commit(convert::authorization_to_wire(&authorization)?)
                .await?
                .into_inner(),
        )?;
        ensure!(
            terminal.intent == intent && terminal.authorization.as_ref() == Some(&authorization),
            "destination decision differs from the authorized transfer"
        );
        self.source
            .resolve_source(convert::terminal_to_wire(&terminal)?)
            .await?;
        self.completion(operation, payload).await
    }

    async fn completion(
        &mut self,
        operation: OperationId,
        payload: PayloadCounts,
    ) -> eyre::Result<Completion> {
        let status = self.status(operation).await?;
        let terminal = status
            .destination
            .as_ref()
            .and_then(|record| record.terminal.as_ref())
            .ok_or_else(|| eyre::eyre!("destination has no durable terminal decision"))?;
        let decision = terminal.decision;
        Ok(Completion {
            operation,
            decision,
            source: status.source,
            destination: status.destination,
            payload,
        })
    }
}

#[derive(serde::Serialize)]
struct Completion {
    operation: OperationId,
    decision: libvm::handoff::types::HandoffDecision,
    source: Option<libvm::handoff::types::HandoffRecord>,
    destination: Option<libvm::handoff::types::HandoffRecord>,
    payload: PayloadCounts,
}

fn print_json(value: &impl serde::Serialize) -> eyre::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
