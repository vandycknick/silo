use crate::daemon::control::{
    conversion, duration, id, native, reference, required, run, Service, Stream,
};
use futures::StreamExt;
use silo_vm_control::{lifecycle, readiness, requests, snapshots, updates};
use silod_spec::daemon::v1 as w;
use tonic::Response;
use tonic::{Request, Status};
fn snapshot(v: &libvm::MachineData) -> Result<w::MachineSnapshot, Status> {
    snapshots::snapshot_to_wire(v).map_err(conversion)
}
fn run_ref(
    v: Option<w::MachineRunRef>,
) -> Result<(libvm::MachineRef, libvm::MachineRunId), Status> {
    let v = required(v)?;
    Ok((id(&v.id)?, run(&v.run_id)?))
}
#[tonic::async_trait]
impl w::machine_service_server::MachineService for Service {
    type ListMachinesStream = Stream<w::MachineInventoryEntry>;
    type CreateMachineStream = Stream<w::CreateMachineEvent>;
    type ReadLogsStream = Stream<w::LogChunk>;
    async fn export_raw_disk(
        &self,
        r: Request<w::ExportRawDiskRequest>,
    ) -> Result<Response<w::RawDiskExport>, Status> {
        let (reference, options) =
            silo_vm_control::stopped::raw_export_request_from_wire(r.into_inner())
                .map_err(conversion)?;
        let state = self.clone();
        let result = self
            .mutate(async move {
                let report = state
                    .machine(&reference)
                    .await?
                    .export_raw_disk(options)
                    .await
                    .map_err(native)?;
                silo_vm_control::stopped::raw_export_to_wire(&report).map_err(conversion)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn pause_machine(
        &self,
        r: Request<w::LiveMachineRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let reference = reference(r.get_ref().machine.clone())?;
        if !libvm::LiveObservationReader::open(&self.config)
            .map_err(native)?
            .catalog_exists()
            .map_err(native)?
        {
            self.require_machine_live(&reference, vm_spec::live::LiveOperation::Pause)
                .await?;
        }
        let observation = self.observe_machine_live(&reference).await?;
        observation.require_pause_submission().map_err(native)?;
        let state = self.clone();
        let result = self
            .mutate(async move {
                let machine = state.machine(&reference).await?;
                machine.pause(&observation).await.map_err(native)?;
                snapshot(&machine.inspect().await.map_err(native)?)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn resume_machine(
        &self,
        r: Request<w::LiveMachineRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let reference = reference(r.get_ref().machine.clone())?;
        let observation = self.observe_machine_live(&reference).await?;
        let state = self.clone();
        let result = self
            .mutate(async move {
                let machine = state.machine(&reference).await?;
                machine.resume(&observation).await.map_err(native)?;
                snapshot(&machine.inspect().await.map_err(native)?)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn capture_execution(
        &self,
        r: Request<w::LiveCaptureRequest>,
    ) -> Result<Response<w::LiveSnapshotInfo>, Status> {
        let value = r.into_inner();
        let reference = reference(value.machine)?;
        let options = libvm::LiveSnapshotOptions {
            name: value
                .name
                .map(|name| silo_vm_control::stopped::alias(&name))
                .transpose()
                .map_err(conversion)?,
            resume_policy: silo_vm_control::capture::resume_policy_from_wire(value.resume_policy)
                .map_err(conversion)?,
            policy: silo_vm_control::capture::policy_from_wire(value.policy).map_err(conversion)?,
            dirty_crossover_percent: silo_vm_control::capture::crossover_from_wire(
                value.dirty_crossover_percent,
            )
            .map_err(conversion)?,
        };
        options.validate().map_err(native)?;
        // Capability refusal precedes every lock, reservation and journal row.
        self.require_machine_live(&reference, vm_spec::live::LiveOperation::Capture)
            .await?;
        let observation = self.observe_machine_live(&reference).await?;
        let state = self.clone();
        let result = self
            .mutate(async move {
                let snapshot = state
                    .machine(&reference)
                    .await?
                    .snapshot_live(&observation, options)
                    .await
                    .map_err(native)?;
                silo_vm_control::capture::live_snapshot_to_wire(&snapshot).map_err(conversion)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn fork_execution(
        &self,
        r: Request<w::LiveForkRequest>,
    ) -> Result<Response<w::LiveForkResult>, Status> {
        let (reference, options) =
            silo_vm_control::fork::request_from_wire(r.into_inner()).map_err(conversion)?;
        options.validate().map_err(native)?;
        // Capability refusal precedes every lock, reservation and journal row.
        self.require_machine_live(&reference, vm_spec::live::LiveOperation::Fork)
            .await?;
        let observation = self.observe_machine_live(&reference).await?;
        let state = self.clone();
        // The spawned mutation owns the operation: a client disconnect is not cancellation.
        let result = self
            .mutate(async move {
                let result = state
                    .machine(&reference)
                    .await?
                    .fork_live(&observation, options)
                    .await
                    .map_err(native)?;
                silo_vm_control::fork::result_to_wire(&result).map_err(conversion)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn fork_stopped(
        &self,
        r: Request<w::StoppedForkRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let value = r.into_inner();
        let reference = reference(value.machine)?;
        let options = libvm::ForkOptions {
            name: silo_vm_control::stopped::name(value.name).map_err(conversion)?,
            external_resources: silo_vm_control::stopped::policy_from_wire(required(
                value.external_resources,
            )?)
            .map_err(conversion)?,
        };
        libvm::preflight_stopped(&self.config, &reference, false, &options.external_resources)
            .await
            .map_err(native)?;
        let state = self.clone();
        let result = self
            .mutate(async move {
                let child = state
                    .machine(&reference)
                    .await?
                    .fork_stopped(options)
                    .await
                    .map_err(native)?;
                snapshot(&child.inspect().await.map_err(native)?)
            })
            .await?;
        Ok(Response::new(result))
    }

    async fn snapshot_stopped(
        &self,
        r: Request<w::CreateStorageSnapshotRequest>,
    ) -> Result<Response<w::StorageSnapshotInfo>, Status> {
        let value = r.into_inner();
        let reference = reference(value.machine)?;
        let options = libvm::SnapshotOptions {
            name: value
                .name
                .map(|name| silo_vm_control::stopped::alias(&name))
                .transpose()
                .map_err(conversion)?,
            external_resources: silo_vm_control::stopped::policy_from_wire(required(
                value.external_resources,
            )?)
            .map_err(conversion)?,
        };
        silo_vm_control::stopped::snapshot_policy(&options.external_resources)
            .map_err(conversion)?;
        libvm::preflight_stopped(&self.config, &reference, true, &options.external_resources)
            .await
            .map_err(native)?;
        let state = self.clone();
        let result = self
            .mutate(async move {
                let info = state
                    .machine(&reference)
                    .await?
                    .snapshot_stopped(options)
                    .await
                    .map_err(native)?;
                silo_vm_control::stopped::info_to_wire(&info).map_err(conversion)
            })
            .await?;
        Ok(Response::new(result))
    }
    async fn list_machines(
        &self,
        _: Request<()>,
    ) -> Result<Response<Self::ListMachinesStream>, Status> {
        let runtime = self.runtime().await?;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            match runtime.inventory().await {
                Ok(entries) => {
                    for entry in entries {
                        if tx
                            .send(snapshots::inventory_to_wire(&entry).map_err(conversion))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(native(e))).await;
                }
            }
        });
        Ok(Response::new(self.response_stream(rx)))
    }
    async fn inspect_inventory(
        &self,
        r: Request<w::MachineRef>,
    ) -> Result<Response<w::MachineInventoryEntry>, Status> {
        let reference = lifecycle::reference_from_wire(r.into_inner()).map_err(conversion)?;
        let v = self
            .runtime()
            .await?
            .inspect_inventory(&reference)
            .await
            .map_err(native)?;
        Ok(Response::new(
            snapshots::inventory_to_wire(&v).map_err(conversion)?,
        ))
    }
    async fn inspect_machine(
        &self,
        r: Request<w::MachineRef>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let reference = lifecycle::reference_from_wire(r.into_inner()).map_err(conversion)?;
        let m = self.machine(&reference).await?;
        let mut v = snapshot(&m.inspect().await.map_err(native)?)?;
        let mut observation = silo_vm_control::node_status::observation_to_wire(
            &m.network_observation().await.map_err(native)?,
        )
        .map_err(conversion)?;
        if observation
            .live
            .as_ref()
            .is_some_and(|live| v.run_id.as_deref() != Some(live.run_id.as_str()))
        {
            observation.live = None;
            observation
                .issues
                .push(w::NetworkObservationIssue::WrongGeneration as i32);
        }
        v.network_observation = Some(observation);
        Ok(Response::new(v))
    }
    async fn ensure_name_available(&self, r: Request<w::Name>) -> Result<Response<()>, Status> {
        let name = r.into_inner().name;
        self.runtime()
            .await?
            .ensure_name_available(&name)
            .await
            .map_err(native)?;
        Ok(Response::new(()))
    }
    async fn create_machine(
        &self,
        r: Request<w::CreateMachineRequest>,
    ) -> Result<Response<Self::CreateMachineStream>, Status> {
        let (config, source, secret_scope) =
            requests::create_request_from_wire(r.into_inner()).map_err(conversion)?;
        let state = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let tx_terminal = tx.clone();
        let (progress, mut events) = libvm::ImageProgressSender::channel(8);
        let permit = self.admit().await?;
        let tx_error = tx.clone();
        // Forward progress concurrently; losing the consumer must not abandon native creation.
        let forwarding = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let v = silo_vm_control::images::progress_to_wire(&event)
                    .map(|v| w::CreateMachineEvent {
                        event: Some(w::create_machine_event::Event::Progress(v)),
                    })
                    .map_err(conversion);
                if tx.send(v).await.is_err() {
                    break;
                }
            }
        });
        let work = async move {
            let runtime = state.runtime().await?.with_image_progress(progress);
            let builder = match source {
                requests::CreateSource::Disk(request) => runtime
                    .machine()
                    .image_source(libvm::ImageSource::Disk(request)),
                requests::CreateSource::Managed(reference) => runtime
                    .machine()
                    .image_source(libvm::ImageSource::Managed(reference)),
                requests::CreateSource::Oci(identity) => {
                    let mut image = runtime
                        .images()
                        .resolve_with(
                            identity.selected_reference.clone(),
                            identity.resolve_options().map_err(conversion)?,
                        )
                        .await
                        .map_err(native)?;
                    identity.verify(&image).map_err(conversion)?;
                    image.requested_reference = identity.requested_reference;
                    runtime
                        .clone()
                        .with_image_pull_policy(identity.pull_policy)
                        .machine()
                        .resolved_image(image)
                }
            };
            let machine = config
                .apply_to_builder(builder.secret_scope(secret_scope))
                .map_err(native)?
                .create()
                .await
                .map_err(native)?;
            snapshot(&machine.inspect().await.map_err(native)?)
        };
        tokio::spawn(async move {
            let result = work.await;
            drop(permit);
            let _ = forwarding.await;
            let event = result.map(|value| w::CreateMachineEvent {
                event: Some(w::create_machine_event::Event::Machine(Box::new(value))),
            });
            let _ = tx_terminal.send(event).await;
            drop(tx_error);
        });
        Ok(Response::new(self.response_stream(rx)))
    }
    async fn start_machine(
        &self,
        r: Request<w::StartMachineRequest>,
    ) -> Result<Response<w::MachineStart>, Status> {
        let v = r.into_inner();
        let reference = reference(v.machine)?;
        let opts = lifecycle::start_options_from_wire(required(v.options)?).map_err(conversion)?;
        let state = self.clone();
        let out = self
            .mutate(async move {
                let m = state.machine(&reference).await?;
                let mut options = libvm::MachineStartOptions::new().credentials(opts.credentials);
                if let Some(e) = opts.entrypoint {
                    options = options.entrypoint(e.program().to_owned(), |_| e);
                }
                if opts.cleanup_on_exit {
                    let command = std::env::current_exe()
                        .and_then(|path| path.canonicalize())
                        .map_err(|_| Status::unavailable("silo executable path unavailable"))?;
                    options = options.on_exit(
                        libvm::HostCommand::new(command)
                            .arg("cleanup")
                            .arg("--home")
                            .arg(state.host.home())
                            .arg("--machine-id")
                            .arg(m.id()),
                    );
                }
                lifecycle::start_to_wire(&m.start_with_options(options).await.map_err(native)?)
                    .map_err(conversion)
            })
            .await?;
        Ok(Response::new(out))
    }
    async fn stop_machine(
        &self,
        r: Request<w::StopMachineRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let v = r.into_inner();
        let reference = reference(v.machine)?;
        let timeout = v.timeout.map(|value| duration(Some(value))).transpose()?;
        let expected = v.expected_run.as_deref().map(run).transpose()?;
        let state = self.clone();
        Ok(Response::new(
            self.mutate(async move {
                let m = state.machine(&reference).await?;
                if v.force {
                    let mut options = libvm::MachineKillOptions::new();
                    if let Some(timeout) = timeout {
                        options = options.timeout(timeout);
                    }
                    match expected {
                        Some(run) => {
                            m.kill_run_with(run, options).await.map_err(native)?;
                        }
                        None => {
                            m.kill_with(options).await.map_err(native)?;
                        }
                    }
                    snapshot(&m.inspect().await.map_err(native)?)
                } else {
                    let mut options = libvm::MachineStopOptions::new();
                    if let Some(timeout) = timeout {
                        options = options.timeout(timeout);
                    }
                    let data = match expected {
                        Some(run) => m.stop_run_with(run, options).await,
                        None => m.stop_with(options).await,
                    }
                    .map_err(native)?;
                    snapshot(&data)
                }
            })
            .await?,
        ))
    }
    async fn remove_machine(
        &self,
        r: Request<w::RemoveMachineRequest>,
    ) -> Result<Response<()>, Status> {
        let reference = reference(r.get_ref().machine.clone())?;
        let state = self.clone();
        self.mutate(async move {
            state
                .machine(&reference)
                .await?
                .remove()
                .await
                .map_err(native)
        })
        .await?;
        Ok(Response::new(()))
    }
    async fn update_machine(
        &self,
        r: Request<w::UpdateMachineRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let reference = reference(r.get_ref().machine.clone())?;
        let update =
            updates::update_from_wire(required(r.get_ref().update.clone())?).map_err(conversion)?;
        let state = self.clone();
        Ok(Response::new(
            self.mutate(async move {
                snapshot(
                    &state
                        .machine(&reference)
                        .await?
                        .update(update)
                        .await
                        .map_err(native)?,
                )
            })
            .await?,
        ))
    }
    /// Explicit stopped boot-bundle replacement under the machine's own
    /// configuration lock; root bytes and userspace platform never change.
    async fn update_boot_assets(
        &self,
        r: Request<w::UpdateBootAssetsRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let (reference, update) =
            silo_vm_control::boot::update_boot_assets_from_wire(r.into_inner())
                .map_err(conversion)?;
        let state = self.clone();
        Ok(Response::new(
            self.mutate(async move {
                snapshot(
                    &state
                        .machine(&reference)
                        .await?
                        .update_boot_assets(update)
                        .await
                        .map_err(native)?,
                )
            })
            .await?,
        ))
    }
    async fn wait_ready(
        &self,
        r: Request<w::WaitReadyRequest>,
    ) -> Result<Response<w::MachineReadiness>, Status> {
        let v = r.into_inner();
        let reference = id(&v.id)?;
        let expected = v.expected_run.as_deref().map(run).transpose()?;
        let timeout = duration(v.timeout)?;
        let m = self.machine(&reference).await?;
        if let Some(expected) = &expected {
            let data = m.inspect().await.map_err(native)?;
            if data.run_id.as_ref() != Some(expected) {
                return Err(native(libvm::LibVmError::MachineStaleGeneration {
                    reference: m.id(),
                    requested: expected.clone(),
                    current: data.run_id,
                }));
            }
        }
        let result = m.wait_ready(timeout).await.map_err(native)?;
        if let Some(expected) = &expected {
            if result.status.run_id.as_ref() != Some(expected) {
                return Err(native(libvm::LibVmError::MachineStaleGeneration {
                    reference: m.id(),
                    requested: expected.clone(),
                    current: result.status.run_id.clone(),
                }));
            }
        }
        let data = m.inspect().await.map_err(native)?;
        if data.run_id != result.status.run_id {
            if let Some(requested) = result.status.run_id {
                return Err(native(libvm::LibVmError::MachineStaleGeneration {
                    reference: m.id(),
                    requested,
                    current: data.run_id,
                }));
            }
            return Err(Status::failed_precondition(
                "machine run changed while inspecting readiness",
            ));
        }
        let mut wire = readiness::readiness_to_wire(&result).map_err(conversion)?;
        wire.data = Some(snapshot(&data)?);
        Ok(Response::new(wire))
    }
    async fn stop_run(
        &self,
        r: Request<w::StopRunRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let (reference, run) = run_ref(r.get_ref().machine.clone())?;
        let mut options = libvm::MachineStopOptions::new().timeout(duration(r.get_ref().timeout)?);
        if let Some(force) = r.get_ref().force_after {
            options = options.force_after_timeout(duration(Some(force))?);
        }
        let state = self.clone();
        Ok(Response::new(
            self.mutate(async move {
                snapshot(
                    &state
                        .machine(&reference)
                        .await?
                        .stop_run_with(run, options)
                        .await
                        .map_err(native)?,
                )
            })
            .await?,
        ))
    }
    async fn kill_run(
        &self,
        r: Request<w::KillRunRequest>,
    ) -> Result<Response<w::MachineExit>, Status> {
        let (reference, run) = run_ref(r.get_ref().machine.clone())?;
        let options = libvm::MachineKillOptions::new().timeout(duration(r.get_ref().timeout)?);
        let state = self.clone();
        Ok(Response::new(
            self.mutate(async move {
                lifecycle::exit_to_wire(
                    &state
                        .machine(&reference)
                        .await?
                        .kill_run_with(run, options)
                        .await
                        .map_err(native)?,
                )
                .map_err(conversion)
            })
            .await?,
        ))
    }
    async fn wait_for_run(
        &self,
        r: Request<w::WaitForRunRequest>,
    ) -> Result<Response<w::MachineExit>, Status> {
        let v = r.into_inner();
        let (reference, run) = run_ref(v.machine)?;
        let options = libvm::MachineWaitOptions::new().timeout(duration(v.timeout)?);
        Ok(Response::new(
            lifecycle::exit_to_wire(
                &self
                    .machine(&reference)
                    .await?
                    .wait_for_run_with(run, options)
                    .await
                    .map_err(native)?,
            )
            .map_err(conversion)?,
        ))
    }
    async fn remove_after_run(&self, r: Request<w::MachineRunRef>) -> Result<Response<()>, Status> {
        let (reference, run) = run_ref(Some(r.into_inner()))?;
        let state = self.clone();
        self.mutate(async move {
            state
                .machine(&reference)
                .await?
                .remove_after_run(run)
                .await
                .map_err(native)
        })
        .await?;
        Ok(Response::new(()))
    }
    async fn set_machine_secret(
        &self,
        r: Request<w::SetMachineSecretRequest>,
    ) -> Result<Response<()>, Status> {
        requests::validate_machine_secret(r.get_ref()).map_err(conversion)?;
        let v = r.into_inner();
        let reference = id(&v.id)?;
        let state = self.clone();
        self.mutate(async move {
            state
                .machine(&reference)
                .await?
                .set_secret(&v.name, v.value)
                .await
                .map_err(native)
        })
        .await?;
        Ok(Response::new(()))
    }
    async fn read_logs(
        &self,
        r: Request<w::ReadLogsRequest>,
    ) -> Result<Response<Self::ReadLogsStream>, Status> {
        let v = r.into_inner();
        let reference = id(&v.id)?;
        if !(1..=6).contains(&v.source) || !(1..=3).contains(&v.output) {
            return Err(Status::invalid_argument("invalid log filters"));
        }
        let tail = v.tail_bytes;
        if tail.is_some_and(|n| n > 16 * 1024 * 1024) {
            return Err(Status::resource_exhausted("tail exceeds 16 MiB"));
        }
        let m = self.machine(&reference).await?;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        for source in [2, 3, 4, 5, 6] {
            if v.source != 1 && v.source != source {
                continue;
            }
            let source_native = requests::log_source_from_wire(source).map_err(conversion)?;
            let options = libvm::MachineLogOptions { follow: v.follow };
            let mut stream = match tail {
                Some(limit) => m.logs_tail(source_native, options, limit).await,
                None => m.logs(source_native, options).await,
            }
            .map_err(native)?;
            let mut discard_partial_line = stream.starts_mid_line();
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Some(chunk) =
                    tokio::select! { _=tx.closed()=>None, chunk=stream.next()=>chunk }
                {
                    let mut chunk = match chunk {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(Err(native(e))).await;
                            return;
                        }
                    };
                    if discard_partial_line {
                        let Some(newline) = chunk.data.iter().position(|byte| *byte == b'\n')
                        else {
                            continue;
                        };
                        discard_partial_line = false;
                        chunk.data = chunk.data.slice(newline + 1..);
                        if chunk.data.is_empty() {
                            continue;
                        }
                    }
                    let wire = match requests::log_chunk_to_wire(&chunk, source_native) {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = tx.send(Err(conversion(e))).await;
                            return;
                        }
                    };
                    if v.output != 1 && v.output != wire.output {
                        continue;
                    }
                    if tx.send(Ok(wire)).await.is_err() {
                        return;
                    }
                }
            });
        }
        drop(tx);
        Ok(Response::new(self.response_stream(rx)))
    }
}
