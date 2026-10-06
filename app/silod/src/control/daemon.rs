use crate::control::{required, ControlState, Service};
use silod_spec::daemon::v1 as w;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl w::daemon_service_server::DaemonService for Service {
    async fn get_status(&self, _: Request<()>) -> Result<Response<w::DaemonStatus>, Status> {
        Ok(Response::new(ControlState::get_status(self).await?))
    }

    async fn get_runtime_info(&self, _: Request<()>) -> Result<Response<w::RuntimeInfo>, Status> {
        let c = self.components().await?;
        Ok(Response::new(w::RuntimeInfo {
            generation: self.generation.to_string(),
            home: silo_vm_control::path_to_wire(self.host.home()),
            components: Some(w::RuntimeComponents {
                supervisor_path: silo_vm_control::path_to_wire(c.supervisor()),
                netd_path: silo_vm_control::path_to_wire(c.netd()),
                kernel_path: silo_vm_control::path_to_wire(c.kernel()),
                initramfs_path: silo_vm_control::path_to_wire(c.initramfs()),
                agent_path: silo_vm_control::path_to_wire(c.agent()),
                asset_dir: silo_vm_control::path_to_wire(c.asset_dir()),
            }),
        }))
    }

    async fn report_tailscale_status(
        &self,
        r: Request<w::TailscaleStatusReport>,
    ) -> Result<Response<()>, Status> {
        let header = r
            .metadata()
            .get("x-silo-helper-generation")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let v = r.into_inner();
        let mut admission = self.admission.lock();
        if admission.helper.as_deref() != Some(v.helper_generation.as_str())
            || header.as_deref() != Some(v.helper_generation.as_str())
        {
            return Err(Status::failed_precondition("stale helper generation"));
        }
        let status = required(v.status)?;
        if !(1..=6).contains(&status.state) || !(1..=3).contains(&status.shutdown_protection) {
            return Err(Status::invalid_argument("invalid component status"));
        }
        let restart_count = u32::try_from(status.restart_count)
            .map_err(|_| Status::invalid_argument("restart count exceeds uint32"))?;
        if status.diagnostic.as_ref().is_some_and(|v| v.len() > 1024)
            || status.approval_url.as_ref().is_some_and(|v| v.len() > 2048)
            || status.dns_name.as_ref().is_some_and(|v| v.len() > 253)
        {
            return Err(Status::invalid_argument("component status too long"));
        }
        if let Some(instance) = v.instance {
            // Match taild's existing 16-byte hex instance format; preserve its
            // identity across supervised helper generations in this daemon.
            if instance.len() != 32 || !instance.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Status::invalid_argument("invalid helper instance"));
            }
            if admission
                .instance
                .as_ref()
                .is_some_and(|previous| previous != &instance)
            {
                return Err(Status::failed_precondition("helper instance changed"));
            }
            admission.instance = Some(instance);
        }
        use silod_spec::status::{ComponentState, ComponentStatus, ShutdownProtection};
        let component = ComponentStatus {
            enabled: status.enabled,
            state: match w::ComponentState::try_from(status.state).unwrap() {
                w::ComponentState::Disabled => ComponentState::Disabled,
                w::ComponentState::Starting => ComponentState::Starting,
                w::ComponentState::NeedsAuth => ComponentState::NeedsAuth,
                w::ComponentState::Ready => ComponentState::Ready,
                w::ComponentState::Degraded => ComponentState::Degraded,
                w::ComponentState::Failed => ComponentState::Failed,
                w::ComponentState::Unspecified => unreachable!(),
            },
            diagnostic: status.diagnostic,
            approval_url: status.approval_url,
            dns_name: status.dns_name,
            restart_count,
            shutdown_protection: match w::ShutdownProtection::try_from(status.shutdown_protection)
                .unwrap()
            {
                w::ShutdownProtection::Active => ShutdownProtection::Active,
                w::ShutdownProtection::Unavailable => ShutdownProtection::Unavailable,
                w::ShutdownProtection::Unsupported => ShutdownProtection::Unsupported,
                w::ShutdownProtection::Unspecified => unreachable!(),
            },
        };
        self.publisher
            .report_tailscale(component)
            .map_err(|_| Status::internal("cannot publish component status"))?;
        Ok(Response::new(()))
    }

    async fn drain_mutations(
        &self,
        r: Request<w::DrainMutationsRequest>,
    ) -> Result<Response<()>, Status> {
        if r.into_inner().expected_generation != self.generation.to_string() {
            return Err(Status::failed_precondition("daemon generation changed"));
        }
        if !self.admission.lock().sealed {
            return Err(Status::failed_precondition(
                "seal mutation admission before draining",
            ));
        }
        ControlState::drain_mutations(self).await?;
        Ok(Response::new(()))
    }
}
