use crate::daemon::control::{ControlState, Service};
use silod_spec::daemon::v1 as w;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl w::daemon_service_server::DaemonService for Service {
    async fn get_status(&self, _: Request<()>) -> Result<Response<w::DaemonStatus>, Status> {
        Ok(Response::new(ControlState::get_status(self).await?))
    }

    async fn get_live_capabilities(
        &self,
        _: Request<()>,
    ) -> Result<Response<w::LiveHostReport>, Status> {
        let report = self.live_capabilities().await?;
        Ok(Response::new(
            silo_vm_control::live::host_to_wire(&report)
                .map_err(crate::daemon::control::conversion)?,
        ))
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
}
