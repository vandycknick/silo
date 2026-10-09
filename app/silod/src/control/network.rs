use crate::control::{conversion, native, reference, required, Service, Stream};
use silo_vm_control::{network, updates};
use silod_spec::daemon::v1 as w;
use tonic::Response;
use tonic::{Request, Status};
fn name(value: &str) -> Result<(), Status> {
    libvm::NetworkDefinition::nat(value)
        .validate()
        .map_err(|_| Status::invalid_argument("invalid network name"))
}
#[tonic::async_trait]
impl w::network_service_server::NetworkService for Service {
    type ListNetworkDefinitionsStream = Stream<w::NetworkDefinition>;
    async fn list_network_definitions(
        &self,
        _: Request<()>,
    ) -> Result<Response<Self::ListNetworkDefinitionsStream>, Status> {
        let runtime = self.runtime().await?;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            match runtime.list_network_definitions().await {
                Ok(entries) => {
                    for e in entries {
                        if tx
                            .send(network::definition_to_wire(&e).map_err(conversion))
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
    async fn get_network_definition(
        &self,
        r: Request<w::Name>,
    ) -> Result<Response<w::OptionalNetworkDefinition>, Status> {
        let n = r.into_inner().name;
        name(&n)?;
        let value = self
            .runtime()
            .await?
            .get_network_definition(&n)
            .await
            .map_err(native)?;
        Ok(Response::new(w::OptionalNetworkDefinition {
            definition: value
                .as_ref()
                .map(network::definition_to_wire)
                .transpose()
                .map_err(conversion)?,
        }))
    }
    async fn create_network_definition(
        &self,
        r: Request<w::CreateNetworkDefinitionRequest>,
    ) -> Result<Response<()>, Status> {
        let value = network::definition_from_wire(required(r.get_ref().definition.clone())?)
            .map_err(conversion)?;
        let state = self.clone();
        self.mutate(&r, false, async move {
            state
                .runtime()
                .await?
                .network(value.name)
                .topology(value.topology)
                .driver(value.driver)
                .create()
                .await
                .map_err(native)
        })
        .await?;
        Ok(Response::new(()))
    }
    async fn remove_network_definition(&self, r: Request<w::Name>) -> Result<Response<()>, Status> {
        let n = r.get_ref().name.clone();
        name(&n)?;
        let state = self.clone();
        self.mutate(&r, false, async move {
            state
                .runtime()
                .await?
                .remove_network_definition(&n)
                .await
                .map_err(native)
        })
        .await?;
        Ok(Response::new(()))
    }
    async fn set_machine_network(
        &self,
        r: Request<w::SetMachineNetworkRequest>,
    ) -> Result<Response<w::MachineSnapshot>, Status> {
        let reference = reference(r.get_ref().machine.clone())?;
        let update = updates::update_from_wire(w::MachineUpdate {
            network: Some(required(r.get_ref().network.clone())?),
            ..Default::default()
        })
        .map_err(conversion)?;
        let state = self.clone();
        Ok(Response::new(
            self.mutate(&r, true, async move {
                silo_vm_control::snapshots::snapshot_to_wire(
                    &state
                        .machine(&reference)
                        .await?
                        .update(update)
                        .await
                        .map_err(native)?,
                )
                .map_err(conversion)
            })
            .await?,
        ))
    }
}
