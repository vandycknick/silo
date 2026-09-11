use eyre::Context as _;
use libvm::{Runtime, RuntimeConfig};

#[derive(Debug)]
pub(crate) struct LocalVmService {
    config: Option<RuntimeConfig>,
    runtime: Option<Runtime>,
}

impl LocalVmService {
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        Self {
            config: Some(config),
            runtime: None,
        }
    }

    pub(crate) async fn runtime(&mut self) -> eyre::Result<&Runtime> {
        if self.runtime.is_none() {
            let config = self
                .config
                .take()
                .ok_or_else(|| eyre::eyre!("local runtime configuration was not initialized"))?;
            self.runtime = Some(
                Runtime::new(config)
                    .await
                    .context("initialize local libvm adapter")?,
            );
        }

        self.runtime
            .as_ref()
            .ok_or_else(|| eyre::eyre!("local runtime was not initialized"))
    }
}
