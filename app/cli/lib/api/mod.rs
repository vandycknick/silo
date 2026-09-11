//! CLI application API boundary.
//!
//! `local` is the in-process ABI adapter around libvm. ABI here means ordinary
//! Rust calls within the CLI process, not a C ABI, FFI surface, or wire protocol.

mod local;

use libvm::{Runtime, RuntimeConfig};

#[derive(Debug)]
pub(crate) struct AppApi {
    local: local::LocalVmService,
}

impl AppApi {
    pub(crate) fn local(config: RuntimeConfig) -> Self {
        Self {
            local: local::LocalVmService::new(config),
        }
    }

    pub(crate) async fn runtime(&mut self) -> eyre::Result<&Runtime> {
        self.local.runtime().await
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use libvm::RuntimeConfig;

    use crate::api::AppApi;

    #[tokio::test]
    async fn local_api_uses_only_its_explicit_disposable_roots() {
        let temp = tempfile::tempdir().expect("create disposable application roots");
        let data = temp.path().join("data");
        let state = temp.path().join("state");
        let run = temp.path().join("run");
        let images = temp.path().join("images");
        let components = temp.path().join("components");
        let bin = components.join("bin");
        let assets = components.join("assets");
        std::fs::create_dir_all(&bin).expect("create binary component fixtures");
        std::fs::create_dir(&assets).expect("create asset component fixtures");
        for name in ["vmmon", "netd", "krun"] {
            executable_fixture(&bin, name);
        }
        for name in ["kernel-default", "initramfs"] {
            std::fs::write(assets.join(name), b"fixture").expect("write asset fixture");
        }
        executable_fixture(&assets, "agent");
        let config = RuntimeConfig::local(&data)
            .with_state_root(&state)
            .with_run_root(&run)
            .with_image_root(&images)
            .with_runtime_root(&components);
        let mut api = AppApi::local(config);

        let machines = api
            .runtime()
            .await
            .expect("open isolated local API")
            .list_machines()
            .await
            .expect("list isolated machines");

        assert!(machines.is_empty());
        assert!(data.join("state.db").is_file());
        assert!(run.is_dir());
        assert!(!temp.path().join(".docker").exists());
        assert!(!temp.path().join("native-service").exists());
    }

    fn executable_fixture(parent: &Path, name: &str) -> std::path::PathBuf {
        let path = parent.join(name);
        std::fs::write(&path, b"fixture").expect("write component fixture");
        let mut permissions = std::fs::metadata(&path)
            .expect("inspect component fixture")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("make component fixture executable");
        path
    }
}
