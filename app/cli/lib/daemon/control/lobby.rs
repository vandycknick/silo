//! In-process lobby access to the daemon's management boundary.
//!
//! Calls retain daemon admission, generation fencing and mutation ownership.
//! Results stay in the daemon's wire types; no SDK projection is needed.

use crate::daemon::control::{ControlState, Service, Stream};
use crate::lobby::failure::{Code, Failure};
use futures::{StreamExt, TryStreamExt};
use silod_spec::daemon::v1::{
    self as w, machine_service_server::MachineService, runtime_service_server::RuntimeService,
};
use std::sync::Arc;
use tonic::{Request, Status};

#[derive(Clone)]
pub(crate) struct Management(Service);

impl Management {
    // The lobby supervisor constructs it once silod starts the lobby.
    #[allow(dead_code)]
    pub(crate) fn new(state: Arc<ControlState>) -> Self {
        Self(Service(state))
    }

    pub(crate) async fn inventory(&self) -> Result<Vec<w::MachineInventoryEntry>, Status> {
        self.0
            .list_machines(Request::new(()))
            .await?
            .into_inner()
            .try_collect()
            .await
    }

    pub(crate) async fn inspect(&self, reference: &str) -> Result<w::MachineSnapshot, Status> {
        Ok(self
            .0
            .inspect_machine(Request::new(machine_ref(reference)))
            .await?
            .into_inner())
    }

    pub(crate) async fn create(
        &self,
        configuration: w::NormalizedMachineCreate,
        source: w::OciIdentity,
    ) -> Result<w::MachineSnapshot, Status> {
        let mut stream = self
            .0
            .create_machine(Request::new(w::CreateMachineRequest {
                configuration: Some(configuration),
                source: Some(w::create_machine_request::Source::Oci(source)),
            }))
            .await?
            .into_inner();
        let mut result = None;
        while let Some(event) = stream.next().await {
            let event = event?;
            if result.is_some() {
                return Err(invalid_response());
            }
            match event.event {
                Some(w::create_machine_event::Event::Machine(machine)) => result = Some(machine),
                Some(w::create_machine_event::Event::Progress(progress))
                    if progress.event.is_some() => {}
                _ => return Err(invalid_response()),
            }
        }
        result.map(|machine| *machine).ok_or_else(invalid_response)
    }

    pub(crate) async fn start(&self, reference: &str) -> Result<w::MachineStart, Status> {
        Ok(self
            .0
            .start_machine(Request::new(w::StartMachineRequest {
                machine: Some(machine_ref(reference)),
                options: Some(w::StartOptions::default()),
            }))
            .await?
            .into_inner())
    }

    pub(crate) async fn stop(
        &self,
        reference: &str,
        expected_run: Option<String>,
        force: bool,
        timeout: Option<prost_types::Duration>,
    ) -> Result<w::MachineSnapshot, Status> {
        Ok(self
            .0
            .stop_machine(Request::new(w::StopMachineRequest {
                machine: Some(machine_ref(reference)),
                expected_run,
                force,
                timeout,
            }))
            .await?
            .into_inner())
    }

    pub(crate) async fn remove(&self, reference: &str) -> Result<(), Status> {
        self.0
            .remove_machine(Request::new(w::RemoveMachineRequest {
                machine: Some(machine_ref(reference)),
            }))
            .await?;
        Ok(())
    }

    pub(crate) async fn remove_after_run(&self, id: &str, run: &str) -> Result<(), Status> {
        self.0
            .remove_after_run(Request::new(w::MachineRunRef {
                id: id.to_owned(),
                run_id: run.to_owned(),
            }))
            .await?;
        Ok(())
    }

    pub(crate) async fn update(
        &self,
        reference: &str,
        update: w::MachineUpdate,
    ) -> Result<w::MachineSnapshot, Status> {
        Ok(self
            .0
            .update_machine(Request::new(w::UpdateMachineRequest {
                machine: Some(machine_ref(reference)),
                update: Some(update),
            }))
            .await?
            .into_inner())
    }

    pub(crate) async fn wait_ready(
        &self,
        id: &str,
        run: &str,
        timeout: prost_types::Duration,
    ) -> Result<w::MachineReadiness, Status> {
        Ok(self
            .0
            .wait_ready(Request::new(w::WaitReadyRequest {
                id: id.to_owned(),
                expected_run: Some(run.to_owned()),
                timeout: Some(timeout),
            }))
            .await?
            .into_inner())
    }

    pub(crate) async fn set_secret(
        &self,
        id: &str,
        name: &str,
        value: Vec<u8>,
    ) -> Result<(), Status> {
        self.0
            .set_machine_secret(Request::new(w::SetMachineSecretRequest {
                id: id.to_owned(),
                name: name.to_owned(),
                value,
            }))
            .await?;
        Ok(())
    }

    pub(crate) async fn resolve_image(
        &self,
        reference: &str,
        policy: w::PullPolicy,
        mut progress: impl FnMut(w::ImageProgress) + Send,
    ) -> Result<w::ResolvedImage, Status> {
        let mut stream = self
            .0
            .resolve_image(Request::new(w::ResolveImageRequest {
                reference: reference.to_owned(),
                pull_policy: policy as i32,
                platform: None,
            }))
            .await?
            .into_inner();
        let mut result = None;
        while let Some(event) = stream.next().await {
            let event = event?;
            if result.is_some() {
                return Err(invalid_response());
            }
            match event.event {
                Some(w::resolve_image_event::Event::Image(image)) => result = Some(image),
                Some(w::resolve_image_event::Event::Progress(event)) if event.event.is_some() => {
                    progress(event)
                }
                _ => return Err(invalid_response()),
            }
        }
        result.ok_or_else(invalid_response)
    }

    pub(crate) async fn pull_image(&self, reference: &str) -> Result<(), Status> {
        let mut stream = self
            .0
            .pull_image(Request::new(w::PullImageRequest {
                reference: reference.to_owned(),
            }))
            .await?
            .into_inner();
        let mut complete = false;
        while let Some(progress) = stream.next().await {
            let progress = progress?;
            if complete || progress.event.is_none() {
                return Err(invalid_response());
            }
            complete = matches!(progress.event, Some(w::image_progress::Event::Complete(())));
        }
        if complete {
            Ok(())
        } else {
            Err(invalid_response())
        }
    }

    pub(crate) async fn propose_machine_name(&self) -> Result<String, Status> {
        Ok(self
            .0
            .propose_machine_name(Request::new(()))
            .await?
            .into_inner()
            .name)
    }

    pub(crate) async fn parse_resource(
        &self,
        kind: w::ResourceKind,
        value: &str,
    ) -> Result<w::Size, Status> {
        Ok(self
            .0
            .parse_resource(Request::new(w::ParseResourceRequest {
                kind: kind as i32,
                value: value.to_owned(),
            }))
            .await?
            .into_inner())
    }

    pub(crate) async fn normalize_policy(
        &self,
        request: w::NormalizePolicyRequest,
    ) -> Result<w::PolicyDocument, Status> {
        Ok(self
            .0
            .normalize_policy(Request::new(request))
            .await?
            .into_inner())
    }

    pub(crate) async fn check_policy_secrets(
        &self,
        request: w::CheckPolicySecretsRequest,
    ) -> Result<w::PolicySecretsResult, Status> {
        Ok(self
            .0
            .check_policy_secrets(Request::new(request))
            .await?
            .into_inner())
    }

    pub(crate) async fn read_logs(
        &self,
        request: w::ReadLogsRequest,
    ) -> Result<Stream<w::LogChunk>, Status> {
        Ok(self.0.read_logs(Request::new(request)).await?.into_inner())
    }

    pub(crate) async fn runtime(&self) -> Result<libvm::Runtime, Status> {
        if let Some(runtime) = self.0 .0.runtime.get() {
            return Ok(runtime.clone());
        }
        Box::pin(self.0.runtime()).await
    }
}

fn machine_ref(reference: &str) -> w::MachineRef {
    let reference = match uuid::Uuid::parse_str(reference) {
        Ok(id) => w::machine_ref::Reference::Id(id.to_string()),
        Err(_) => w::machine_ref::Reference::Name(reference.to_owned()),
    };
    w::MachineRef {
        reference: Some(reference),
    }
}

fn invalid_response() -> Status {
    Status::internal("invalid or incomplete daemon response")
}

fn unavailable() -> Failure {
    Failure::new(
        Code::Unavailable,
        "runtime operation unavailable; inspect VM state",
    )
}

/// Only typed safe messages may cross the lobby boundary, never transport diagnostics.
pub(crate) fn categorize(status: &Status) -> Failure {
    if status.code() == tonic::Code::Cancelled {
        return Failure::new(Code::Cancelled, "operation cancelled");
    }
    match silo_vm_control::errors::status_error_detail(status) {
        Ok(Some(detail)) => categorize_detail(&detail),
        Err(_) => unavailable(),
        Ok(None) => match status.code() {
            tonic::Code::InvalidArgument | tonic::Code::OutOfRange => {
                Failure::new(Code::Usage, "invalid request")
            }
            tonic::Code::NotFound => Failure::new(Code::NotFound, "requested resource not found"),
            tonic::Code::AlreadyExists | tonic::Code::FailedPrecondition | tonic::Code::Aborted => {
                Failure::new(
                    Code::Conflict,
                    "management request conflicts with current state",
                )
            }
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
                Failure::new(Code::Forbidden, "management request denied")
            }
            tonic::Code::ResourceExhausted => {
                Failure::new(Code::Limit, "management request exceeds a limit")
            }
            _ => unavailable(),
        },
    }
}

fn categorize_detail(detail: &w::ErrorDetail) -> Failure {
    let Ok(kind) = w::ErrorKind::try_from(detail.kind) else {
        return unavailable();
    };
    let Ok(code) = w::ErrorCode::try_from(detail.code) else {
        return unavailable();
    };
    if kind == w::ErrorKind::Unspecified || code == w::ErrorCode::Unspecified {
        return unavailable();
    }
    if code == w::ErrorCode::LiveOperationUnsupported {
        return unavailable();
    }
    if detail.live_unsupported.is_some()
        || detail.native_variant.as_deref() == Some("LiveOperationUnsupported")
    {
        return unavailable();
    }
    let variant = match code {
        w::ErrorCode::AlreadyRunning => "MachineAlreadyRunning",
        w::ErrorCode::NotRunning => "MachineNotRunning",
        w::ErrorCode::StaleGeneration => "MachineStaleGeneration",
        w::ErrorCode::MonitorConnection => "MonitorConnection",
        w::ErrorCode::EntrypointLaunchFailed | w::ErrorCode::CommandNotFound => {
            "EntrypointLaunchFailed"
        }
        _ => detail.native_variant.as_deref().unwrap_or_default(),
    };
    match variant {
        "MachineNotFound" => Failure::new(Code::NotFound, "VM not found"),
        "MachineAlreadyExists" => Failure::new(
            Code::Conflict,
            "name already taken locally or on the tailnet",
        ),
        "MachineAlreadyRunning"
        | "MachineNotRunning"
        | "MachineStaleGeneration"
        | "InvalidMachineUpdate" => {
            Failure::new(Code::Conflict, "VM state does not permit this operation")
        }
        "InvalidArgument" | "InvalidCreateRequest" | "InvalidMachineName" => {
            Failure::new(Code::Usage, "invalid request")
        }
        "ImageReferenceRejected" => Failure::new(
            Code::Usage,
            if detail.safe_message.is_empty() {
                "daemon management operation failed"
            } else {
                &detail.safe_message
            },
        ),
        "Image" | "ImageNotFound" => {
            Failure::new(Code::Image, "image pull or materialization failed")
        }
        "MachinePreparationFailed"
        | "MachineStartCleanupFailed"
        | "EntrypointLaunchFailed"
        | "RootDisk"
        | "GuestSession"
        | "NetworkRuntime" => Failure::new(
            Code::OperationFailed,
            "VM operation failed; inspect VM state",
        ),
        "" => match kind {
            w::ErrorKind::Invalid => Failure::new(Code::Usage, "invalid request"),
            w::ErrorKind::Duplicate => Failure::new(
                Code::Conflict,
                "name already taken locally or on the tailnet",
            ),
            w::ErrorKind::Conflict => Failure::new(Code::Conflict, &detail.safe_message),
            w::ErrorKind::Denied => Failure::new(Code::Forbidden, &detail.safe_message),
            w::ErrorKind::Limit => Failure::new(Code::Limit, &detail.safe_message),
            _ => unavailable(),
        },
        _ => unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{FeatureSelection, GlobalConfig};
    use crate::daemon::control::lobby::{categorize, categorize_detail, machine_ref, Management};
    use crate::daemon::control::ControlState;
    use crate::lobby::failure::Code;
    use libvm::HostPaths;
    use silod_spec::daemon::v1 as w;
    use std::sync::Arc;
    use tonic::Status;

    fn state(root: &std::path::Path) -> Arc<ControlState> {
        let host = HostPaths::new(root.join("home"), root.join("config"));
        let global = GlobalConfig::default();
        let generation = uuid::Uuid::new_v4();
        let publisher = Arc::new(
            crate::daemon::status::StatusPublisher::new(
                &host,
                generation,
                global
                    .daemon_identity(FeatureSelection {
                        system: false,
                        tailscale: false,
                    })
                    .unwrap(),
                None,
            )
            .unwrap(),
        );
        Arc::new(ControlState::new(host, global, generation, publisher))
    }

    #[test]
    fn guest_runtime_access_keeps_native_initialization_off_the_caller_stack() {
        let root = tempfile::tempdir().unwrap();
        let management = Management::new(state(root.path()));
        assert!(std::mem::size_of_val(&management.runtime()) < 1024);
    }

    impl Management {
        pub(crate) fn for_test_runtime(
            root: &std::path::Path,
            config: libvm::RuntimeConfig,
            runtime: libvm::Runtime,
            components: libvm::ResolvedRuntimeComponents,
        ) -> Self {
            let mut state = state(root);
            let owner = Arc::get_mut(&mut state).unwrap();
            assert_eq!(runtime.local_home(), owner.host.home());
            owner.config = config;
            assert!(owner.components.set(components).is_ok());
            assert!(owner.runtime.set(runtime).is_ok());
            Self::new(state)
        }
    }

    #[tokio::test]
    async fn pure_management_operations_use_real_daemon_services_without_runtime() {
        let root = tempfile::tempdir().unwrap();
        let state = state(root.path());
        let management = Management::new(state.clone());
        let name = management.propose_machine_name().await.unwrap();
        assert!(!name.is_empty());
        assert!(name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
        for text in ["4GiB", " 4GB ", "4gb", "4g"] {
            assert_eq!(
                management
                    .parse_resource(w::ResourceKind::Memory, text)
                    .await
                    .unwrap()
                    .bytes,
                4 << 30
            );
        }
        assert_eq!(
            management
                .parse_resource(w::ResourceKind::RootDisk, "8GiB")
                .await
                .unwrap()
                .bytes,
            8 << 30
        );
        for text in ["", "not-a-size", "0", "-1GiB"] {
            let error = management
                .parse_resource(w::ResourceKind::Memory, text)
                .await
                .unwrap_err();
            assert_eq!(categorize(&error).code, Code::Usage, "{text}");
        }
        let policy = management
            .normalize_policy(w::NormalizePolicyRequest {
                input: Some(w::normalize_policy_request::Input::Empty(())),
            })
            .await
            .unwrap();
        assert!(!policy.canonical_json.is_empty());
        assert!(!policy.hcl.is_empty());
        let reparsed = management
            .normalize_policy(w::NormalizePolicyRequest {
                input: Some(w::normalize_policy_request::Input::CanonicalJson(
                    policy.canonical_json.clone(),
                )),
            })
            .await
            .unwrap();
        assert_eq!(reparsed.canonical_json, policy.canonical_json);
        let error = management
            .normalize_policy(w::NormalizePolicyRequest {
                input: Some(w::normalize_policy_request::Input::CanonicalJson(
                    "{".into(),
                )),
            })
            .await
            .unwrap_err();
        assert_eq!(categorize(&error).code, Code::Usage);
        assert!(state.runtime.get().is_none());
        assert!(state.components.get().is_none());
    }

    #[tokio::test]
    async fn inventory_and_missing_inspection_share_the_daemon_runtime() {
        let root = tempfile::tempdir().unwrap();
        let binary = test_utils::mock_vmm_binary().to_path_buf();
        let kernel = root.path().join("kernel");
        let initramfs = root.path().join("initramfs");
        std::fs::write(&kernel, b"unused inventory kernel").unwrap();
        std::fs::write(&initramfs, b"unused inventory initramfs").unwrap();
        let components = libvm::ResolvedRuntimeComponents::from_paths(
            binary.clone(),
            binary.clone(),
            kernel,
            initramfs,
            binary,
            root.path().to_path_buf(),
        )
        .unwrap();
        let mut state = state(root.path());
        let owner = Arc::get_mut(&mut state).unwrap();
        owner.config = libvm::RuntimeConfig::local(root.path().join("home"))
            .with_run_root(root.path().join("run"))
            .with_runtime_components(components.clone())
            .with_virt_backend(libvm::VirtBackendOverride::Mock { scenario: None });
        assert!(owner.components.set(components).is_ok());
        let management = Management::new(state.clone());
        assert!(management.inventory().await.unwrap().is_empty());
        let runtime = management.runtime().await.unwrap();
        assert_eq!(runtime.local_home(), root.path().join("home"));
        assert!(state.runtime.get().is_some());
        assert!(root.path().join("home/state.db").is_file());
        for reference in [
            "missing-exact-name".to_owned(),
            uuid::Uuid::new_v4().to_string(),
        ] {
            let error = management.inspect(&reference).await.unwrap_err();
            let failure = categorize(&error);
            assert_eq!(failure.code, Code::NotFound);
            assert_eq!(failure.exit, 3);
            assert_eq!(failure.message, "VM not found");
        }
        let policy = management
            .normalize_policy(w::NormalizePolicyRequest {
                input: Some(w::normalize_policy_request::Input::Empty(())),
            })
            .await
            .unwrap();
        let secrets = management
            .check_policy_secrets(w::CheckPolicySecretsRequest {
                policy_json: policy.canonical_json,
                machine_id: None,
            })
            .await
            .unwrap();
        assert_eq!(secrets.state, w::PolicySecretsState::Ready as i32);
        assert!(management.clone().inventory().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn early_validation_and_daemon_admission_are_preserved() {
        let root = tempfile::tempdir().unwrap();
        let state = state(root.path());
        let management = Management::new(state.clone());
        state.begin_stopping().await.unwrap();
        let error = management
            .resolve_image("", w::PullPolicy::Never, |_| {})
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let error = management.pull_image("").await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let error = management
            .resolve_image("example/image", w::PullPolicy::Never, |_| {})
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        let error = management.pull_image("example/image").await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        let id = uuid::Uuid::new_v4().to_string();
        let error = management
            .stop(
                &id,
                None,
                false,
                Some(prost_types::Duration {
                    seconds: -1,
                    nanos: 0,
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let error = management
            .set_secret("not-a-uuid", "secret", Vec::new())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let error = management
            .wait_ready(
                "not-a-uuid",
                &id,
                prost_types::Duration {
                    seconds: 1,
                    nanos: 0,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(state.runtime.get().is_none());
        assert!(state.components.get().is_none());
        assert_eq!(state.capacity.available_permits(), 64);
    }

    #[test]
    fn references_preserve_exact_names_and_canonicalize_full_ids() {
        let id = uuid::Uuid::new_v4();
        assert_eq!(
            machine_ref(&id.simple().to_string()).reference,
            Some(w::machine_ref::Reference::Id(id.to_string()))
        );
        for name in ["devbox", "ab12", ""] {
            assert_eq!(
                machine_ref(name).reference,
                Some(w::machine_ref::Reference::Name(name.into()))
            );
        }
    }

    #[test]
    fn rich_native_categories_match_go_table_without_exposing_diagnostics() {
        for (variant, expected) in [
            ("LiveDiscovery", Code::Unavailable),
            ("LiveProtocol", Code::Unavailable),
            ("LiveObservation", Code::Unavailable),
            ("MachineNotFound", Code::NotFound),
            ("MachineAlreadyExists", Code::Conflict),
            ("MachineAlreadyRunning", Code::Conflict),
            ("MachineNotRunning", Code::Conflict),
            ("MachineStaleGeneration", Code::Conflict),
            ("InvalidMachineUpdate", Code::Conflict),
            ("InvalidArgument", Code::Usage),
            ("InvalidCreateRequest", Code::Usage),
            ("InvalidMachineName", Code::Usage),
            ("Image", Code::Image),
            ("ImageNotFound", Code::Image),
            ("MachinePreparationFailed", Code::OperationFailed),
            ("MachineStartCleanupFailed", Code::OperationFailed),
            ("EntrypointLaunchFailed", Code::OperationFailed),
            ("RootDisk", Code::OperationFailed),
            ("GuestSession", Code::OperationFailed),
            ("NetworkRuntime", Code::OperationFailed),
        ] {
            let detail = w::ErrorDetail {
                kind: w::ErrorKind::Invalid as i32,
                code: w::ErrorCode::Native as i32,
                native_variant: Some(variant.into()),
                safe_message: "unsafe native diagnostic".into(),
                ..Default::default()
            };
            let failure = categorize_detail(&detail);
            assert_eq!(failure.code, expected, "{variant}");
            assert!(!failure.message.contains("unsafe"));
        }
    }

    #[test]
    fn native_rich_statuses_decode_and_preserve_only_safe_image_rejection() {
        let message = "image denied by registry policy rule";
        let rejected = silo_vm_control::errors::native_error_to_status(
            &libvm::LibVmError::ImageReferenceRejected {
                reference: "example/image".into(),
                message: message.into(),
            },
        );
        let failure = categorize(&rejected);
        assert_eq!(failure.code, Code::Usage);
        assert_eq!(failure.message, message);
        let missing =
            silo_vm_control::errors::native_error_to_status(&libvm::LibVmError::MachineNotFound {
                reference: "/home/private".into(),
            });
        let failure = categorize(&missing);
        assert_eq!(failure.code, Code::NotFound);
        assert_eq!(failure.exit, 3);
        assert_eq!(failure.message, "VM not found");
    }

    #[test]
    fn unstructured_statuses_never_expose_transport_diagnostics() {
        for (status, code) in [
            (
                Status::invalid_argument("secret /home/private"),
                Code::Usage,
            ),
            (Status::out_of_range("secret /home/private"), Code::Usage),
            (Status::not_found("secret /home/private"), Code::NotFound),
            (
                Status::already_exists("secret /home/private"),
                Code::Conflict,
            ),
            (
                Status::failed_precondition("secret /home/private"),
                Code::Conflict,
            ),
            (Status::aborted("secret /home/private"), Code::Conflict),
            (
                Status::permission_denied("secret /home/private"),
                Code::Forbidden,
            ),
            (
                Status::unauthenticated("secret /home/private"),
                Code::Forbidden,
            ),
            (
                Status::resource_exhausted("secret /home/private"),
                Code::Limit,
            ),
            (Status::unknown("secret /home/private"), Code::Unavailable),
            (
                Status::deadline_exceeded("secret /home/private"),
                Code::Unavailable,
            ),
            (Status::cancelled("secret /home/private"), Code::Cancelled),
        ] {
            let failure = categorize(&status);
            assert_eq!(failure.code, code);
            assert!(!failure.message.contains("secret"));
            assert!(!failure.message.contains("private"));
        }
        let malformed =
            Status::with_details(tonic::Code::InvalidArgument, "secret", vec![255].into());
        assert_eq!(categorize(&malformed).code, Code::Unavailable);
    }

    #[test]
    fn rich_codes_override_native_variant_and_invalid_details_fail_closed() {
        for (code, category) in [
            (w::ErrorCode::AlreadyRunning, Code::Conflict),
            (w::ErrorCode::NotRunning, Code::Conflict),
            (w::ErrorCode::StaleGeneration, Code::Conflict),
            (w::ErrorCode::MonitorConnection, Code::Unavailable),
            (w::ErrorCode::EntrypointLaunchFailed, Code::OperationFailed),
            (w::ErrorCode::CommandNotFound, Code::OperationFailed),
        ] {
            let detail = w::ErrorDetail {
                kind: w::ErrorKind::Unavailable as i32,
                code: code as i32,
                native_variant: Some("MachineNotFound".into()),
                ..Default::default()
            };
            assert_eq!(categorize_detail(&detail).code, category);
        }
        for (kind, code) in [(99, 99), (0, 7), (1, 0)] {
            let detail = w::ErrorDetail {
                kind,
                code,
                safe_message: "secret".into(),
                ..Default::default()
            };
            let failure = categorize_detail(&detail);
            assert_eq!(failure.code, Code::Unavailable);
            assert!(!failure.message.contains("secret"));
        }
        for (kind, expected, message) in [
            (w::ErrorKind::Invalid, Code::Usage, "invalid request"),
            (
                w::ErrorKind::Duplicate,
                Code::Conflict,
                "name already taken locally or on the tailnet",
            ),
            (w::ErrorKind::Conflict, Code::Conflict, "safe failure"),
            (w::ErrorKind::Denied, Code::Forbidden, "safe failure"),
            (w::ErrorKind::Limit, Code::Limit, "safe failure"),
            (
                w::ErrorKind::Missing,
                Code::Unavailable,
                "runtime operation unavailable; inspect VM state",
            ),
            (
                w::ErrorKind::Unavailable,
                Code::Unavailable,
                "runtime operation unavailable; inspect VM state",
            ),
            (
                w::ErrorKind::Internal,
                Code::Unavailable,
                "runtime operation unavailable; inspect VM state",
            ),
        ] {
            let detail = w::ErrorDetail {
                kind: kind as i32,
                code: w::ErrorCode::Native as i32,
                safe_message: "safe failure".into(),
                ..Default::default()
            };
            let failure = categorize_detail(&detail);
            assert_eq!(failure.code, expected);
            assert_eq!(failure.message, message);
        }
    }
}
