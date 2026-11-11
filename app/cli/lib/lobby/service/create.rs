use crate::config::tailscale::EnrollmentMode;
use crate::daemon::control::lobby::categorize;
use crate::lobby::{
    caller::Caller,
    failure::{Code, Failure, Outcome},
    identity::{canonical_dns, Action, Peer, Principal},
    jobs::{Completion, Operation},
    service::{
        disk::Reservation,
        documents::{self, DocumentKind, GUEST_PORTS_LABEL, POLICY_LABEL, TEMPLATE_LABEL},
        vm, Service,
    },
};
use silo_secrets as secrets;
use silod_spec::daemon::v1 as w;
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct CreateRequest {
    pub(crate) tags: Vec<String>,
    pub(crate) guest_user: Option<w::User>,
    pub(crate) template: String,
    pub(crate) policy_ref: String,
    pub(crate) guest_ports: Vec<u16>,
    pub(crate) userdata_set: bool,
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) cpus: u64,
    pub(crate) memory: u64,
    pub(crate) disk: u64,
    pub(crate) memory_text: String,
    pub(crate) disk_text: String,
    pub(crate) userdata: String,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) owner: Option<Principal>,
    pub(crate) tailscale: bool,
    pub(crate) no_start: bool,
    pub(crate) policy: Option<w::PolicyDocument>,
}

impl Service {
    pub(crate) async fn parse_resource(&self, kind: &str, text: &str) -> Outcome<u64> {
        let resource = match kind {
            "memory" => w::ResourceKind::Memory,
            "disk" | "disk-size" => w::ResourceKind::RootDisk,
            _ => return Err(Failure::new(Code::Usage, "unknown resource kind")),
        };
        self.management().parse_resource(resource, text).await.map(|size| size.bytes).map_err(|status| {
            let error = categorize(&status);
            if error.code == Code::Usage { Failure::new(Code::Usage, format!("invalid value for --{kind}: expected a positive binary size (e.g. 4GiB or 8gb)")) } else { error }
        })
    }
    pub(crate) async fn validate_create(
        &self,
        peer: &Peer,
        mut request: CreateRequest,
    ) -> Outcome<CreateRequest> {
        self.authorize(peer, Action::Create, None)?;
        if request.tailscale
            && (!self.config.vm_nodes_enabled
                || self.config.node_pin.is_none()
                || self.config.settings.enrollment_mode() == EnrollmentMode::None)
        {
            return Err(Failure::new(
                Code::Usage,
                "Tailscale enrollment is disabled or unavailable",
            ));
        }
        if !request.tags.is_empty() && !request.tailscale {
            return Err(Failure::new(Code::Usage, "--tag requires --tailscale"));
        }
        if request.tags.len() > 32 {
            return Err(Failure::new(
                Code::Usage,
                "at most 32 tags may be requested",
            ));
        }
        for tag in &mut request.tags {
            let principal = Principal::parse(&tag.to_lowercase())
                .map_err(|_| Failure::new(Code::Usage, "invalid Tailscale tag"))?;
            if !principal.is_tag() {
                return Err(Failure::new(Code::Usage, "invalid Tailscale tag"));
            }
            *tag = principal.to_string();
        }
        request.tags.sort_unstable();
        request.tags.dedup();
        if !request.name.is_empty() && !documents::valid_document_name(&request.name) {
            return Err(Failure::new(Code::Usage, "invalid VM name"));
        }
        if let Some(user) = &request.guest_user {
            libvm::MachineUserConfig::new(&user.name, user.uid, user.gid, &user.home)
                .validate()
                .map_err(|message| Failure::new(Code::Usage, message))?;
        }
        let owner = documents::selected_owner(peer, request.owner.as_ref())?;
        if request.tailscale && owner.is_tag() && request.tags.is_empty() {
            request.tags.push(owner.to_string());
        }
        request.owner = Some(owner);
        if request.image.is_empty() {
            return Err(Failure::new(
                Code::Usage,
                "image required (IMAGE, --image, or a template image)",
            ));
        }
        if !documents::valid_userdata(&request.userdata) {
            return Err(Failure::new(
                Code::Usage,
                "userdata must be a shebang script of at most 16KiB",
            ));
        }
        documents::validate_labels(&request.labels)?;
        let (cpus, memory, disk) = self.config.settings.vm_defaults();
        if request.cpus == 0 {
            request.cpus = cpus;
        }
        if !request.memory_text.is_empty() {
            request.memory = self.parse_resource("memory", &request.memory_text).await?;
            request.memory_text.clear();
        }
        if !request.disk_text.is_empty() {
            request.disk = self.parse_resource("disk", &request.disk_text).await?;
            request.disk_text.clear();
        }
        if request.memory == 0 {
            request.memory = memory;
        }
        if request.disk == 0 {
            request.disk = disk;
        }
        self.resources(peer, request.cpus, request.memory, request.disk)?;
        Ok(request)
    }
    pub(crate) fn resources(&self, peer: &Peer, cpus: u64, memory: u64, disk: u64) -> Outcome<()> {
        let (_, max_cpus, max_memory, max_disk) = self.config.settings.vm_ceilings();
        let limits = peer.permissions.limits;
        if cpus == 0
            || cpus > 255
            || cpus > max_cpus.min(limits.cpus)
            || memory == 0
            || memory > max_memory.min(limits.memory)
            || disk == 0
            || disk > max_disk.min(limits.disk)
        {
            Err(Failure::new(Code::Limit, "resource ceiling exceeded"))
        } else {
            Ok(())
        }
    }
    async fn resolve_create(
        &self,
        peer: &Peer,
        mut request: CreateRequest,
    ) -> Outcome<CreateRequest> {
        let owner = documents::selected_owner(peer, request.owner.as_ref())?;
        if !request.template.is_empty() {
            let document = self
                .store
                .read(DocumentKind::Template, &owner, &request.template, self)
                .await?;
            let template = document
                .template
                .ok_or_else(|| Failure::new(Code::Unavailable, "template unavailable"))?;
            if request.image.is_empty() {
                request.image = template.image.unwrap_or_default();
            }
            if let Some(resources) = template.resources {
                if request.cpus == 0 {
                    request.cpus = resources.cpus.unwrap_or_default();
                }
                if request.memory == 0 && request.memory_text.is_empty() {
                    request.memory_text = resources.memory.unwrap_or_default();
                }
            }
            if request.disk == 0 && request.disk_text.is_empty() {
                request.disk_text = template.disk_size.unwrap_or_default();
            }
            if !request.userdata_set && request.userdata.is_empty() {
                request.userdata = template.userdata.unwrap_or_default();
            }
            let mut labels = template.labels;
            labels.extend(request.labels);
            request.labels = labels;
            if let Some(network) = template.network {
                if request.policy_ref.is_empty() {
                    request.policy_ref = network.policy_ref.unwrap_or_default();
                }
                request.guest_ports = network.publish;
            }
        }
        if request.image.is_empty() {
            return Err(Failure::new(
                Code::Usage,
                "image required (IMAGE, --image, or a template image)",
            ));
        }
        if !request.policy_ref.is_empty() {
            let document = self
                .store
                .read(DocumentKind::Policy, &owner, &request.policy_ref, self)
                .await?;
            request.policy = Some(self.parse_policy(&document.content).await?);
        }
        if let Some(policy) = &request.policy {
            if has_forwards(policy)? && !request.tailscale {
                return Err(Failure::new(
                    Code::Usage,
                    "policy forwards require --tailscale",
                ));
            }
            self.check_secrets(policy).await?;
        }
        Ok(request)
    }
    pub(crate) async fn visible_names(&self) -> Outcome<Vec<String>> {
        (self.config.visible_names)()
            .await
            .map_err(|_| Failure::new(Code::Unavailable, "tailnet name inventory unavailable"))
    }
    async fn admit_create(
        &self,
        peer: &Peer,
        owner: &Principal,
        disk: u64,
        reserved: bool,
    ) -> Outcome<()> {
        self.disk_admission(disk)?;
        let entries = self
            .management()
            .inventory()
            .await
            .map_err(|status| categorize(&status))?;
        let mut durable = HashSet::new();
        let mut count = 0u64;
        for entry in entries {
            let machine = entry
                .data
                .ok_or_else(|| Failure::new(Code::Unavailable, "VM quota inventory unreadable"))?;
            if vm::label(&machine, vm::INSTANCE_LABEL) == self.config.instance
                && vm::label(&machine, vm::OWNER_LABEL) == owner.as_str()
            {
                count += 1;
                durable.insert(machine.name);
            }
        }
        for (name, principal) in &self.admission.lock().names {
            if principal == owner && !durable.contains(name) {
                count += 1;
            }
        }
        let limit = self
            .config
            .settings
            .vm_ceilings()
            .0
            .min(peer.permissions.limits.vms);
        if count > limit || (!reserved && count == limit) {
            Err(Failure::new(Code::Limit, "VM count ceiling exceeded"))
        } else {
            Ok(())
        }
    }
    async fn reserve_create(
        &self,
        peer: &Peer,
        request: &mut CreateRequest,
    ) -> Outcome<Reservation> {
        let owner = request
            .owner
            .as_ref()
            .ok_or_else(|| Failure::new(Code::Forbidden, "owner required"))?;
        let _guard = self.create_lock.lock().await;
        self.admit_create(peer, owner, request.disk, false).await?;
        let names = self.visible_names().await?;
        let generated = request.name.is_empty();
        for _ in 0..3 {
            if generated {
                request.name = self
                    .management()
                    .propose_machine_name()
                    .await
                    .map_err(|status| categorize(&status))?;
            }
            if self.name_available(&request.name, &names).await? {
                let mut admission = self.admission.lock();
                admission.names.insert(request.name.clone(), owner.clone());
                admission.disks.insert(request.name.clone(), request.disk);
                return Ok(Reservation::new(self, request.name.clone()));
            }
            if !generated {
                return Err(Failure::new(
                    Code::Conflict,
                    "exact VM name is already taken",
                ));
            }
        }
        Err(Failure::new(
            Code::Conflict,
            "could not reserve a generated name after 3 attempts",
        ))
    }
    pub(crate) async fn name_available(&self, name: &str, visible: &[String]) -> Outcome<bool> {
        if self.admission.lock().names.contains_key(name)
            || visible
                .iter()
                .any(|visible| canonical_dns(visible).split('.').next() == Some(name))
        {
            return Ok(false);
        }
        Ok(!self
            .management()
            .inventory()
            .await
            .map_err(|status| categorize(&status))?
            .iter()
            .any(|entry| entry.name == name))
    }
    async fn revalidate_create(&self, caller: &Caller, request: &CreateRequest) -> Outcome<Peer> {
        let peer = caller.fresh().await?;
        self.authorize(&peer, Action::Create, None)?;
        self.resources(&peer, request.cpus, request.memory, request.disk)?;
        let selected = documents::selected_owner(
            &peer,
            request.owner.as_ref().filter(|owner| owner.is_tag()),
        )?;
        if request.owner.as_ref() != Some(&selected) {
            return Err(Failure::new(Code::Forbidden, "owner identity changed"));
        }
        Ok(peer)
    }
    pub(crate) async fn create(
        &self,
        caller: &Caller,
        request: CreateRequest,
    ) -> Outcome<Operation> {
        self.authorize(&caller.peer, Action::Create, None)?;
        let request = self.resolve_create(&caller.peer, request).await?;
        let mut request = self.validate_create(&caller.peer, request).await?;
        let reservation = Arc::new(self.reserve_create(&caller.peer, &mut request).await?);
        let owner = request
            .owner
            .clone()
            .ok_or_else(|| Failure::new(Code::Forbidden, "owner required"))?;
        if request.tailscale {
            request.policy = Some(
                self.inject_node(
                    request.policy.as_ref(),
                    &request.name,
                    &owner,
                    &request.tags,
                    self.enrollment_mode(&owner),
                )
                .await?,
            );
        }
        let service = self.clone();
        let caller = caller.clone();
        let held = reservation.clone();
        let attempt = uuid::Uuid::new_v4().to_string();
        self.jobs().submit_result("create", request.name.clone(), owner.clone(), move |cancel, progress| async move {
            tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Failure::new(Code::Cancelled, "operation cancelled")),
                result = async {
                    service.revalidate_create(&caller, &request).await?;
                    let key = if request.tailscale && !owner.is_tag() && service.config.settings.enrollment_mode() != EnrollmentMode::Interactive {
                        match &service.config.consent { Some(consent) => consent.acquire(&attempt, &owner, progress.clone()).await?.map(secrets::SecretBytes::new), None => None }
                    } else { None };
                    service.revalidate_create(&caller, &request).await?;
                    if let Some(policy) = &request.policy { service.check_secrets(policy).await?; }
                    progress(format!("creating {}", request.name)); progress(format!("pulling {}", request.image));
                    service.management().pull_image(&request.image).await.map_err(|status| categorize(&status))?;
                    progress("image pull complete".into());
                    service.revalidate_create(&caller, &request).await?;
                    let image_progress = progress.clone();
                    let resolved = service.management().resolve_image(&request.image, w::PullPolicy::IfMissing, move |event| {
                        if let Some(event) = image_progress_line(event) { image_progress(event); }
                    }).await.map_err(|status| categorize(&status))?;
                    let peer = service.revalidate_create(&caller, &request).await?;
                    if let Some(policy) = &request.policy { service.check_secrets(policy).await?; }
                    let mut labels = request.labels.clone();
                    labels.insert(vm::OWNER_LABEL.into(), owner.to_string()); labels.insert(vm::LOGIN_LABEL.into(), peer.login.clone()); labels.insert(vm::NAME_LABEL.into(), request.name.clone()); labels.insert(vm::INSTANCE_LABEL.into(), service.config.instance.clone());
                    labels.insert(vm::MODE_LABEL.into(), if request.tailscale { service.enrollment_mode(&owner) } else { "none" }.into());
                    if request.tailscale { labels.insert(vm::TAGS_LABEL.into(), serde_json::to_string(&request.tags).map_err(|_| Failure::new(Code::Usage, "invalid tags"))?); }
                    if !request.template.is_empty() { labels.insert(TEMPLATE_LABEL.into(), request.template.clone()); }
                    if !request.policy_ref.is_empty() { labels.insert(POLICY_LABEL.into(), request.policy_ref.clone()); }
                    if !request.guest_ports.is_empty() { labels.insert(GUEST_PORTS_LABEL.into(), serde_json::to_string(&request.guest_ports).map_err(|_| Failure::new(Code::Usage, "invalid guest ports"))?); }
                    let spec = w::NormalizedMachineCreate { name: Some(request.name.clone()), labels, cpus: Some(request.cpus as u32), memory_bytes: Some(request.memory), root_disk_size_bytes: Some(request.disk), vsock: Some(true), process: Some(w::ProcessConfig::default()), retention: w::Retention::Persistent as i32,
                        agent: Some(w::Agent { mode: Some(w::agent::Mode::DefaultAgent(())) }), temporary_directory: Some(w::TemporaryDirectoryPolicy { backing: Some(w::temporary_directory_policy::Backing::DiskBacked(())) }), provision_user: request.guest_user.clone(), userdata: if request.userdata.is_empty() { None } else { Some(request.userdata.clone()) },
                        network: request.policy.as_ref().map(|policy| w::ResolvedNetwork { attachment: Some(w::resolved_network::Attachment::Private(w::PrivateNetwork { policy_json: Some(policy.canonical_json.clone()), publish: None })) }), ..Default::default() };
                    let source = resolved.identity.ok_or_else(|| Failure::new(Code::Unavailable, "image identity unavailable"))?;
                    let machine = {
                        let _guard = service.create_lock.lock().await;
                        service.admit_create(&peer, &owner, 0, true).await?;
                        service.management().create(spec, source).await.map_err(|status| categorize(&status))?
                    };
                    if request.tailscale { service.store_node_credentials(&caller, Action::Create, &machine, key.as_ref().map(secrets::SecretBytes::as_bytes)).await?; }
                    held.release(); progress(format!("VM created: {}", request.name));
                    let mut completion = Completion { vm_id: machine.id.clone(), name: request.name.clone(), image: request.image.clone(), user: request.guest_user.as_ref().map_or_else(|| "root".into(), |user| user.name.clone()), node_state: if request.tailscale && request.no_start { "enrollment starts on boot" } else { "none" }.into(), ..Default::default() };
                    if !request.no_start {
                        service.jobs().with_vm(&cancel, &machine.id, || async {
                            let machine = service.management().inspect(&machine.id).await.map_err(|status| categorize(&status))?;
                            service.prepare_node(&caller, Action::Create, &machine).await?;
                            service.reauthorize(&caller, Action::Create, &machine).await?;
                            progress("starting VM".into());
                            let start = service.management().start(&machine.id).await.map_err(|status| categorize(&status))?;
                            progress(format!("preparing {}", request.name)); service.wait_ready(&machine.id, &start.run_id).await?;
                            progress("guest ready".into()); completion.running = true; service.complete_node(&machine.id, &mut completion, &progress).await; Ok(())
                        }).await?;
                    }
                    Ok(Some(completion))
                } => result,
            }
        }, move || reservation.release())
    }
}
pub(crate) fn has_forwards(policy: &w::PolicyDocument) -> Outcome<bool> {
    let root: serde_json::Value = serde_json::from_str(&policy.canonical_json)
        .map_err(|_| Failure::new(Code::Usage, "invalid normalized policy"))?;
    Ok(root
        .get("forwards")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|forwards| !forwards.is_empty()))
}
fn image_progress_line(progress: w::ImageProgress) -> Option<String> {
    use w::image_progress::Event;
    match progress.event? {
        Event::ResolvedManifest(manifest) => {
            Some(format!("resolved image: {} layers", manifest.layer_count))
        }
        Event::CacheHit(_) => Some("using cached image".into()),
        Event::ApplyingLayer(layer) => {
            Some(format!("applying layer {}/{}", layer.index, layer.total))
        }
        Event::LayerDownloadFinished(layer) => {
            Some(format!("downloaded layer {}/{}", layer.index, layer.total))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::{
        identity::Action,
        service::{create::CreateRequest, testing, vm},
    };
    #[tokio::test]
    async fn validation_and_operator_intersection_tables() {
        let fixture = testing::fixture().await;
        let service = &fixture.service;
        let caller = testing::caller("user:1", &[Action::Create]);
        let base = CreateRequest {
            image: "fixture:latest".into(),
            name: "safe".into(),
            ..Default::default()
        };
        let cases = [
            (
                CreateRequest {
                    owner: Some("tag:foreign".parse().unwrap()),
                    ..base.clone()
                },
                4,
            ),
            (
                CreateRequest {
                    owner: Some("user:1".parse().unwrap()),
                    ..base.clone()
                },
                4,
            ),
            (
                CreateRequest {
                    labels: [(vm::OWNER_LABEL.into(), "user:2".into())].into(),
                    ..base.clone()
                },
                2,
            ),
            (
                CreateRequest {
                    labels: [("x".into(), "bad\n".into())].into(),
                    ..base.clone()
                },
                2,
            ),
            (
                CreateRequest {
                    userdata: "x".repeat(16385),
                    ..base.clone()
                },
                2,
            ),
            (
                CreateRequest {
                    cpus: 9,
                    ..base.clone()
                },
                6,
            ),
            (
                CreateRequest {
                    disk: 201 << 30,
                    ..base.clone()
                },
                6,
            ),
            (
                CreateRequest {
                    tags: vec!["tag:dev".into()],
                    ..base.clone()
                },
                2,
            ),
            (
                CreateRequest {
                    name: "Bad".into(),
                    ..base.clone()
                },
                2,
            ),
        ];
        for (request, exit) in cases {
            assert_eq!(
                service
                    .validate_create(&caller.peer, request)
                    .await
                    .unwrap_err()
                    .exit,
                exit
            );
        }
        let mut peer = caller.peer.clone();
        peer.permissions.limits.cpus = 1;
        assert_eq!(
            service
                .validate_create(
                    &peer,
                    CreateRequest {
                        cpus: 2,
                        ..base.clone()
                    }
                )
                .await
                .unwrap_err()
                .exit,
            6
        );
        peer.principals = vec!["tag:ci".parse().unwrap(), "tag:team".parse().unwrap()];
        peer.permissions.limits.cpus = 8;
        assert_eq!(
            service
                .validate_create(&peer, base.clone())
                .await
                .unwrap_err()
                .exit,
            2
        );
        assert_eq!(
            service
                .validate_create(
                    &peer,
                    CreateRequest {
                        owner: Some("tag:team".parse().unwrap()),
                        ..base
                    }
                )
                .await
                .unwrap()
                .owner
                .unwrap()
                .as_str(),
            "tag:team"
        );
    }
    #[tokio::test]
    async fn reservations_names_quota_and_cleanup_use_real_inventory() {
        let mut fixture = testing::fixture().await;
        std::sync::Arc::get_mut(&mut fixture.service.config)
            .unwrap()
            .visible_names =
            std::sync::Arc::new(|| Box::pin(async { Ok(vec!["Visible.tail.test.".into()]) }));
        let service = &fixture.service;
        let caller = testing::caller("user:1", &[Action::Create]);
        let request = CreateRequest {
            image: "fixture:latest".into(),
            name: "reserved".into(),
            disk: 1 << 30,
            ..Default::default()
        };
        let mut first = service
            .validate_create(&caller.peer, request.clone())
            .await
            .unwrap();
        let held = service
            .reserve_create(&caller.peer, &mut first)
            .await
            .unwrap();
        let mut second = service
            .validate_create(&caller.peer, request)
            .await
            .unwrap();
        assert_eq!(
            service
                .reserve_create(&caller.peer, &mut second)
                .await
                .err()
                .unwrap()
                .exit,
            5
        );
        second.name = "visible".into();
        assert_eq!(
            service
                .reserve_create(&caller.peer, &mut second)
                .await
                .err()
                .unwrap()
                .exit,
            5
        );
        let mut limited = caller.peer.clone();
        limited.permissions.limits.vms = 1;
        second.name = "other".into();
        assert_eq!(
            service
                .reserve_create(&limited, &mut second)
                .await
                .err()
                .unwrap()
                .exit,
            6
        );
        drop(held);
        let held = service.reserve_create(&limited, &mut second).await.unwrap();
        drop(held);
        assert!(service.admission.lock().names.is_empty());
        assert!(service.admission.lock().disks.is_empty());
        testing::stopped_vm(&fixture, "durable", "user:1").await;
        second.name = "new".into();
        assert_eq!(
            service
                .reserve_create(&limited, &mut second)
                .await
                .err()
                .unwrap()
                .exit,
            6
        );
    }
    #[tokio::test]
    async fn submission_failure_releases_prepublication_admission() {
        let fixture = testing::fixture().await;
        fixture
            .service
            .jobs()
            .wait(&tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
        let caller = testing::caller("user:1", &[Action::Create]);
        let result = fixture
            .service
            .create(
                &caller,
                CreateRequest {
                    image: "fixture:latest".into(),
                    name: "release".into(),
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(result.unwrap_err().exit, 9);
        assert!(fixture.service.admission.lock().names.is_empty());
        assert!(fixture.service.admission.lock().disks.is_empty());
    }
    #[tokio::test]
    async fn native_resource_parsing_and_limit_boundaries() {
        let fixture = testing::fixture().await;
        for text in ["4GiB", " 4GB ", "4gb", "4g"] {
            assert_eq!(
                fixture
                    .service
                    .parse_resource("memory", text)
                    .await
                    .unwrap(),
                4 << 30
            );
        }
        for text in ["", "0", "-1GiB", "nonsense"] {
            assert_eq!(
                fixture
                    .service
                    .parse_resource("disk", text)
                    .await
                    .unwrap_err()
                    .exit,
                2
            );
        }
        let caller = testing::caller("user:1", &[Action::Create]);
        for (cpus, memory, disk, valid) in [
            (8, 32 << 30, 200 << 30, true),
            (0, 1, 1, false),
            (256, 1, 1, false),
            (1, 0, 1, false),
            (1, 1, 0, false),
            (1, (32 << 30) + 1, 1, false),
            (1, 1, (200 << 30) + 1, false),
        ] {
            assert_eq!(
                fixture
                    .service
                    .resources(&caller.peer, cpus, memory, disk)
                    .is_ok(),
                valid
            );
        }
    }
    #[tokio::test]
    async fn document_resolution_and_missing_secrets_precede_pull_and_admission() {
        let fixture = testing::fixture().await;
        let caller = testing::caller(
            "user:1",
            &[Action::Read, Action::Create, Action::TemplateManage],
        );
        fixture.service.documents(&caller, "template", "create", "base", None, "version: \"1\"\nimage: fixture:latest\nresources:\n  cpus: 3\n  memory: 2GiB\ndisk_size: 1GiB\nlabels:\n  tier: template\n").await.unwrap();
        let resolved = fixture
            .service
            .resolve_create(
                &caller.peer,
                CreateRequest {
                    template: "base".into(),
                    labels: [("tier".into(), "explicit".into())].into(),
                    cpus: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(resolved.image, "fixture:latest");
        assert_eq!(resolved.cpus, 1);
        assert_eq!(resolved.memory_text, "2GiB");
        assert_eq!(resolved.labels["tier"], "explicit");
        fixture.service.documents(&caller, "policy", "create", "needs-secret", None, "endpoint \"https\" \"api\" { hosts = [\"api.example.test\"] }\ncredential \"bearer_token\" \"personal\" { endpoint = https.api }\n").await.unwrap();
        let failure = fixture
            .service
            .create(
                &caller,
                CreateRequest {
                    image: "must-not-be-pulled".into(),
                    name: "missing-secret".into(),
                    policy_ref: "needs-secret".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(failure.exit, 2);
        assert!(failure.message.contains("missing policy secrets"));
        assert!(fixture.service.jobs().list(&caller.peer).is_empty());
        assert!(fixture.service.admission.lock().names.is_empty());
        assert!(fixture.management.inventory().await.unwrap().is_empty());
    }
}
