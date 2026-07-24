use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use std::process::Command;

use nix::unistd::{access, AccessFlags};

use crate::runtime::RuntimeConfig;
use crate::LibVmError;

const ENV_RUNTIME_DIR: &str = "SILO_RUNTIME_DIR";
const ENV_VMMON_PATH: &str = "SILO_VMMON_PATH";
const ENV_NETD_PATH: &str = "NETD_BIN";
const ENV_KRUN_PATH: &str = "KRUN_BIN";
const ENV_ASSET_DIR: &str = "SILO_ASSET_DIR";

const VMMON: Component = Component::executable("vmmon", "bin/vmmon");
const NETD: Component = Component::executable("netd", "bin/netd");
const KRUN: Component = Component::executable("krun", "bin/krun");
const KERNEL: Component = Component::readable("kernel", "assets/kernel-default");
const INITRAMFS: Component = Component::readable("initramfs", "assets/initramfs");
const AGENT: Component = Component::executable("agent", "assets/agent");
const COMPONENTS: [Component; 6] = [VMMON, NETD, KRUN, KERNEL, INITRAMFS, AGENT];

#[derive(Debug, Clone)]
pub(crate) struct ResolvedRuntimeComponents {
    vmmon: PathBuf,
    netd: PathBuf,
    krun: PathBuf,
    kernel: PathBuf,
    initramfs: PathBuf,
    agent: PathBuf,
}

impl ResolvedRuntimeComponents {
    pub(crate) fn resolve(config: &RuntimeConfig) -> Result<Self, LibVmError> {
        Resolver::new(config, DiscoveryInputs::from_process()).resolve()
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self {
            vmmon: PathBuf::from("/test/runtime/bin/vmmon"),
            netd: PathBuf::from("/test/runtime/bin/netd"),
            krun: PathBuf::from("/test/runtime/bin/krun"),
            kernel: PathBuf::from("/test/runtime/assets/kernel-default"),
            initramfs: PathBuf::from("/test/runtime/assets/initramfs"),
            agent: PathBuf::from("/test/runtime/assets/agent"),
        }
    }

    pub(crate) fn vmmon(&self) -> &Path {
        &self.vmmon
    }

    pub(crate) fn netd(&self) -> &Path {
        &self.netd
    }

    pub(crate) fn krun(&self) -> &Path {
        &self.krun
    }

    pub(crate) fn kernel(&self) -> &Path {
        &self.kernel
    }

    pub(crate) fn initramfs(&self) -> &Path {
        &self.initramfs
    }

    pub(crate) fn agent(&self) -> &Path {
        &self.agent
    }
}

#[derive(Debug, Clone, Copy)]
struct Component {
    name: &'static str,
    relative_path: &'static str,
    executable: bool,
}

impl Component {
    const fn executable(name: &'static str, relative_path: &'static str) -> Self {
        Self {
            name,
            relative_path,
            executable: true,
        }
    }

    const fn readable(name: &'static str, relative_path: &'static str) -> Self {
        Self {
            name,
            relative_path,
            executable: false,
        }
    }
}

#[derive(Debug, Default)]
struct PartialComponents {
    vmmon: Option<PathBuf>,
    netd: Option<PathBuf>,
    krun: Option<PathBuf>,
    kernel: Option<PathBuf>,
    initramfs: Option<PathBuf>,
    agent: Option<PathBuf>,
}

impl PartialComponents {
    fn is_complete(&self) -> bool {
        self.vmmon.is_some()
            && self.netd.is_some()
            && self.krun.is_some()
            && self.kernel.is_some()
            && self.initramfs.is_some()
            && self.agent.is_some()
    }

    fn assets_are_complete(&self) -> bool {
        self.kernel.is_some() && self.initramfs.is_some() && self.agent.is_some()
    }

    fn get_mut(&mut self, component: Component) -> &mut Option<PathBuf> {
        match component.name {
            "vmmon" => &mut self.vmmon,
            "netd" => &mut self.netd,
            "krun" => &mut self.krun,
            "kernel" => &mut self.kernel,
            "initramfs" => &mut self.initramfs,
            "agent" => &mut self.agent,
            _ => unreachable!("all runtime components are covered"),
        }
    }

    fn finish(self, checked: &[String]) -> Result<ResolvedRuntimeComponents, LibVmError> {
        macro_rules! required {
            ($field:ident, $name:literal) => {
                self.$field
                    .ok_or_else(|| LibVmError::RuntimeComponentNotFound {
                        component: $name,
                        checked: checked.join(", "),
                    })?
            };
        }

        Ok(ResolvedRuntimeComponents {
            vmmon: required!(vmmon, "vmmon"),
            netd: required!(netd, "netd"),
            krun: required!(krun, "krun"),
            kernel: required!(kernel, "kernel"),
            initramfs: required!(initramfs, "initramfs"),
            agent: required!(agent, "agent"),
        })
    }
}

struct Resolver<'a> {
    config: &'a RuntimeConfig,
    inputs: DiscoveryInputs,
    resolved: PartialComponents,
    checked: Vec<String>,
}

impl<'a> Resolver<'a> {
    fn new(config: &'a RuntimeConfig, inputs: DiscoveryInputs) -> Self {
        Self {
            config,
            inputs,
            resolved: PartialComponents::default(),
            checked: Vec::new(),
        }
    }

    fn resolve(mut self) -> Result<ResolvedRuntimeComponents, LibVmError> {
        self.apply_explicit_component(VMMON, self.config.vmmon_path.as_deref())?;
        self.apply_explicit_component(NETD, self.config.netd_path.as_deref())?;
        self.apply_explicit_component(KRUN, self.config.krun_path.as_deref())?;
        self.apply_explicit_component(KERNEL, self.config.kernel_path.as_deref())?;
        self.apply_explicit_component(INITRAMFS, self.config.initramfs_path.as_deref())?;
        self.apply_explicit_component(AGENT, self.config.agent_path.as_deref())?;

        if !self.resolved.is_complete() {
            if let Some(root) = self.config.runtime_root.as_deref() {
                self.apply_strict_portable_root(root, "runtime config runtime_root")?;
            }
        }

        self.apply_environment_component(VMMON, ENV_VMMON_PATH, self.inputs.vmmon_path.clone())?;
        self.apply_environment_component(NETD, ENV_NETD_PATH, self.inputs.netd_path.clone())?;
        self.apply_environment_component(KRUN, ENV_KRUN_PATH, self.inputs.krun_path.clone())?;
        if !self.resolved.assets_are_complete() {
            if let Some(directory) = self.inputs.asset_dir.clone() {
                self.apply_strict_asset_directory(&PathBuf::from(directory), ENV_ASSET_DIR)?;
            }
        }

        if !self.resolved.is_complete() {
            if let Some(root) = self.inputs.runtime_dir.clone() {
                self.apply_strict_portable_root(&PathBuf::from(root), ENV_RUNTIME_DIR)?;
            }
        }
        if !self.resolved.is_complete() {
            if let Some(root) = self.config.bundled_runtime_root.as_deref() {
                self.apply_strict_portable_root(root, "caller bundled runtime")?;
            }
        }

        if !self.resolved.is_complete() {
            self.apply_current_executable_candidates()?;
        }
        if !self.resolved.is_complete() {
            self.apply_native_candidates()?;
        }
        if !self.resolved.is_complete() {
            self.apply_legacy_fallbacks()?;
        }

        self.resolved.finish(&self.checked)
    }

    fn apply_explicit_component(
        &mut self,
        component: Component,
        path: Option<&Path>,
    ) -> Result<(), LibVmError> {
        let Some(path) = path else {
            return Ok(());
        };
        let source = format!("runtime config {}_path", component.name);
        *self.resolved.get_mut(component) =
            Some(require_component(component, path, &source, true)?);
        Ok(())
    }

    fn apply_environment_component(
        &mut self,
        component: Component,
        variable: &'static str,
        value: Option<OsString>,
    ) -> Result<(), LibVmError> {
        if self.resolved.get_mut(component).is_some() {
            return Ok(());
        }
        let Some(value) = value else {
            return Ok(());
        };
        let path = PathBuf::from(value);
        *self.resolved.get_mut(component) =
            Some(require_component(component, &path, variable, true)?);
        Ok(())
    }

    fn apply_strict_portable_root(
        &mut self,
        root: &Path,
        source: &'static str,
    ) -> Result<(), LibVmError> {
        let candidate = portable_candidate(root, source)?;
        self.apply_candidate(candidate);
        Ok(())
    }

    fn apply_strict_asset_directory(
        &mut self,
        directory: &Path,
        source: &'static str,
    ) -> Result<(), LibVmError> {
        if !directory.is_absolute() {
            return Err(LibVmError::RuntimeComponentInvalid {
                component: "default assets",
                origin: source.to_string(),
                path: directory.to_path_buf(),
                reason: "path must be absolute".to_string(),
            });
        }
        let root = canonical_directory(directory, "default assets", source)?;
        let mut candidate = PartialComponents::default();
        for component in [KERNEL, INITRAMFS, AGENT] {
            let path = require_contained_component(
                component,
                &root,
                &root.join(asset_filename(component)),
                source,
            )?;
            *candidate.get_mut(component) = Some(path);
        }
        self.checked
            .push(format!("{source}={}", directory.display()));
        self.apply_candidate(candidate);
        Ok(())
    }

    fn apply_current_executable_candidates(&mut self) -> Result<(), LibVmError> {
        let Some(executable) = self.inputs.current_exe.clone() else {
            self.checked
                .push("runtime relative to current executable (unavailable)".to_string());
            return Ok(());
        };

        #[cfg(target_os = "macos")]
        {
            if let Some(candidate) = app_bundle_candidate(&executable)? {
                self.checked.push(format!(
                    "application bundle containing {}",
                    executable.display()
                ));
                self.apply_candidate(candidate);
                if self.resolved.is_complete() {
                    return Ok(());
                }
            }
        }

        if let Some(bin_directory) = executable.parent() {
            if let Some(root) = bin_directory.parent() {
                self.try_portable_root(root, "runtime relative to current executable")?;
            }
        }
        Ok(())
    }

    fn apply_native_candidates(&mut self) -> Result<(), LibVmError> {
        if !self.inputs.use_system_locations {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            if let Some(home) = self.inputs.home.as_deref().map(PathBuf::from) {
                if home.is_absolute() {
                    self.try_app_bundle(&home.join("Applications/Silo.app"), "user application")?;
                }
            }
            self.try_app_bundle(Path::new("/Applications/Silo.app"), "system application")?;
        }

        #[cfg(target_os = "linux")]
        {
            self.try_portable_root(Path::new("/usr/lib/silo"), "native package")?;
            self.try_split_candidate(
                Path::new("/usr/libexec/silo"),
                Path::new("/usr/lib64/silo/assets"),
                "RHEL native package",
            )?;
            self.try_split_candidate(
                Path::new("/usr/libexec/silo"),
                Path::new("/usr/lib/silo/assets"),
                "RHEL native package",
            )?;
        }

        self.try_portable_root(
            Path::new("/usr/local/lib/silo"),
            "administrator installation",
        )
    }

    fn apply_legacy_fallbacks(&mut self) -> Result<(), LibVmError> {
        let sibling = self
            .inputs
            .current_exe
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        let path_entries = self
            .inputs
            .path
            .as_deref()
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let mut bin_directories = Vec::new();
        if let Some(sibling) = sibling {
            bin_directories.push(sibling);
        }
        for path_entry in path_entries {
            if !bin_directories.contains(&path_entry) {
                bin_directories.push(path_entry);
            }
        }

        let mut asset_directories = Vec::new();
        if self.inputs.use_system_locations {
            asset_directories.push(PathBuf::from("/usr/local/share/silo/assets"));
        }
        if let Some(home) = self.inputs.home.as_deref().map(PathBuf::from) {
            if home.is_absolute() {
                asset_directories.push(home.join(".local/share/silo/assets"));
            }
        }

        for bin_directory in &bin_directories {
            for asset_directory in &asset_directories {
                self.checked.push(format!(
                    "legacy installation {} and {}",
                    bin_directory.display(),
                    asset_directory.display()
                ));
                if let Some(candidate) =
                    optional_split_candidate(bin_directory, asset_directory, "legacy installation")?
                {
                    self.apply_candidate(candidate);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn try_portable_root(&mut self, root: &Path, source: &'static str) -> Result<(), LibVmError> {
        self.checked.push(format!("{source} {}", root.display()));
        if let Some(candidate) = optional_portable_candidate(root, source)? {
            self.apply_candidate(candidate);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn try_app_bundle(&mut self, root: &Path, source: &'static str) -> Result<(), LibVmError> {
        self.checked.push(format!("{source} {}", root.display()));
        let executable = root.join("Contents/MacOS/silo");
        if let Some(candidate) = app_bundle_candidate(&executable)? {
            self.apply_candidate(candidate);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn try_split_candidate(
        &mut self,
        bin_directory: &Path,
        asset_directory: &Path,
        source: &'static str,
    ) -> Result<(), LibVmError> {
        self.checked.push(format!(
            "{source} {} and {}",
            bin_directory.display(),
            asset_directory.display()
        ));
        if let Some(candidate) = optional_split_candidate(bin_directory, asset_directory, source)? {
            self.apply_candidate(candidate);
        }
        Ok(())
    }

    fn apply_candidate(&mut self, mut candidate: PartialComponents) {
        for component in COMPONENTS {
            let target = self.resolved.get_mut(component);
            if target.is_none() {
                *target = candidate.get_mut(component).take();
            }
        }
    }
}

fn portable_candidate(root: &Path, source: &str) -> Result<PartialComponents, LibVmError> {
    if !root.is_absolute() {
        return Err(LibVmError::RuntimeComponentInvalid {
            component: "runtime root",
            origin: source.to_string(),
            path: root.to_path_buf(),
            reason: "path must be absolute".to_string(),
        });
    }
    let root = canonical_directory(root, "runtime root", source)?;
    candidate_from_paths(
        &root,
        COMPONENTS.map(|component| root.join(component.relative_path)),
        source,
    )
}

fn optional_portable_candidate(
    root: &Path,
    source: &str,
) -> Result<Option<PartialComponents>, LibVmError> {
    let Some(root) = optional_canonical_directory(root)? else {
        return Ok(None);
    };
    let paths = COMPONENTS.map(|component| root.join(component.relative_path));
    if paths.iter().any(|path| !path.is_file()) {
        return Ok(None);
    }
    candidate_from_paths(&root, paths, source).map(Some)
}

fn optional_split_candidate(
    bin_directory: &Path,
    asset_directory: &Path,
    source: &str,
) -> Result<Option<PartialComponents>, LibVmError> {
    let (Some(bin_directory), Some(asset_directory)) = (
        optional_canonical_directory(bin_directory)?,
        optional_canonical_directory(asset_directory)?,
    ) else {
        return Ok(None);
    };
    let paths = [
        bin_directory.join("vmmon"),
        bin_directory.join("netd"),
        bin_directory.join("krun"),
        asset_directory.join("kernel-default"),
        asset_directory.join("initramfs"),
        asset_directory.join("agent"),
    ];
    if paths.iter().any(|path| !path.is_file()) {
        return Ok(None);
    }
    let mut candidate = PartialComponents::default();
    for (index, (component, path)) in COMPONENTS.into_iter().zip(paths).enumerate() {
        let root = if index < 3 {
            &bin_directory
        } else {
            &asset_directory
        };
        *candidate.get_mut(component) =
            Some(require_contained_component(component, root, &path, source)?);
    }
    Ok(Some(candidate))
}

#[cfg(target_os = "macos")]
fn app_bundle_candidate(executable: &Path) -> Result<Option<PartialComponents>, LibVmError> {
    let Some(mac_os_directory) = executable.parent() else {
        return Ok(None);
    };
    if mac_os_directory.file_name().and_then(|name| name.to_str()) != Some("MacOS") {
        return Ok(None);
    }
    let Some(contents) = mac_os_directory.parent() else {
        return Ok(None);
    };
    if contents.file_name().and_then(|name| name.to_str()) != Some("Contents") {
        return Ok(None);
    }
    if executable.file_name().and_then(|name| name.to_str()) != Some("silo") {
        return Ok(None);
    }
    let Some(bundle) = contents.parent() else {
        return Ok(None);
    };
    let Some(bundle) = optional_canonical_directory(bundle)? else {
        return Ok(None);
    };
    validate_app_bundle(&bundle)?;
    let paths = [
        bundle.join("Contents/Helpers/vmmon"),
        bundle.join("Contents/Helpers/netd"),
        bundle.join("Contents/Helpers/krun"),
        bundle.join("Contents/Resources/assets/kernel-default"),
        bundle.join("Contents/Resources/assets/initramfs"),
        bundle.join("Contents/Resources/assets/agent"),
    ];
    if paths.iter().any(|path| !path.is_file()) {
        return Ok(None);
    }
    candidate_from_paths(&bundle, paths, "Silo.app").map(Some)
}

#[cfg(target_os = "macos")]
fn validate_app_bundle(bundle: &Path) -> Result<(), LibVmError> {
    validate_macos_host(bundle)?;
    let plist = bundle.join("Contents/Info.plist");
    require_bundle_value(&plist, "CFBundleIdentifier", "sh.silo.app")?;
    require_bundle_value(
        &plist,
        "CFBundleShortVersionString",
        env!("CARGO_PKG_VERSION"),
    )?;
    require_bundle_value(&plist, "LSMinimumSystemVersion", "26.0")?;
    require_bundle_value(&plist, "CFBundleExecutable", "silo")?;

    for relative in [
        "Contents/MacOS/silo",
        "Contents/Helpers/vmmon",
        "Contents/Helpers/netd",
        "Contents/Helpers/krun",
    ] {
        require_arm64_macho(&bundle.join(relative))?;
    }
    require_arm64_elf(&bundle.join("Contents/Resources/assets/agent"))?;
    require_arm64_linux_kernel(&bundle.join("Contents/Resources/assets/kernel-default"))
}

#[cfg(target_os = "macos")]
fn validate_macos_host(bundle: &Path) -> Result<(), LibVmError> {
    if std::env::consts::ARCH != "aarch64" {
        return Err(bundle_error(
            bundle,
            format!(
                "Silo.app requires an arm64 host, found {}",
                std::env::consts::ARCH
            ),
        ));
    }
    let output = Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .map_err(|err| bundle_error(bundle, format!("read macOS version: {err}")))?;
    if !output.status.success() {
        return Err(bundle_error(
            bundle,
            format!(
                "read macOS version: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    let version = String::from_utf8(output.stdout)
        .map_err(|err| bundle_error(bundle, format!("decode macOS version: {err}")))?;
    let major = version
        .trim()
        .split('.')
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| bundle_error(bundle, format!("invalid macOS version {version:?}")))?;
    if major < 26 {
        return Err(bundle_error(
            bundle,
            format!("Silo.app requires macOS 26 or newer, found {version:?}"),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_bundle_value(plist: &Path, key: &'static str, expected: &str) -> Result<(), LibVmError> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .output()
        .map_err(|err| bundle_error(plist, format!("read {key}: {err}")))?;
    if !output.status.success() {
        return Err(bundle_error(
            plist,
            format!(
                "read {key}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    let actual = String::from_utf8(output.stdout)
        .map_err(|err| bundle_error(plist, format!("decode {key}: {err}")))?;
    let actual = actual.trim();
    if actual != expected {
        return Err(bundle_error(
            plist,
            format!("{key} must be {expected:?}, found {actual:?}"),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_arm64_macho(path: &Path) -> Result<(), LibVmError> {
    let bytes = std::fs::read(path)
        .map_err(|err| bundle_error(path, format!("read Mach-O header: {err}")))?;
    if macho_contains_arm64(&bytes) {
        return Ok(());
    }
    Err(bundle_error(path, "executable does not contain arm64 code"))
}

#[cfg(target_os = "macos")]
fn macho_contains_arm64(bytes: &[u8]) -> bool {
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    let Some(magic) = bytes.get(..4) else {
        return false;
    };
    if magic == [0xcf, 0xfa, 0xed, 0xfe] {
        return bytes
            .get(4..8)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_le_bytes)
            == Some(CPU_TYPE_ARM64);
    }

    let (entry_size, byte_order) = match magic {
        [0xca, 0xfe, 0xba, 0xbe] => (20_usize, u32::from_be_bytes as fn([u8; 4]) -> u32),
        [0xca, 0xfe, 0xba, 0xbf] => (32_usize, u32::from_be_bytes as fn([u8; 4]) -> u32),
        [0xbe, 0xba, 0xfe, 0xca] => (20_usize, u32::from_le_bytes as fn([u8; 4]) -> u32),
        [0xbf, 0xba, 0xfe, 0xca] => (32_usize, u32::from_le_bytes as fn([u8; 4]) -> u32),
        _ => return false,
    };
    let Some(count) = bytes
        .get(4..8)
        .and_then(|value| value.try_into().ok())
        .map(byte_order)
        .and_then(|count| usize::try_from(count).ok())
    else {
        return false;
    };
    (0..count).any(|index| {
        let offset = 8_usize.saturating_add(index.saturating_mul(entry_size));
        bytes
            .get(offset..offset.saturating_add(4))
            .and_then(|value| value.try_into().ok())
            .map(byte_order)
            == Some(CPU_TYPE_ARM64)
    })
}

#[cfg(target_os = "macos")]
fn require_arm64_elf(path: &Path) -> Result<(), LibVmError> {
    let bytes =
        std::fs::read(path).map_err(|err| bundle_error(path, format!("read ELF header: {err}")))?;
    let is_arm64 = bytes.get(..4) == Some(b"\x7fELF") && bytes.get(18..20) == Some(&[0xb7, 0x00]);
    if is_arm64 {
        return Ok(());
    }
    Err(bundle_error(path, "guest agent is not an arm64 ELF file"))
}

#[cfg(target_os = "macos")]
fn require_arm64_linux_kernel(path: &Path) -> Result<(), LibVmError> {
    let bytes = std::fs::read(path)
        .map_err(|err| bundle_error(path, format!("read Linux kernel header: {err}")))?;
    if bytes.get(56..60) == Some(b"ARM\x64") {
        return Ok(());
    }
    Err(bundle_error(
        path,
        "default kernel is not an arm64 Linux image",
    ))
}

#[cfg(target_os = "macos")]
fn bundle_error(path: &Path, reason: impl Into<String>) -> LibVmError {
    LibVmError::RuntimeComponentInvalid {
        component: "application bundle",
        origin: "Silo.app".to_string(),
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn candidate_from_paths(
    root: &Path,
    paths: [PathBuf; 6],
    source: &str,
) -> Result<PartialComponents, LibVmError> {
    let mut candidate = PartialComponents::default();
    for (component, path) in COMPONENTS.into_iter().zip(paths) {
        let path = require_contained_component(component, root, &path, source)?;
        *candidate.get_mut(component) = Some(path);
    }
    Ok(candidate)
}

fn require_contained_component(
    component: Component,
    root: &Path,
    path: &Path,
    source: &str,
) -> Result<PathBuf, LibVmError> {
    let path = require_component(component, path, source, false)?;
    if !path.starts_with(root) {
        return Err(LibVmError::RuntimeComponentInvalid {
            component: component.name,
            origin: source.to_string(),
            path,
            reason: format!("resolved path escapes runtime root {}", root.display()),
        });
    }
    Ok(path)
}

fn require_component(
    component: Component,
    path: &Path,
    source: &str,
    require_absolute: bool,
) -> Result<PathBuf, LibVmError> {
    if require_absolute && !path.is_absolute() {
        return Err(LibVmError::RuntimeComponentInvalid {
            component: component.name,
            origin: source.to_string(),
            path: path.to_path_buf(),
            reason: "path must be absolute".to_string(),
        });
    }
    let canonical =
        std::fs::canonicalize(path).map_err(|err| LibVmError::RuntimeComponentInvalid {
            component: component.name,
            origin: source.to_string(),
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    let metadata = canonical.metadata().map_err(LibVmError::Io)?;
    if !metadata.is_file() {
        return Err(LibVmError::RuntimeComponentInvalid {
            component: component.name,
            origin: source.to_string(),
            path: canonical,
            reason: "path is not a regular file".to_string(),
        });
    }
    let access_mode = if component.executable {
        AccessFlags::X_OK
    } else {
        AccessFlags::R_OK
    };
    access(&canonical, access_mode).map_err(|err| LibVmError::RuntimeComponentInvalid {
        component: component.name,
        origin: source.to_string(),
        path: canonical.clone(),
        reason: if component.executable {
            format!("file is not executable: {err}")
        } else {
            format!("file is not readable: {err}")
        },
    })?;
    Ok(canonical)
}

fn canonical_directory(
    path: &Path,
    component: &'static str,
    source: &str,
) -> Result<PathBuf, LibVmError> {
    let canonical =
        std::fs::canonicalize(path).map_err(|err| LibVmError::RuntimeComponentInvalid {
            component,
            origin: source.to_string(),
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    if !canonical.is_dir() {
        return Err(LibVmError::RuntimeComponentInvalid {
            component,
            origin: source.to_string(),
            path: canonical,
            reason: "path is not a directory".to_string(),
        });
    }
    Ok(canonical)
}

fn optional_canonical_directory(path: &Path) -> Result<Option<PathBuf>, LibVmError> {
    if !path.is_dir() {
        return Ok(None);
    }
    std::fs::canonicalize(path)
        .map(Some)
        .map_err(LibVmError::Io)
}

fn asset_filename(component: Component) -> &'static str {
    match component.name {
        "kernel" => "kernel-default",
        "initramfs" => "initramfs",
        "agent" => "agent",
        _ => unreachable!("asset component expected"),
    }
}

struct DiscoveryInputs {
    runtime_dir: Option<OsString>,
    vmmon_path: Option<OsString>,
    netd_path: Option<OsString>,
    krun_path: Option<OsString>,
    asset_dir: Option<OsString>,
    path: Option<OsString>,
    home: Option<OsString>,
    current_exe: Option<PathBuf>,
    use_system_locations: bool,
}

impl DiscoveryInputs {
    fn from_process() -> Self {
        Self {
            runtime_dir: std::env::var_os(ENV_RUNTIME_DIR),
            vmmon_path: std::env::var_os(ENV_VMMON_PATH),
            netd_path: std::env::var_os(ENV_NETD_PATH),
            krun_path: std::env::var_os(ENV_KRUN_PATH),
            asset_dir: std::env::var_os(ENV_ASSET_DIR),
            path: std::env::var_os("PATH"),
            home: std::env::var_os("HOME"),
            current_exe: std::env::current_exe()
                .ok()
                .and_then(|path| std::fs::canonicalize(path).ok()),
            use_system_locations: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    #[cfg(target_os = "macos")]
    use crate::runtime::components::app_bundle_candidate;
    use crate::runtime::components::{DiscoveryInputs, Resolver};
    use crate::{LibVmError, RuntimeConfig};

    fn write_runtime(root: &Path) {
        for relative in [
            "bin/vmmon",
            "bin/netd",
            "bin/krun",
            "assets/kernel-default",
            "assets/initramfs",
            "assets/agent",
        ] {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().expect("component parent"))
                .expect("create component parent");
            std::fs::write(&path, relative.as_bytes()).expect("write component");
            let mode = if relative.starts_with("bin/") || relative.ends_with("agent") {
                0o755
            } else {
                0o644
            };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set component permissions");
        }
    }

    fn write_asset(directory: &Path, name: &str, mode: u32) -> PathBuf {
        std::fs::create_dir_all(directory).expect("create component directory");
        let path = directory.join(name);
        std::fs::write(&path, name.as_bytes()).expect("write component");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set component permissions");
        path
    }

    #[cfg(target_os = "macos")]
    fn write_app_bundle(bundle: &Path, bundle_identifier: &str) -> PathBuf {
        let contents = bundle.join("Contents");
        let executable = contents.join("MacOS/silo");
        for path in [
            executable.clone(),
            contents.join("Helpers/vmmon"),
            contents.join("Helpers/netd"),
            contents.join("Helpers/krun"),
        ] {
            std::fs::create_dir_all(path.parent().expect("Mach-O parent"))
                .expect("create Mach-O parent");
            std::fs::write(&path, [0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01])
                .expect("write arm64 Mach-O header");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("make Mach-O executable");
        }
        let assets = contents.join("Resources/assets");
        write_asset(&assets, "initramfs", 0o644);
        let mut agent = vec![0_u8; 20];
        agent[..4].copy_from_slice(b"\x7fELF");
        agent[18..20].copy_from_slice(&[0xb7, 0x00]);
        let agent_path = assets.join("agent");
        std::fs::write(&agent_path, agent).expect("write arm64 agent");
        std::fs::set_permissions(&agent_path, std::fs::Permissions::from_mode(0o755))
            .expect("make agent executable");
        let mut kernel = vec![0_u8; 60];
        kernel[56..60].copy_from_slice(b"ARM\x64");
        std::fs::write(assets.join("kernel-default"), kernel).expect("write arm64 kernel");
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{bundle_identifier}</string>
<key>CFBundleExecutable</key><string>silo</string>
<key>CFBundleShortVersionString</key><string>{}</string>
<key>LSMinimumSystemVersion</key><string>26.0</string>
</dict></plist>"#,
            env!("CARGO_PKG_VERSION")
        );
        std::fs::write(contents.join("Info.plist"), plist).expect("write Info.plist");
        executable
    }

    fn inputs() -> DiscoveryInputs {
        DiscoveryInputs {
            runtime_dir: None,
            vmmon_path: None,
            netd_path: None,
            krun_path: None,
            asset_dir: None,
            path: None,
            home: None,
            current_exe: None,
            use_system_locations: false,
        }
    }

    #[test]
    fn explicit_runtime_root_resolves_one_complete_set() {
        let temp = TempDir::new().expect("tempdir");
        write_runtime(temp.path());
        let config = RuntimeConfig::default().with_runtime_root(temp.path());

        let resolved = Resolver::new(&config, inputs()).resolve().expect("resolve");
        let root = temp.path().canonicalize().expect("canonical runtime root");

        assert_eq!(resolved.vmmon(), root.join("bin/vmmon"));
        assert_eq!(resolved.netd(), root.join("bin/netd"));
        assert_eq!(resolved.krun(), root.join("bin/krun"));
        assert_eq!(resolved.kernel(), root.join("assets/kernel-default"));
        assert_eq!(resolved.initramfs(), root.join("assets/initramfs"));
        assert_eq!(resolved.agent(), root.join("assets/agent"));
    }

    #[test]
    fn explicit_component_overrides_runtime_root() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("runtime");
        write_runtime(&root);
        let custom_vmmon = temp.path().join("custom-vmmon");
        std::fs::write(&custom_vmmon, b"vmmon").expect("write custom vmmon");
        std::fs::set_permissions(&custom_vmmon, std::fs::Permissions::from_mode(0o755))
            .expect("make custom vmmon executable");
        let config = RuntimeConfig::default()
            .with_runtime_root(&root)
            .with_vmmon_path(&custom_vmmon);

        let resolved = Resolver::new(&config, inputs()).resolve().expect("resolve");

        assert_eq!(
            resolved.vmmon(),
            custom_vmmon.canonicalize().expect("canonical custom vmmon")
        );
        assert_eq!(
            resolved.netd(),
            root.canonicalize()
                .expect("canonical runtime root")
                .join("bin/netd")
        );
    }

    #[test]
    fn component_environment_precedes_environment_runtime_root() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("runtime");
        write_runtime(&root);
        let custom_netd = temp.path().join("custom-netd");
        std::fs::write(&custom_netd, b"netd").expect("write custom netd");
        std::fs::set_permissions(&custom_netd, std::fs::Permissions::from_mode(0o755))
            .expect("make custom netd executable");
        let mut discovery = inputs();
        discovery.runtime_dir = Some(root.clone().into_os_string());
        discovery.netd_path = Some(custom_netd.clone().into_os_string());

        let resolved = Resolver::new(&RuntimeConfig::default(), discovery)
            .resolve()
            .expect("resolve");

        assert_eq!(
            resolved.netd(),
            custom_netd.canonicalize().expect("canonical custom netd")
        );
        assert_eq!(
            resolved.vmmon(),
            root.canonicalize()
                .expect("canonical runtime root")
                .join("bin/vmmon")
        );
    }

    #[test]
    fn asset_directory_must_contain_a_complete_set() {
        let temp = TempDir::new().expect("tempdir");
        let assets = temp.path().join("assets");
        std::fs::create_dir_all(&assets).expect("create assets");
        std::fs::write(assets.join("kernel-default"), b"kernel").expect("write kernel");
        let mut discovery = inputs();
        discovery.asset_dir = Some(assets.into_os_string());

        let error = Resolver::new(&RuntimeConfig::default(), discovery)
            .resolve()
            .expect_err("incomplete explicit assets must fail");

        assert!(matches!(
            error,
            LibVmError::RuntimeComponentInvalid {
                component: "initramfs",
                ..
            }
        ));
    }

    #[test]
    fn convention_candidates_do_not_mix_incomplete_roots() {
        let temp = TempDir::new().expect("tempdir");
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        write_runtime(&first);
        write_runtime(&second);
        std::fs::remove_file(first.join("assets/agent")).expect("remove first agent");
        let mut discovery = inputs();
        discovery.current_exe = Some(first.join("bin/silo"));
        discovery.path = Some(OsString::from(second.join("bin")));
        discovery.home = Some(second.clone().into_os_string());

        let error = Resolver::new(&RuntimeConfig::default(), discovery)
            .resolve()
            .expect_err("incomplete roots must not be mixed");

        assert!(matches!(
            error,
            LibVmError::RuntimeComponentNotFound {
                component: "vmmon",
                ..
            }
        ));
    }

    #[test]
    fn explicit_runtime_root_precedes_component_environment() {
        let temp = TempDir::new().expect("tempdir");
        write_runtime(temp.path());
        let mut discovery = inputs();
        discovery.vmmon_path = Some(OsString::from("ignored/relative/vmmon"));

        let resolved = Resolver::new(
            &RuntimeConfig::default().with_runtime_root(temp.path()),
            discovery,
        )
        .resolve()
        .expect("explicit root should satisfy all components first");

        assert_eq!(
            resolved.vmmon(),
            temp.path()
                .canonicalize()
                .expect("canonical runtime root")
                .join("bin/vmmon")
        );
    }

    #[test]
    fn legacy_fallback_selects_complete_helper_and_asset_directories() {
        let temp = TempDir::new().expect("tempdir");
        let bin = temp.path().join("legacy-bin");
        let home = temp.path().join("home");
        let assets = home.join(".local/share/silo/assets");
        for helper in ["vmmon", "netd", "krun"] {
            let path = write_asset(&bin, helper, 0o755);
            assert!(path.is_file());
        }
        write_asset(&assets, "kernel-default", 0o644);
        write_asset(&assets, "initramfs", 0o644);
        write_asset(&assets, "agent", 0o755);
        let mut discovery = inputs();
        discovery.current_exe = Some(bin.join("silo"));
        discovery.home = Some(home.into_os_string());

        let resolved = Resolver::new(&RuntimeConfig::default(), discovery)
            .resolve()
            .expect("resolve complete legacy installation");
        let bin = bin.canonicalize().expect("canonical bin");
        let assets = assets.canonicalize().expect("canonical assets");

        assert_eq!(resolved.vmmon(), bin.join("vmmon"));
        assert_eq!(resolved.netd(), bin.join("netd"));
        assert_eq!(resolved.krun(), bin.join("krun"));
        assert_eq!(resolved.kernel(), assets.join("kernel-default"));
        assert_eq!(resolved.initramfs(), assets.join("initramfs"));
        assert_eq!(resolved.agent(), assets.join("agent"));
    }

    #[test]
    fn legacy_asset_symlink_cannot_escape_its_directory() {
        let temp = TempDir::new().expect("tempdir");
        let bin = temp.path().join("legacy-bin");
        let home = temp.path().join("home");
        let assets = home.join(".local/share/silo/assets");
        for helper in ["vmmon", "netd", "krun"] {
            write_asset(&bin, helper, 0o755);
        }
        write_asset(&assets, "kernel-default", 0o644);
        write_asset(&assets, "initramfs", 0o644);
        let outside = write_asset(temp.path(), "outside-agent", 0o755);
        std::os::unix::fs::symlink(&outside, assets.join("agent")).expect("symlink agent");
        let mut discovery = inputs();
        discovery.current_exe = Some(bin.join("silo"));
        discovery.home = Some(home.into_os_string());

        let error = Resolver::new(&RuntimeConfig::default(), discovery)
            .resolve()
            .expect_err("escaping legacy asset must fail");

        assert!(matches!(
            error,
            LibVmError::RuntimeComponentInvalid {
                component: "agent",
                ref reason,
                ..
            } if reason.contains("escapes runtime root")
        ));
    }

    #[test]
    fn relative_environment_component_is_rejected() {
        let mut discovery = inputs();
        discovery.vmmon_path = Some(OsString::from("relative/vmmon"));

        let error = Resolver::new(&RuntimeConfig::default(), discovery)
            .resolve()
            .expect_err("relative environment path must fail");

        assert!(matches!(
            &error,
            LibVmError::RuntimeComponentInvalid {
                component: "vmmon",
                reason,
                ..
            } if reason == "path must be absolute"
        ));
        let message = error.to_string();
        assert!(message.contains("portable roots must contain bin/{vmmon,netd,krun}"));
        assert!(message.contains("explicit component paths must be absolute regular files"));
    }

    #[test]
    fn non_executable_helper_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        write_runtime(temp.path());
        std::fs::set_permissions(
            temp.path().join("bin/netd"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("remove execute permission");

        let error = Resolver::new(
            &RuntimeConfig::default().with_runtime_root(temp.path()),
            inputs(),
        )
        .resolve()
        .expect_err("non-executable helper must fail");

        assert!(matches!(
            error,
            LibVmError::RuntimeComponentInvalid {
                component: "netd",
                ref reason,
                ..
            } if reason.contains("not executable")
        ));
    }

    #[test]
    fn symlinked_component_cannot_escape_runtime_root() {
        let temp = TempDir::new().expect("tempdir");
        write_runtime(temp.path());
        let outside = temp
            .path()
            .parent()
            .expect("temp parent")
            .join(format!("outside-agent-{}", std::process::id()));
        std::fs::write(&outside, b"agent").expect("write outside agent");
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755))
            .expect("make outside agent executable");
        std::fs::remove_file(temp.path().join("assets/agent")).expect("remove agent");
        std::os::unix::fs::symlink(&outside, temp.path().join("assets/agent"))
            .expect("symlink agent");

        let error = Resolver::new(
            &RuntimeConfig::default().with_runtime_root(temp.path()),
            inputs(),
        )
        .resolve()
        .expect_err("escaping symlink must fail");
        std::fs::remove_file(&outside).expect("remove outside agent");

        assert!(matches!(
            error,
            LibVmError::RuntimeComponentInvalid {
                component: "agent",
                ref reason,
                ..
            } if reason.contains("escapes runtime root")
        ));
    }

    #[test]
    fn bundled_runtime_is_used_after_environment_candidates() {
        let temp = TempDir::new().expect("tempdir");
        write_runtime(temp.path());
        let config = RuntimeConfig::default().with_bundled_runtime_root(temp.path());

        let resolved = Resolver::new(&config, inputs()).resolve().expect("resolve");

        assert_eq!(
            resolved.agent(),
            temp.path()
                .canonicalize()
                .expect("canonical runtime root")
                .join("assets/agent")
        );
    }

    #[test]
    fn missing_runtime_reports_the_component_and_candidates() {
        let error = Resolver::new(&RuntimeConfig::default(), inputs())
            .resolve()
            .expect_err("missing runtime must fail");

        assert!(matches!(
            error,
            LibVmError::RuntimeComponentNotFound {
                component: "vmmon",
                ref checked,
            } if checked.contains("current executable")
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_bundle_requires_identity_version_and_arm64_components() {
        let temp = TempDir::new().expect("tempdir");
        let bundle = temp.path().join("Silo.app");
        let executable = write_app_bundle(&bundle, "sh.silo.app");

        let resolved = app_bundle_candidate(&executable)
            .expect("validate app bundle")
            .expect("recognize app bundle");

        assert_eq!(
            resolved.vmmon,
            Some(
                bundle
                    .canonicalize()
                    .expect("canonical bundle")
                    .join("Contents/Helpers/vmmon")
            )
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_bundle_rejects_wrong_bundle_identifier() {
        let temp = TempDir::new().expect("tempdir");
        let executable = write_app_bundle(&temp.path().join("Silo.app"), "com.example.not-silo");

        let error = app_bundle_candidate(&executable).expect_err("wrong identity must fail");

        assert!(matches!(
            error,
            LibVmError::RuntimeComponentInvalid {
                component: "application bundle",
                ref reason,
                ..
            } if reason.contains("CFBundleIdentifier")
        ));
    }

    #[allow(dead_code)]
    fn assert_paths_are_send_sync(_: PathBuf) {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<PathBuf>();
    }
}
