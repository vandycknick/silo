use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::runtime::RuntimeConfig;
use crate::LibVmError;

const ENV_VMMON_PATH: &str = "SILO_VMMON_PATH";
const ENV_NETD_PATH: &str = "NETD_BIN";
const ENV_KRUN_PATH: &str = "KRUN_BIN";
const ENV_ASSET_DIR: &str = "SILO_ASSET_DIR";
const ENV_RUNTIME_DIR: &str = "SILO_RUNTIME_DIR";
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub(crate) struct ResolvedRuntimeComponents {
    pub(crate) vmmon: PathBuf,
    pub(crate) netd: PathBuf,
    pub(crate) krun: PathBuf,
    pub(crate) kernel: PathBuf,
    pub(crate) initramfs: PathBuf,
    pub(crate) agent: PathBuf,
}

#[derive(Debug, Clone, Default)]
struct ComponentOverrides {
    vmmon: Option<PathBuf>,
    netd: Option<PathBuf>,
    krun: Option<PathBuf>,
    kernel: Option<PathBuf>,
    initramfs: Option<PathBuf>,
    agent: Option<PathBuf>,
}

struct EnvironmentOverrides {
    components: ComponentOverrides,
    assets: Option<PathBuf>,
}

impl ComponentOverrides {
    fn apply_to(self, mut components: ResolvedRuntimeComponents) -> ResolvedRuntimeComponents {
        if let Some(path) = self.vmmon {
            components.vmmon = path;
        }
        if let Some(path) = self.netd {
            components.netd = path;
        }
        if let Some(path) = self.krun {
            components.krun = path;
        }
        if let Some(path) = self.kernel {
            components.kernel = path;
        }
        if let Some(path) = self.initramfs {
            components.initramfs = path;
        }
        if let Some(path) = self.agent {
            components.agent = path;
        }
        components
    }

    fn merge(self, lower: Self) -> Self {
        Self {
            vmmon: self.vmmon.or(lower.vmmon),
            netd: self.netd.or(lower.netd),
            krun: self.krun.or(lower.krun),
            kernel: self.kernel.or(lower.kernel),
            initramfs: self.initramfs.or(lower.initramfs),
            agent: self.agent.or(lower.agent),
        }
    }
}

#[derive(Debug, Clone)]
struct ComponentPaths {
    vmmon: PathBuf,
    netd: PathBuf,
    krun: PathBuf,
    kernel: PathBuf,
    initramfs: PathBuf,
    agent: PathBuf,
}

impl ComponentPaths {
    fn portable(root: &Path) -> Self {
        Self {
            vmmon: root.join("bin/vmmon"),
            netd: root.join("bin/netd"),
            krun: root.join("bin/krun"),
            kernel: root.join("assets/kernel-default"),
            initramfs: root.join("assets/initramfs"),
            agent: root.join("assets/agent"),
        }
    }

    fn adjacent(directory: &Path) -> Self {
        Self {
            vmmon: directory.join("vmmon"),
            netd: directory.join("netd"),
            krun: directory.join("krun"),
            kernel: directory.join("assets/kernel-default"),
            initramfs: directory.join("assets/initramfs"),
            agent: directory.join("assets/agent"),
        }
    }

    fn rhel(helpers: &Path, assets: &Path) -> Self {
        Self {
            vmmon: helpers.join("vmmon"),
            netd: helpers.join("netd"),
            krun: helpers.join("krun"),
            kernel: assets.join("kernel-default"),
            initramfs: assets.join("initramfs"),
            agent: assets.join("agent"),
        }
    }
}

trait ComponentEnvironment {
    fn get(&mut self, name: &'static str) -> Option<OsString>;
}

struct ProcessEnvironment;

impl ComponentEnvironment for ProcessEnvironment {
    fn get(&mut self, name: &'static str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

pub(crate) fn resolve_components(
    config: &RuntimeConfig,
) -> Result<ResolvedRuntimeComponents, LibVmError> {
    let mut environment = ProcessEnvironment;
    resolve_components_with(
        config,
        &mut environment,
        std::env::current_exe,
        &native_candidates(),
    )
}

fn resolve_components_with<E, F>(
    config: &RuntimeConfig,
    environment: &mut E,
    current_exe: F,
    native_candidates: &[(String, ComponentPaths)],
) -> Result<ResolvedRuntimeComponents, LibVmError>
where
    E: ComponentEnvironment,
    F: FnOnce() -> io::Result<PathBuf>,
{
    let api = explicit_api_overrides(config)?;
    if let Some(root) = config.runtime_root.as_deref() {
        let components = resolve_required_portable_root("runtime_root", root)?;
        return Ok(api.apply_to(components));
    }

    let environment_overrides = explicit_environment_overrides(environment)?;
    let path_assets = environment_overrides.assets;
    let overrides = api.merge(environment_overrides.components);
    if let Some(root) = environment.get(ENV_RUNTIME_DIR) {
        let root = PathBuf::from(root);
        let components = resolve_required_portable_root(ENV_RUNTIME_DIR, &root)?;
        return Ok(overrides.apply_to(components));
    }
    if let Some(root) = config.bundled_runtime_root.as_deref() {
        let components = resolve_required_portable_root("bundled_runtime_root", root)?;
        return Ok(overrides.apply_to(components));
    }

    let mut considered = Vec::new();
    let canonical_exe = match current_exe().and_then(fs::canonicalize) {
        Ok(path) => Some(path),
        Err(err) => {
            considered.push(format!("canonical current executable: {err}"));
            None
        }
    };

    if let Some(executable) = canonical_exe.as_deref() {
        if let Some(directory) = executable.parent() {
            if let Some(components) = consider(
                &mut considered,
                "adjacent development runtime",
                ComponentPaths::adjacent(directory),
                None,
            ) {
                return Ok(overrides.apply_to(components));
            }
        }

        if let Some(root) = portable_root_for_executable(executable) {
            if let Some(components) = consider(
                &mut considered,
                "executable-relative portable runtime",
                ComponentPaths::portable(&root),
                Some(&root),
            ) {
                return Ok(overrides.apply_to(components));
            }
        }

        if let Some((bundle, contents)) = app_contents_for_executable(executable) {
            if let Some(components) = consider_app_bundle(&mut considered, &bundle, &contents) {
                return Ok(overrides.apply_to(components));
            }
        }
    }

    if let Some(assets) = path_assets.as_deref() {
        if let Some(components) =
            resolve_path_helpers(environment, assets, &overrides, &mut considered)?
        {
            return Ok(components);
        }
    }

    for (name, paths) in native_candidates {
        if let Some(components) = consider(&mut considered, name, paths.clone(), None) {
            return Ok(overrides.clone().apply_to(components));
        }
    }
    #[cfg(target_os = "macos")]
    for bundle in sdk_app_candidates() {
        let contents = bundle.join("Contents");
        if let Some(components) = consider_app_bundle(&mut considered, &bundle, &contents) {
            return Ok(overrides.clone().apply_to(components));
        }
    }

    Err(LibVmError::RuntimeComponentsNotFound {
        considered: considered.join("; "),
    })
}

fn explicit_api_overrides(config: &RuntimeConfig) -> Result<ComponentOverrides, LibVmError> {
    Ok(ComponentOverrides {
        vmmon: explicit_component("vmmon_path", config.vmmon_path.as_deref(), true)?,
        netd: explicit_component("netd_path", config.netd_path.as_deref(), true)?,
        krun: explicit_component("krun_path", config.krun_path.as_deref(), true)?,
        kernel: explicit_component("kernel_path", config.kernel_path.as_deref(), false)?,
        initramfs: explicit_component("initramfs_path", config.initramfs_path.as_deref(), false)?,
        agent: explicit_component("agent_path", config.agent_path.as_deref(), true)?,
    })
}

fn explicit_environment_overrides<E: ComponentEnvironment>(
    environment: &mut E,
) -> Result<EnvironmentOverrides, LibVmError> {
    let vmmon = environment.get(ENV_VMMON_PATH).map(PathBuf::from);
    let netd = environment.get(ENV_NETD_PATH).map(PathBuf::from);
    let krun = environment.get(ENV_KRUN_PATH).map(PathBuf::from);
    let assets = environment.get(ENV_ASSET_DIR).map(PathBuf::from);
    let assets = assets
        .map(|path| resolve_required_asset_dir(ENV_ASSET_DIR, &path))
        .transpose()?;
    Ok(EnvironmentOverrides {
        components: ComponentOverrides {
            vmmon: explicit_component(ENV_VMMON_PATH, vmmon.as_deref(), true)?,
            netd: explicit_component(ENV_NETD_PATH, netd.as_deref(), true)?,
            krun: explicit_component(ENV_KRUN_PATH, krun.as_deref(), true)?,
            kernel: assets
                .as_ref()
                .map(|assets| {
                    canonical_component(
                        "kernel-default",
                        &assets.join("kernel-default"),
                        false,
                        Some(assets),
                    )
                })
                .transpose()
                .map_err(|message| LibVmError::RuntimeComponentInvalid {
                    input: ENV_ASSET_DIR.to_string(),
                    message,
                })?,
            initramfs: assets
                .as_ref()
                .map(|assets| {
                    canonical_component("initramfs", &assets.join("initramfs"), false, Some(assets))
                })
                .transpose()
                .map_err(|message| LibVmError::RuntimeComponentInvalid {
                    input: ENV_ASSET_DIR.to_string(),
                    message,
                })?,
            agent: assets
                .as_ref()
                .map(|assets| {
                    canonical_component("agent", &assets.join("agent"), true, Some(assets))
                })
                .transpose()
                .map_err(|message| LibVmError::RuntimeComponentInvalid {
                    input: ENV_ASSET_DIR.to_string(),
                    message,
                })?,
        },
        assets,
    })
}

fn explicit_component(
    source: &'static str,
    path: Option<&Path>,
    executable: bool,
) -> Result<Option<PathBuf>, LibVmError> {
    path.map(|path| {
        if !path.is_absolute() {
            return Err(LibVmError::RuntimeComponentInvalid {
                input: source.to_string(),
                message: format!("path must be absolute, got {}", path.display()),
            });
        }
        canonical_component(source, path, executable, None).map_err(|message| {
            LibVmError::RuntimeComponentInvalid {
                input: source.to_string(),
                message,
            }
        })
    })
    .transpose()
}

fn resolve_required_portable_root(
    source: &'static str,
    root: &Path,
) -> Result<ResolvedRuntimeComponents, LibVmError> {
    if !root.is_absolute() {
        return Err(LibVmError::RuntimeComponentInvalid {
            input: source.to_string(),
            message: format!("runtime root must be absolute, got {}", root.display()),
        });
    }
    validate_components(ComponentPaths::portable(root), Some(root)).map_err(|message| {
        LibVmError::RuntimeComponentInvalid {
            input: source.to_string(),
            message,
        }
    })
}

fn resolve_required_asset_dir(source: &'static str, assets: &Path) -> Result<PathBuf, LibVmError> {
    if !assets.is_absolute() {
        return Err(LibVmError::RuntimeComponentInvalid {
            input: source.to_string(),
            message: format!("asset directory must be absolute, got {}", assets.display()),
        });
    }
    let assets = canonical_root(assets).map_err(|message| LibVmError::RuntimeComponentInvalid {
        input: source.to_string(),
        message,
    })?;
    for (name, executable) in [
        ("kernel-default", false),
        ("initramfs", false),
        ("agent", true),
    ] {
        canonical_component(name, &assets.join(name), executable, Some(&assets)).map_err(
            |message| LibVmError::RuntimeComponentInvalid {
                input: source.to_string(),
                message,
            },
        )?;
    }
    Ok(assets)
}

fn consider(
    considered: &mut Vec<String>,
    name: &str,
    paths: ComponentPaths,
    root: Option<&Path>,
) -> Option<ResolvedRuntimeComponents> {
    match validate_components(paths, root) {
        Ok(components) => Some(components),
        Err(message) => {
            considered.push(format!("{name}: {message}"));
            None
        }
    }
}

fn validate_components(
    paths: ComponentPaths,
    root: Option<&Path>,
) -> Result<ResolvedRuntimeComponents, String> {
    let root = root.map(canonical_root).transpose()?;
    Ok(ResolvedRuntimeComponents {
        vmmon: canonical_component("vmmon", &paths.vmmon, true, root.as_deref())?,
        netd: canonical_component("netd", &paths.netd, true, root.as_deref())?,
        krun: canonical_component("krun", &paths.krun, true, root.as_deref())?,
        kernel: canonical_component("kernel-default", &paths.kernel, false, root.as_deref())?,
        initramfs: canonical_component("initramfs", &paths.initramfs, false, root.as_deref())?,
        agent: canonical_component("agent", &paths.agent, true, root.as_deref())?,
    })
}

fn canonical_root(root: &Path) -> Result<PathBuf, String> {
    let root = fs::canonicalize(root)
        .map_err(|err| format!("canonicalize runtime root {}: {err}", root.display()))?;
    if root.is_dir() {
        Ok(root)
    } else {
        Err(format!(
            "runtime root {} is not a directory",
            root.display()
        ))
    }
}

fn canonical_component(
    name: &str,
    path: &Path,
    executable: bool,
    root: Option<&Path>,
) -> Result<PathBuf, String> {
    let canonical =
        fs::canonicalize(path).map_err(|err| format!("{name} at {}: {err}", path.display()))?;
    if let Some(root) = root {
        if !canonical.starts_with(root) {
            return Err(format!(
                "{name} at {} escapes runtime root {}",
                canonical.display(),
                root.display()
            ));
        }
    }
    let metadata = fs::metadata(&canonical)
        .map_err(|err| format!("read {name} metadata at {}: {err}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{name} at {} is not a regular file",
            canonical.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode();
        let required = if executable { 0o111 } else { 0o444 };
        if mode & required == 0 {
            let kind = if executable { "executable" } else { "readable" };
            return Err(format!("{name} at {} is not {kind}", canonical.display()));
        }
    }
    Ok(canonical)
}

fn portable_root_for_executable(executable: &Path) -> Option<PathBuf> {
    let bin = executable.parent()?;
    (executable.file_name()? == "silo" && bin.file_name()? == "bin")
        .then(|| bin.parent().map(Path::to_path_buf))?
}

fn app_contents_for_executable(executable: &Path) -> Option<(PathBuf, PathBuf)> {
    let macos = executable.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    (executable.file_name()? == "silo"
        && macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.file_name()? == "Silo.app")
        .then(|| (bundle.to_path_buf(), contents.to_path_buf()))
}

fn consider_app_bundle(
    considered: &mut Vec<String>,
    bundle: &Path,
    contents: &Path,
) -> Option<ResolvedRuntimeComponents> {
    match validate_app_bundle(bundle, contents) {
        Ok(components) => Some(components),
        Err(message) => {
            considered.push(format!("Silo.app {}: {message}", bundle.display()));
            None
        }
    }
}

fn validate_app_bundle(
    bundle: &Path,
    contents: &Path,
) -> Result<ResolvedRuntimeComponents, String> {
    let plist = plist::Value::from_file(contents.join("Info.plist"))
        .map_err(|err| format!("read Info.plist: {err}"))?;
    let dictionary = plist
        .as_dictionary()
        .ok_or_else(|| "Info.plist is not a dictionary".to_string())?;
    require_plist_string(dictionary, "CFBundleIdentifier", "sh.silo.app")?;
    require_plist_string(dictionary, "CFBundleExecutable", "silo")?;
    require_plist_string(dictionary, "CFBundleShortVersionString", PRODUCT_VERSION)?;
    require_plist_string(dictionary, "LSMinimumSystemVersion", "26.0")?;
    validate_arm64_macho(&contents.join("MacOS/silo"))?;
    let bundle = canonical_root(bundle)?;
    validate_components(
        ComponentPaths {
            vmmon: contents.join("Helpers/vmmon"),
            netd: contents.join("Helpers/netd"),
            krun: contents.join("Helpers/krun"),
            kernel: contents.join("Resources/assets/kernel-default"),
            initramfs: contents.join("Resources/assets/initramfs"),
            agent: contents.join("Resources/assets/agent"),
        },
        Some(&bundle),
    )
}

fn require_plist_string(
    dictionary: &plist::Dictionary,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    match dictionary.get(key).and_then(plist::Value::as_string) {
        Some(value) if value == expected => Ok(()),
        Some(value) => Err(format!(
            "Info.plist {key} must be {expected:?}, got {value:?}"
        )),
        None => Err(format!("Info.plist is missing string {key}")),
    }
}

fn validate_arm64_macho(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|err| format!("read Mach-O {}: {err}", path.display()))?;
    let bytes = arm64_macho_slice(&bytes)?;
    let architecture = read_u32(bytes, 4, false)?;
    if architecture != 0x0100_000c {
        return Err(format!(
            "{} is not an arm64 Mach-O executable",
            path.display()
        ));
    }
    if !macho_minimum_system_is_26(bytes)? {
        return Err(format!("{} does not require macOS 26.0", path.display()));
    }
    Ok(())
}

fn arm64_macho_slice(bytes: &[u8]) -> Result<&[u8], String> {
    if read_u32(bytes, 0, false)? == 0xfeed_facf {
        return Ok(bytes);
    }
    if read_u32(bytes, 0, true)? != 0xcafe_babe {
        return Err("not a Mach-O executable".to_string());
    }
    let count = read_u32(bytes, 4, true)? as usize;
    for index in 0..count {
        let entry = 8usize
            .checked_add(
                index
                    .checked_mul(20)
                    .ok_or_else(|| "fat Mach-O overflow".to_string())?,
            )
            .ok_or_else(|| "fat Mach-O overflow".to_string())?;
        if read_u32(bytes, entry, true)? != 0x0100_000c {
            continue;
        }
        let offset = read_u32(bytes, entry + 8, true)? as usize;
        let size = read_u32(bytes, entry + 12, true)? as usize;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "fat Mach-O slice overflows".to_string())?;
        return bytes
            .get(offset..end)
            .ok_or_else(|| "fat Mach-O arm64 slice is truncated".to_string());
    }
    Err("Mach-O does not contain an arm64 slice".to_string())
}

fn macho_minimum_system_is_26(bytes: &[u8]) -> Result<bool, String> {
    if read_u32(bytes, 0, false)? != 0xfeed_facf {
        return Ok(false);
    }
    let command_count = read_u32(bytes, 16, false)? as usize;
    let mut offset = 32;
    for _ in 0..command_count {
        let command = read_u32(bytes, offset, false)?;
        let size = read_u32(bytes, offset + 4, false)? as usize;
        if size < 8 {
            return Err("Mach-O load command has an invalid size".to_string());
        }
        if command == 0x32 && read_u32(bytes, offset + 8, false)? == 1 {
            return Ok(read_u32(bytes, offset + 12, false)? == 26 << 16);
        }
        if command == 0x24 {
            return Ok(read_u32(bytes, offset + 8, false)? == 26 << 16);
        }
        offset = offset
            .checked_add(size)
            .ok_or_else(|| "Mach-O load commands overflow".to_string())?;
    }
    Ok(false)
}

fn read_u32(bytes: &[u8], offset: usize, big_endian: bool) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "Mach-O offset overflow".to_string())?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| "Mach-O is truncated".to_string())?
        .try_into()
        .map_err(|_| "Mach-O integer has an invalid length".to_string())?;
    Ok(if big_endian {
        u32::from_be_bytes(value)
    } else {
        u32::from_le_bytes(value)
    })
}

fn resolve_path_helpers<E: ComponentEnvironment>(
    environment: &mut E,
    assets: &Path,
    overrides: &ComponentOverrides,
    considered: &mut Vec<String>,
) -> Result<Option<ResolvedRuntimeComponents>, LibVmError> {
    let Some(path) = environment.get("PATH") else {
        considered.push("PATH unset".to_string());
        return Ok(None);
    };
    for entry in std::env::split_paths(&path) {
        if !entry.is_absolute() {
            continue;
        }
        let paths = ComponentPaths {
            vmmon: entry.join("vmmon"),
            netd: entry.join("netd"),
            krun: entry.join("krun"),
            kernel: assets.join("kernel-default"),
            initramfs: assets.join("initramfs"),
            agent: assets.join("agent"),
        };
        if let Some(components) = consider(
            considered,
            &format!("PATH helper entry {}", entry.display()),
            paths,
            None,
        ) {
            return Ok(Some(overrides.clone().apply_to(components)));
        }
    }
    Ok(None)
}

fn native_candidates() -> Vec<(String, ComponentPaths)> {
    vec![
        (
            "/usr/lib/silo".to_string(),
            ComponentPaths::portable(Path::new("/usr/lib/silo")),
        ),
        (
            "/usr/libexec/silo with /usr/lib64/silo/assets".to_string(),
            ComponentPaths::rhel(
                Path::new("/usr/libexec/silo"),
                Path::new("/usr/lib64/silo/assets"),
            ),
        ),
        (
            "/usr/libexec/silo with /usr/lib/silo/assets".to_string(),
            ComponentPaths::rhel(
                Path::new("/usr/libexec/silo"),
                Path::new("/usr/lib/silo/assets"),
            ),
        ),
        (
            "/usr/local/lib/silo".to_string(),
            ComponentPaths::portable(Path::new("/usr/local/lib/silo")),
        ),
    ]
}

#[cfg(test)]
pub(crate) fn test_components(base: &Path) -> ResolvedRuntimeComponents {
    let paths = ComponentPaths::portable(base);
    ResolvedRuntimeComponents {
        vmmon: paths.vmmon,
        netd: paths.netd,
        krun: paths.krun,
        kernel: paths.kernel,
        initramfs: paths.initramfs,
        agent: paths.agent,
    }
}

#[cfg(target_os = "macos")]
fn sdk_app_candidates() -> Vec<PathBuf> {
    let mut candidates = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| vec![home.join("Applications/Silo.app")])
        .unwrap_or_default();
    candidates.push(PathBuf::from("/Applications/Silo.app"));
    candidates
}

#[cfg(test)]
mod tests {
    use super::{
        resolve_components_with, validate_app_bundle, ComponentEnvironment, ComponentPaths,
        ResolvedRuntimeComponents,
    };
    use crate::{LibVmError, RuntimeConfig};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};

    #[derive(Default)]
    struct TestEnvironment {
        values: BTreeMap<&'static str, OsString>,
        read: Vec<&'static str>,
    }

    impl ComponentEnvironment for TestEnvironment {
        fn get(&mut self, name: &'static str) -> Option<OsString> {
            self.read.push(name);
            self.values.get(name).cloned()
        }
    }

    fn write_file(path: &Path, executable: bool) {
        std::fs::create_dir_all(path.parent().expect("file parent")).expect("create parent");
        std::fs::write(path, b"component").expect("write component");
        let mode = if executable { 0o755 } else { 0o644 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set component mode");
    }

    fn portable(root: &Path) -> ComponentPaths {
        for name in ["vmmon", "netd", "krun"] {
            write_file(&root.join("bin").join(name), true);
        }
        write_file(&root.join("assets/kernel-default"), false);
        write_file(&root.join("assets/initramfs"), false);
        write_file(&root.join("assets/agent"), true);
        ComponentPaths::portable(root)
    }

    fn resolve(
        config: &RuntimeConfig,
        environment: &mut TestEnvironment,
        executable: PathBuf,
        native: Vec<(String, ComponentPaths)>,
    ) -> Result<ResolvedRuntimeComponents, LibVmError> {
        resolve_components_with(config, environment, || Ok(executable), &native)
    }

    #[test]
    fn api_component_overrides_overlay_api_runtime_root() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("runtime");
        portable(&root);
        let vmmon = temp.path().join("custom-vmmon");
        write_file(&vmmon, true);
        let config = RuntimeConfig::default()
            .with_runtime_root(&root)
            .with_vmmon_path(&vmmon);

        let resolved = resolve(
            &config,
            &mut TestEnvironment::default(),
            temp.path().join("silo"),
            vec![],
        )
        .expect("resolve api runtime root");

        assert_eq!(
            resolved.vmmon,
            vmmon.canonicalize().expect("canonical vmmon")
        );
        assert_eq!(
            resolved.netd,
            root.join("bin/netd")
                .canonicalize()
                .expect("canonical netd")
        );
    }

    #[test]
    fn environment_components_overlay_runtime_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("runtime");
        portable(&root);
        let netd = temp.path().join("custom-netd");
        write_file(&netd, true);
        let mut environment = TestEnvironment::default();
        environment
            .values
            .insert("NETD_BIN", netd.clone().into_os_string());
        environment
            .values
            .insert("SILO_RUNTIME_DIR", root.clone().into_os_string());

        let resolved = resolve(
            &RuntimeConfig::default(),
            &mut environment,
            temp.path().join("silo"),
            vec![],
        )
        .expect("resolve environment runtime root");

        assert_eq!(resolved.netd, netd.canonicalize().expect("canonical netd"));
    }

    #[test]
    fn bundled_runtime_precedes_executable_relative_discovery() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bundled = temp.path().join("bundled");
        let portable_root = temp.path().join("portable");
        portable(&bundled);
        portable(&portable_root);
        let executable = portable_root.join("bin/silo");
        write_file(&executable, true);

        let resolved = resolve(
            &RuntimeConfig::default().with_bundled_runtime_root(&bundled),
            &mut TestEnvironment::default(),
            executable,
            vec![],
        )
        .expect("resolve bundled runtime");

        assert_eq!(
            resolved.agent,
            bundled.join("assets/agent").canonicalize().expect("agent")
        );
    }

    #[test]
    fn adjacent_runtime_uses_only_the_executable_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let direct = temp.path().join("debug");
        let parent = temp.path().join("target");
        portable(&parent);
        for name in ["vmmon", "netd", "krun"] {
            write_file(&direct.join(name), true);
        }
        write_file(&direct.join("assets/kernel-default"), false);
        write_file(&direct.join("assets/initramfs"), false);
        write_file(&direct.join("assets/agent"), true);
        let executable = direct.join("silo");
        write_file(&executable, true);

        let resolved = resolve(
            &RuntimeConfig::default(),
            &mut TestEnvironment::default(),
            executable,
            vec![],
        )
        .expect("resolve adjacent runtime");

        assert_eq!(
            resolved.krun,
            direct.join("krun").canonicalize().expect("krun")
        );
    }

    #[test]
    fn portable_runtime_uses_fixed_parent_bin_and_assets_layout() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("portable");
        portable(&root);
        let executable = root.join("bin/silo");
        write_file(&executable, true);

        let resolved = resolve(
            &RuntimeConfig::default(),
            &mut TestEnvironment::default(),
            executable,
            vec![],
        )
        .expect("resolve portable runtime");

        assert_eq!(
            resolved.kernel,
            root.join("assets/kernel-default")
                .canonicalize()
                .expect("kernel")
        );
    }

    #[test]
    fn path_requires_valid_explicit_assets_and_one_complete_entry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let assets = temp.path().join("assets");
        write_file(&assets.join("kernel-default"), false);
        write_file(&assets.join("initramfs"), false);
        write_file(&assets.join("agent"), true);
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        write_file(&first.join("vmmon"), true);
        write_file(&second.join("netd"), true);
        write_file(&second.join("krun"), true);
        let complete = temp.path().join("complete");
        for name in ["vmmon", "netd", "krun"] {
            write_file(&complete.join(name), true);
        }
        let mut environment = TestEnvironment::default();
        environment
            .values
            .insert("SILO_ASSET_DIR", assets.into_os_string());
        environment.values.insert(
            "PATH",
            std::env::join_paths([
                Path::new("relative"),
                first.as_path(),
                second.as_path(),
                complete.as_path(),
            ])
            .expect("PATH"),
        );

        let resolved = resolve(
            &RuntimeConfig::default(),
            &mut environment,
            temp.path().join("silo"),
            vec![],
        )
        .expect("resolve PATH helpers");

        assert_eq!(
            resolved.vmmon,
            complete.join("vmmon").canonicalize().expect("vmmon")
        );
        assert!(environment.read.contains(&"PATH"));
    }

    #[test]
    fn path_is_not_read_without_explicit_assets() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut environment = TestEnvironment::default();
        environment
            .values
            .insert("PATH", temp.path().to_path_buf().into_os_string());

        let error = resolve(
            &RuntimeConfig::default(),
            &mut environment,
            temp.path().join("silo"),
            vec![],
        )
        .expect_err("no runtime should resolve");

        assert!(matches!(
            error,
            LibVmError::RuntimeComponentsNotFound { .. }
        ));
        assert!(!environment.read.contains(&"PATH"));
    }

    #[test]
    fn malformed_authoritative_root_stops_resolution() {
        let temp = tempfile::tempdir().expect("temp dir");
        let fallback = temp.path().join("fallback");
        portable(&fallback);
        let mut environment = TestEnvironment::default();
        environment.values.insert(
            "SILO_RUNTIME_DIR",
            PathBuf::from("relative").into_os_string(),
        );

        let error = resolve(
            &RuntimeConfig::default(),
            &mut environment,
            temp.path().join("silo"),
            vec![("fallback".to_string(), ComponentPaths::portable(&fallback))],
        )
        .expect_err("relative runtime root must fail");

        assert!(matches!(error, LibVmError::RuntimeComponentInvalid { .. }));
    }

    #[test]
    fn portable_component_cannot_escape_root() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("runtime");
        portable(&root);
        let outside = temp.path().join("outside-agent");
        write_file(&outside, true);
        std::fs::remove_file(root.join("assets/agent")).expect("remove agent");
        symlink(&outside, root.join("assets/agent")).expect("link outside agent");

        let error = resolve(
            &RuntimeConfig::default().with_runtime_root(&root),
            &mut TestEnvironment::default(),
            temp.path().join("silo"),
            vec![],
        )
        .expect_err("root escape must fail");

        assert!(matches!(error, LibVmError::RuntimeComponentInvalid { .. }));
        assert!(error.to_string().contains("escapes runtime root"));
    }

    #[test]
    fn native_candidates_are_considered_last() {
        let temp = tempfile::tempdir().expect("temp dir");
        let native = temp.path().join("native");
        portable(&native);

        let resolved = resolve(
            &RuntimeConfig::default(),
            &mut TestEnvironment::default(),
            temp.path().join("silo"),
            vec![("test native".to_string(), ComponentPaths::portable(&native))],
        )
        .expect("resolve native candidate");

        assert_eq!(
            resolved.initramfs,
            native
                .join("assets/initramfs")
                .canonicalize()
                .expect("initramfs")
        );
    }

    fn app_bundle(base: &Path, binary_plist: bool) -> (PathBuf, PathBuf) {
        let bundle = base.join("Silo.app");
        let contents = bundle.join("Contents");
        let executable = contents.join("MacOS/silo");
        write_file(&contents.join("Helpers/vmmon"), true);
        write_file(&contents.join("Helpers/netd"), true);
        write_file(&contents.join("Helpers/krun"), true);
        write_file(&contents.join("Resources/assets/kernel-default"), false);
        write_file(&contents.join("Resources/assets/initramfs"), false);
        write_file(&contents.join("Resources/assets/agent"), true);
        std::fs::create_dir_all(executable.parent().expect("executable parent"))
            .expect("create executable parent");
        let mut macho = vec![0_u8; 56];
        macho[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        macho[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        macho[12..16].copy_from_slice(&2_u32.to_le_bytes());
        macho[16..20].copy_from_slice(&1_u32.to_le_bytes());
        macho[20..24].copy_from_slice(&24_u32.to_le_bytes());
        macho[32..36].copy_from_slice(&0x32_u32.to_le_bytes());
        macho[36..40].copy_from_slice(&24_u32.to_le_bytes());
        macho[40..44].copy_from_slice(&1_u32.to_le_bytes());
        macho[44..48].copy_from_slice(&(26_u32 << 16).to_le_bytes());
        std::fs::write(&executable, macho).expect("write Mach-O executable");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("set executable mode");

        let mut info = plist::Dictionary::new();
        info.insert(
            "CFBundleIdentifier".to_string(),
            plist::Value::String("sh.silo.app".to_string()),
        );
        info.insert(
            "CFBundleExecutable".to_string(),
            plist::Value::String("silo".to_string()),
        );
        info.insert(
            "CFBundleShortVersionString".to_string(),
            plist::Value::String(env!("CARGO_PKG_VERSION").to_string()),
        );
        info.insert(
            "LSMinimumSystemVersion".to_string(),
            plist::Value::String("26.0".to_string()),
        );
        let info = plist::Value::Dictionary(info);
        let info_path = contents.join("Info.plist");
        if binary_plist {
            info.to_file_binary(&info_path).expect("write binary plist");
        } else {
            info.to_file_xml(&info_path).expect("write XML plist");
        }
        (bundle, contents)
    }

    #[test]
    fn app_bundle_validation_accepts_xml_and_binary_plists() {
        let temp = tempfile::tempdir().expect("temp dir");
        for (name, binary_plist) in [("xml", false), ("binary", true)] {
            let (bundle, contents) = app_bundle(&temp.path().join(name), binary_plist);
            validate_app_bundle(&bundle, &contents).expect("validate app bundle");
        }
    }
}
