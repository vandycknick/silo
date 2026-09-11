pub(crate) mod config;
pub(crate) mod ownership;
pub(crate) mod provision;
pub(crate) mod record;
pub(crate) mod storage;

pub(crate) const SYSTEM_MACHINE_NAME: &str = "silo-system";
pub(crate) const MANAGED_ROLE_LABEL: &str = "io.silo.system.role";
pub(crate) const INSTALLATION_LABEL: &str = "io.silo.system.installation";
pub(crate) const MANAGED_ROLE: &str = "system";
