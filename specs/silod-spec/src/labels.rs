//! libvm machine labels that mark machines silod owns.
use std::collections::BTreeMap;

pub const MANAGED_ROLE_LABEL: &str = "io.silo.system.role";
pub const MANAGED_ROLE: &str = "system";
pub const INSTALLATION_LABEL: &str = "io.silo.system.installation";

/// Whether silod created the machine: the active system VM, an upgrade candidate,
/// or a qualification VM. For tracking only; nothing is forbidden on these.
pub fn is_system_managed(labels: &BTreeMap<String, String>) -> bool {
    labels.get(MANAGED_ROLE_LABEL).map(String::as_str) == Some(MANAGED_ROLE)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::labels::{is_system_managed, MANAGED_ROLE, MANAGED_ROLE_LABEL};

    #[test]
    fn only_the_system_role_is_managed() {
        let labels = |value: &str| BTreeMap::from([(MANAGED_ROLE_LABEL.to_string(), value.into())]);
        assert!(is_system_managed(&labels(MANAGED_ROLE)));
        assert!(!is_system_managed(&labels("user")));
        assert!(!is_system_managed(&BTreeMap::new()));
    }
}
