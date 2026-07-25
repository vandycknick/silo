use std::env::consts::OS;
use std::path::Path;

use crate::paths::LocalRoots;

/// Stored root contract for a local Silo state database.
///
/// The `db_config` table contains exactly one row, `id = 1`. It stores the
/// host OS that created the database and the durable roots that are
/// independently configurable:
///
/// - `data_root`: persistent machine metadata, assets, keys, and `state.db`
/// - `image_root`: unpacked machine images
/// - `state_root`: durable logs and operational state
///
/// Derived paths are intentionally not persisted. `state.db` is always
/// `data_root/state.db`; machines, assets, keys, and secrets live below
/// `data_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DbConfig {
    pub(crate) os: String,
    pub(crate) data_root: String,
    pub(crate) image_root: String,
    pub(crate) state_root: String,
}

impl DbConfig {
    pub(crate) fn from_roots(roots: &LocalRoots) -> Self {
        Self {
            os: OS.to_string(),
            data_root: path_to_db_string(roots.data_root()),
            image_root: path_to_db_string(roots.image_root()),
            state_root: path_to_db_string(roots.state_root()),
        }
    }
}

fn path_to_db_string(path: &Path) -> String {
    path.display().to_string()
}
