use std::env::consts::OS;

/// Stored host contract for a local Silo state database.
///
/// The `db_config` table contains exactly one row, `id = 1`, recording the host
/// OS that created the database. Paths are not stored: `state.db` always lives
/// at `<home>/state.db` and every other location derives from the home and the
/// fixed run root. Schema compatibility belongs to sqlx migrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DbConfig {
    pub(crate) os: String,
}

impl DbConfig {
    pub(crate) fn current() -> Self {
        Self { os: OS.to_string() }
    }
}
