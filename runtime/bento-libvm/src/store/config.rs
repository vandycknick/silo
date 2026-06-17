use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::{Row, SqlitePool};

use crate::paths::LocalRoots;
use crate::LibVmError;

const STATE_SCHEMA_VERSION: i64 = 1;

pub(super) async fn validate(
    pool: &SqlitePool,
    roots: &LocalRoots,
) -> Result<LocalRoots, LibVmError> {
    let expected = ExpectedDbConfig::from_roots(roots);
    let now = now_unix();
    sqlx::query(
        "INSERT INTO db_config
            (id, schema_version, data_dir, state_db_path, created_at, modified_at)
         SELECT 1, ?1, ?2, ?3, ?4, ?4
         WHERE NOT EXISTS (SELECT 1 FROM db_config)",
    )
    .bind(expected.schema_version)
    .bind(&expected.data_dir)
    .bind(&expected.state_db_path)
    .bind(now)
    .execute(pool)
    .await?;

    let rows = sqlx::query(
        "SELECT schema_version, data_dir, state_db_path
         FROM db_config",
    )
    .fetch_all(pool)
    .await?;

    if rows.len() != 1 {
        return Err(LibVmError::StateDatabaseConfigMismatch {
            field: "db_config.row_count",
            expected: "1".to_string(),
            actual: rows.len().to_string(),
        });
    }
    let row = &rows[0];

    let actual = StoredDbConfig {
        schema_version: row.try_get("schema_version")?,
        data_dir: row.try_get("data_dir")?,
        state_db_path: row.try_get("state_db_path")?,
    };

    compare_i64(
        "schema_version",
        expected.schema_version,
        actual.schema_version,
    )?;
    compare_str("data_dir", &expected.data_dir, &actual.data_dir)?;
    compare_str(
        "state_db_path",
        &expected.state_db_path,
        &actual.state_db_path,
    )?;
    Ok(LocalRoots::with_state_db_path(
        actual.data_dir,
        actual.state_db_path,
    ))
}

struct ExpectedDbConfig {
    schema_version: i64,
    data_dir: String,
    state_db_path: String,
}

struct StoredDbConfig {
    schema_version: i64,
    data_dir: String,
    state_db_path: String,
}

impl ExpectedDbConfig {
    fn from_roots(roots: &LocalRoots) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            data_dir: path_to_db_string(roots.data_dir()),
            state_db_path: path_to_db_string(roots.state_db_path()),
        }
    }
}

fn path_to_db_string(path: &Path) -> String {
    path.display().to_string()
}

fn compare_i64(field: &'static str, expected: i64, actual: i64) -> Result<(), LibVmError> {
    if expected == actual {
        return Ok(());
    }
    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn compare_str(field: &'static str, expected: &str, actual: &str) -> Result<(), LibVmError> {
    if expected == actual {
        return Ok(());
    }
    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
