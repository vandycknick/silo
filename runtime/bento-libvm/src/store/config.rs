use std::env::consts::OS;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::{Row, SqlitePool};

use crate::paths::LocalRoots;
use crate::store::models::DbConfig;
use crate::{LibVmError, PathChoice, RuntimeConfig};

const DB_CONFIG_ID: i64 = 1;

pub(super) fn validate_roots_absolute(roots: &LocalRoots) -> Result<(), LibVmError> {
    validate_absolute_path("data_root", roots.data_root())?;
    validate_absolute_path("run_root", roots.run_root())?;
    validate_absolute_path("image_root", roots.image_root())
}

pub(super) async fn open(
    pool: &SqlitePool,
    opened_db_path: &Path,
    runtime_config: &RuntimeConfig,
) -> Result<LocalRoots, LibVmError> {
    let stored = match read_single_config(pool).await? {
        Some(stored) => stored,
        None => {
            let seed_roots = runtime_config.resolve_roots()?;
            validate_roots_absolute(&seed_roots)?;
            read_or_seed(pool, &DbConfig::from_roots(&seed_roots)).await?
        }
    };
    validate_header(&stored)?;
    let roots = merge_roots(runtime_config, &stored)?;
    validate_roots_absolute(&roots)?;
    validate_roots_match_config(&roots, &stored)?;
    compare_path("state_db_path", &roots.state_db_path(), opened_db_path)?;
    Ok(roots)
}

#[cfg(test)]
pub(super) async fn validate(
    pool: &SqlitePool,
    opened_db_path: &Path,
    roots: &LocalRoots,
) -> Result<LocalRoots, LibVmError> {
    validate_roots_absolute(roots)?;
    let stored = read_or_seed(pool, &DbConfig::from_roots(roots)).await?;
    validate_header(&stored)?;
    validate_roots_match_config(roots, &stored)?;
    compare_path("state_db_path", &roots.state_db_path(), opened_db_path)?;
    Ok(roots.clone())
}

async fn read_or_seed(pool: &SqlitePool, seed: &DbConfig) -> Result<DbConfig, LibVmError> {
    if let Some(config) = read_single_config(pool).await? {
        return Ok(config);
    }

    insert_seed(pool, seed).await?;
    read_single_config(pool)
        .await?
        .ok_or(LibVmError::StateDatabaseConfigMismatch {
            field: "db_config.row_count",
            expected: "1".to_string(),
            actual: "0".to_string(),
        })
}

async fn insert_seed(pool: &SqlitePool, seed: &DbConfig) -> Result<(), LibVmError> {
    let now = now_unix();
    sqlx::query(
        "INSERT INTO db_config
            (id, os, data_root, run_root, image_root, created_at, modified_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(DB_CONFIG_ID)
    .bind(&seed.os)
    .bind(&seed.data_root)
    .bind(&seed.run_root)
    .bind(&seed.image_root)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

async fn read_configs(pool: &SqlitePool) -> Result<Vec<DbConfig>, LibVmError> {
    let rows = sqlx::query(
        "SELECT os, data_root, run_root, image_root
         FROM db_config",
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(DbConfig {
                os: row.try_get("os")?,
                data_root: row.try_get("data_root")?,
                run_root: row.try_get("run_root")?,
                image_root: row.try_get("image_root")?,
            })
        })
        .collect()
}

async fn read_single_config(pool: &SqlitePool) -> Result<Option<DbConfig>, LibVmError> {
    let mut configs = read_configs(pool).await?;
    match configs.len() {
        0 => Ok(None),
        1 => Ok(configs.pop()),
        count => Err(LibVmError::StateDatabaseConfigMismatch {
            field: "db_config.row_count",
            expected: "1".to_string(),
            actual: count.to_string(),
        }),
    }
}

fn validate_header(config: &DbConfig) -> Result<(), LibVmError> {
    compare_str("os", OS, &config.os)
}

fn path_to_db_string(path: &Path) -> String {
    path.display().to_string()
}

fn merge_roots(
    runtime_config: &RuntimeConfig,
    stored: &DbConfig,
) -> Result<LocalRoots, LibVmError> {
    let data_root = merge_root(
        "data_root",
        &runtime_config.data_root,
        Path::new(&stored.data_root),
    )?;
    let run_root = merge_root(
        "run_root",
        &runtime_config.run_root,
        Path::new(&stored.run_root),
    )?;
    let image_root = merge_root(
        "image_root",
        &runtime_config.image_root,
        Path::new(&stored.image_root),
    )?;

    Ok(LocalRoots::with_roots(data_root, run_root, image_root))
}

fn merge_root(
    field: &'static str,
    choice: &PathChoice,
    stored: &Path,
) -> Result<PathBuf, LibVmError> {
    match choice {
        PathChoice::Default => Ok(stored.to_path_buf()),
        PathChoice::Explicit(path) => {
            compare_path(field, path, stored)?;
            Ok(path.clone())
        }
    }
}

fn validate_roots_match_config(roots: &LocalRoots, config: &DbConfig) -> Result<(), LibVmError> {
    compare_path("data_root", roots.data_root(), Path::new(&config.data_root))?;
    compare_path("run_root", roots.run_root(), Path::new(&config.run_root))?;
    compare_path(
        "image_root",
        roots.image_root(),
        Path::new(&config.image_root),
    )
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

fn compare_path(field: &'static str, expected: &Path, actual: &Path) -> Result<(), LibVmError> {
    let expected = path_for_compare(field, expected)?;
    let actual = path_for_compare(field, actual)?;
    if expected == actual {
        return Ok(());
    }

    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: path_to_db_string(&expected),
        actual: path_to_db_string(&actual),
    })
}

fn path_for_compare(field: &'static str, path: &Path) -> Result<PathBuf, LibVmError> {
    validate_absolute_path(field, path)?;
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(normalize_absolute_path(path)),
        Err(err) => Err(LibVmError::Io(err)),
    }
}

fn validate_absolute_path(field: &'static str, path: &Path) -> Result<(), LibVmError> {
    if path.is_absolute() {
        return Ok(());
    }

    Err(LibVmError::StateDatabaseConfigMismatch {
        field,
        expected: "absolute path".to_string(),
        actual: path_to_db_string(path),
    })
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
