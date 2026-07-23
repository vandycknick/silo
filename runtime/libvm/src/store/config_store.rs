use async_trait::async_trait;
use sqlx::Row;

use crate::store::models::DbConfig;
use crate::store::{ConfigStore, Store};
use crate::utils::now_unix;
use crate::LibVmError;

const DB_CONFIG_ID: i64 = 1;

#[async_trait]
impl ConfigStore for Store {
    async fn db_config(&self) -> Result<Option<DbConfig>, LibVmError> {
        self.read_single_db_config().await
    }

    async fn read_or_seed_db_config(&self, seed: &DbConfig) -> Result<DbConfig, LibVmError> {
        if let Some(config) = self.read_single_db_config().await? {
            return Ok(config);
        }

        self.insert_db_config(seed).await?;
        self.read_single_db_config()
            .await?
            .ok_or(LibVmError::StateDatabaseConfigMismatch {
                field: "db_config.row_count",
                expected: "1".to_string(),
                actual: "0".to_string(),
            })
    }

    async fn claim_state_root(&self, state_root: &str) -> Result<DbConfig, LibVmError> {
        let now = now_unix();
        sqlx::query(
            "UPDATE db_config SET state_root = ?1, modified_at = ?2
             WHERE id = ?3 AND state_root IS NULL",
        )
        .bind(state_root)
        .bind(now)
        .bind(DB_CONFIG_ID)
        .execute(&self.pool)
        .await?;

        let stored =
            self.read_single_db_config()
                .await?
                .ok_or(LibVmError::StateDatabaseConfigMismatch {
                    field: "db_config.row_count",
                    expected: "1".to_string(),
                    actual: "0".to_string(),
                })?;
        if stored.state_root.as_deref() != Some(state_root) {
            return Err(LibVmError::StateDatabaseConfigMismatch {
                field: "state_root",
                expected: state_root.to_string(),
                actual: stored.state_root.unwrap_or_default(),
            });
        }
        Ok(stored)
    }

    async fn complete_state_root_migration(&self) -> Result<DbConfig, LibVmError> {
        let now = now_unix();
        sqlx::query(
            "UPDATE db_config SET state_migration_complete = 1, modified_at = ?1
             WHERE id = ?2 AND state_root IS NOT NULL",
        )
        .bind(now)
        .bind(DB_CONFIG_ID)
        .execute(&self.pool)
        .await?;
        self.read_single_db_config()
            .await?
            .ok_or(LibVmError::StateDatabaseConfigMismatch {
                field: "db_config.row_count",
                expected: "1".to_string(),
                actual: "0".to_string(),
            })
    }
}

impl Store {
    async fn insert_db_config(&self, seed: &DbConfig) -> Result<(), LibVmError> {
        let now = now_unix();
        sqlx::query(
            "INSERT INTO db_config
                (id, os, data_root, run_root, image_root, state_root,
                 state_migration_complete, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(DB_CONFIG_ID)
        .bind(&seed.os)
        .bind(&seed.data_root)
        .bind(&seed.legacy_run_root)
        .bind(&seed.image_root)
        .bind(&seed.state_root)
        .bind(seed.state_migration_complete)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn read_db_configs(&self) -> Result<Vec<DbConfig>, LibVmError> {
        let rows = sqlx::query(
            "SELECT os, data_root, run_root, image_root, state_root,
                    state_migration_complete
             FROM db_config",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(DbConfig {
                    os: row.try_get("os")?,
                    data_root: row.try_get("data_root")?,
                    legacy_run_root: row.try_get("run_root")?,
                    image_root: row.try_get("image_root")?,
                    state_root: row.try_get("state_root")?,
                    state_migration_complete: row.try_get("state_migration_complete")?,
                })
            })
            .collect()
    }

    async fn read_single_db_config(&self) -> Result<Option<DbConfig>, LibVmError> {
        let mut configs = self.read_db_configs().await?;
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
}
