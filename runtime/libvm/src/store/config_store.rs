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
}

impl Store {
    async fn insert_db_config(&self, seed: &DbConfig) -> Result<(), LibVmError> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn read_db_configs(&self) -> Result<Vec<DbConfig>, LibVmError> {
        let rows = sqlx::query(
            "SELECT os, data_root, run_root, image_root
             FROM db_config",
        )
        .fetch_all(&self.pool)
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
