ALTER TABLE db_config ADD COLUMN state_root TEXT;
ALTER TABLE db_config ADD COLUMN state_migration_complete INTEGER NOT NULL DEFAULT 0;
