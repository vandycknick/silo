use rusqlite::Connection;

use crate::LibVmError;

pub(super) fn run_migrations(conn: &Connection) -> Result<(), LibVmError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS machines (
            id             TEXT PRIMARY KEY,
            name           TEXT NOT NULL UNIQUE,
            instance_dir   TEXT NOT NULL,
            created_at     INTEGER NOT NULL,
            modified_at    INTEGER NOT NULL,
            image_ref      TEXT NOT NULL DEFAULT '',
            labels         BLOB NOT NULL,
            metadata       BLOB NOT NULL,
            network        BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS network_instances (
            id                      TEXT PRIMARY KEY,
            driver                  TEXT NOT NULL,
            definition_name         TEXT,
            runtime_dir             TEXT NOT NULL,
            attachment_json         BLOB NOT NULL,
            driver_state_json       BLOB NOT NULL,
            state                   TEXT NOT NULL,
            created_at              INTEGER NOT NULL,
            modified_at             INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS network_attachments (
            machine_id              TEXT NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
            network_instance_id     TEXT NOT NULL REFERENCES network_instances(id) ON DELETE CASCADE,
            guest_mac               TEXT NOT NULL,
            created_at              INTEGER NOT NULL,
            modified_at             INTEGER NOT NULL,
            PRIMARY KEY (machine_id)
        );
        CREATE TABLE IF NOT EXISTS network_definitions (
            name                    TEXT PRIMARY KEY,
            mode                    TEXT NOT NULL,
            driver_preference       TEXT NOT NULL,
            created_at              INTEGER NOT NULL,
            modified_at             INTEGER NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS machines_created_at_immutable
        BEFORE UPDATE OF created_at ON machines
        BEGIN
            SELECT RAISE(ABORT, 'machines.created_at is immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS network_instances_created_at_immutable
        BEFORE UPDATE OF created_at ON network_instances
        BEGIN
            SELECT RAISE(ABORT, 'network_instances.created_at is immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS network_attachments_created_at_immutable
        BEFORE UPDATE OF created_at ON network_attachments
        BEGIN
            SELECT RAISE(ABORT, 'network_attachments.created_at is immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS network_definitions_created_at_immutable
        BEFORE UPDATE OF created_at ON network_definitions
        BEGIN
            SELECT RAISE(ABORT, 'network_definitions.created_at is immutable');
        END;
        ",
    )?;
    Ok(())
}
