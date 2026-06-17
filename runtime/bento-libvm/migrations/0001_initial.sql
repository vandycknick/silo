CREATE TABLE IF NOT EXISTS db_config (
    id                  INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    schema_version      INTEGER NOT NULL,
    os                  TEXT NOT NULL,
    data_root           TEXT NOT NULL,
    run_root            TEXT NOT NULL,
    image_root          TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    modified_at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS machine_config (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    config_json         BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS machine_state (
    machine_id          TEXT PRIMARY KEY REFERENCES machine_config(id) ON DELETE CASCADE,
    status              TEXT NOT NULL,
    state_json          BLOB NOT NULL
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
    machine_id              TEXT NOT NULL REFERENCES machine_config(id) ON DELETE CASCADE,
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

CREATE TRIGGER IF NOT EXISTS db_config_created_at_immutable
BEFORE UPDATE OF created_at ON db_config
BEGIN
    SELECT RAISE(ABORT, 'db_config.created_at is immutable');
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
