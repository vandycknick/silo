CREATE TABLE db_config_without_durable_run_root (
    id                          INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    os                          TEXT NOT NULL,
    data_root                   TEXT NOT NULL,
    run_root                    TEXT,
    image_root                  TEXT NOT NULL,
    state_root                  TEXT,
    state_migration_complete    INTEGER NOT NULL DEFAULT 0,
    created_at                  INTEGER NOT NULL,
    modified_at                 INTEGER NOT NULL
);

INSERT INTO db_config_without_durable_run_root (
    id,
    os,
    data_root,
    run_root,
    image_root,
    state_root,
    state_migration_complete,
    created_at,
    modified_at
)
SELECT
    id,
    os,
    data_root,
    run_root,
    image_root,
    state_root,
    state_migration_complete,
    created_at,
    modified_at
FROM db_config;

DROP TABLE db_config;
ALTER TABLE db_config_without_durable_run_root RENAME TO db_config;

CREATE TRIGGER db_config_created_at_immutable
BEFORE UPDATE OF created_at ON db_config
BEGIN
    SELECT RAISE(ABORT, 'db_config.created_at is immutable');
END;
