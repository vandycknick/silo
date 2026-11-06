CREATE TABLE db_config (
    id                  INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    os                  TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    modified_at         INTEGER NOT NULL
);

-- Current machine_config JSON has no machineDir field. Private machine paths
-- are derived from this catalog's current home and its indexed machine ID.
CREATE TABLE machine_config (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    config_json         BLOB NOT NULL
);

CREATE TABLE machine_state (
    machine_id          TEXT PRIMARY KEY REFERENCES machine_config(id) ON DELETE CASCADE,
    status              TEXT NOT NULL,
    state_json          BLOB NOT NULL
);

-- Command history is immutable intent plus a separately retained response.
-- Current pause authority is deliberately not derived from historical results.
CREATE TABLE live_command (
    machine_id TEXT NOT NULL REFERENCES machine_config(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    monitor_id TEXT NOT NULL,
    input_json BLOB NOT NULL,
    result_json BLOB,
    PRIMARY KEY (machine_id, run_id, request_id)
);
CREATE INDEX live_command_pending ON live_command(machine_id, run_id)
WHERE result_json IS NULL;
CREATE TRIGGER live_command_intent_immutable
BEFORE UPDATE OF machine_id, run_id, request_id, monitor_id, input_json ON live_command
BEGIN SELECT RAISE(ABORT, 'live command intent is immutable'); END;
CREATE TRIGGER live_command_result_immutable
BEFORE UPDATE OF result_json ON live_command WHEN OLD.result_json IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'live command result is immutable'); END;
CREATE TABLE live_run (
    machine_id TEXT PRIMARY KEY NOT NULL REFERENCES machine_config(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    monitor_id TEXT NOT NULL,
    projection_json BLOB NOT NULL
);
CREATE TABLE live_operation (
    machine_id TEXT NOT NULL REFERENCES machine_config(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    monitor_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    terminal INTEGER NOT NULL CHECK (terminal IN (0,1)),
    record_json BLOB NOT NULL,
    PRIMARY KEY (machine_id, run_id, operation_id)
);
CREATE TRIGGER live_operation_terminal_immutable
BEFORE UPDATE ON live_operation WHEN OLD.terminal = 1
BEGIN SELECT RAISE(ABORT, 'terminal live operation is immutable'); END;
CREATE TRIGGER live_run_authority_follows_machine
AFTER UPDATE ON machine_state
BEGIN
    DELETE FROM live_run WHERE machine_id = NEW.machine_id AND (
        NEW.status IN ('stopped', 'stopping') OR
        CASE WHEN json_valid(NEW.state_json, 8) THEN
            json_extract(NEW.state_json, '$.vmmonPid') IS NULL OR
            run_id IS NOT json_extract(NEW.state_json, '$.runId')
        ELSE 1 END
    );
END;

CREATE TABLE network_instances (
    id                      TEXT PRIMARY KEY,
    driver                  TEXT NOT NULL,
    definition_name         TEXT,
    attachment_json         BLOB NOT NULL,
    driver_state_json       BLOB NOT NULL,
    state                   TEXT NOT NULL,
    created_at              INTEGER NOT NULL,
    modified_at             INTEGER NOT NULL
);

CREATE UNIQUE INDEX network_instances_definition_name_unique
ON network_instances(definition_name)
WHERE definition_name IS NOT NULL;

CREATE TABLE network_attachments (
    machine_id              TEXT NOT NULL REFERENCES machine_config(id) ON DELETE CASCADE,
    network_instance_id     TEXT NOT NULL REFERENCES network_instances(id) ON DELETE CASCADE,
    guest_mac               TEXT NOT NULL,
    created_at              INTEGER NOT NULL,
    modified_at             INTEGER NOT NULL,
    PRIMARY KEY (machine_id)
);

CREATE TABLE network_definitions (
    name                    TEXT PRIMARY KEY,
    mode                    TEXT NOT NULL,
    driver_preference       TEXT NOT NULL,
    created_at              INTEGER NOT NULL,
    modified_at             INTEGER NOT NULL
);

CREATE TRIGGER db_config_created_at_immutable
BEFORE UPDATE OF created_at ON db_config
BEGIN
    SELECT RAISE(ABORT, 'db_config.created_at is immutable');
END;

CREATE TRIGGER network_instances_created_at_immutable
BEFORE UPDATE OF created_at ON network_instances
BEGIN
    SELECT RAISE(ABORT, 'network_instances.created_at is immutable');
END;

CREATE TRIGGER network_attachments_created_at_immutable
BEFORE UPDATE OF created_at ON network_attachments
BEGIN
    SELECT RAISE(ABORT, 'network_attachments.created_at is immutable');
END;

CREATE TRIGGER network_definitions_created_at_immutable
BEFORE UPDATE OF created_at ON network_definitions
BEGIN
    SELECT RAISE(ABORT, 'network_definitions.created_at is immutable');
END;

CREATE TABLE image_manifest (
    digest                  TEXT PRIMARY KEY,
    media_type              TEXT NOT NULL,
    image_id                TEXT NOT NULL,
    platform_os             TEXT NOT NULL,
    platform_architecture   TEXT NOT NULL,
    platform_variant        TEXT,
    config_digest           TEXT NOT NULL,
    layer_count             INTEGER NOT NULL,
    total_size_bytes        INTEGER NOT NULL,
    created_at              INTEGER NOT NULL,
    last_used_at            INTEGER
);

CREATE TABLE image_ref (
    requested_reference     TEXT PRIMARY KEY,
    selected_reference      TEXT NOT NULL,
    manifest_digest         TEXT NOT NULL REFERENCES image_manifest(digest) ON DELETE RESTRICT,
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,
    last_used_at            INTEGER
);

CREATE TABLE image_config (
    manifest_digest         TEXT PRIMARY KEY REFERENCES image_manifest(digest) ON DELETE CASCADE,
    digest                  TEXT NOT NULL,
    env_json                BLOB,
    cmd_json                BLOB,
    entrypoint_json         BLOB,
    working_dir             TEXT,
    user                    TEXT,
    labels_json             BLOB,
    stop_signal             TEXT,
    created_at              INTEGER NOT NULL
);

CREATE TABLE image_layer (
    diff_id                 TEXT NOT NULL,
    blob_digest             TEXT NOT NULL,
    compressed_size_bytes   INTEGER,
    uncompressed_size_bytes INTEGER,
    created_at              INTEGER NOT NULL,
    last_used_at            INTEGER,
    PRIMARY KEY (diff_id, blob_digest)
);

CREATE TABLE image_manifest_layer (
    manifest_digest         TEXT NOT NULL REFERENCES image_manifest(digest) ON DELETE CASCADE,
    layer_diff_id           TEXT NOT NULL,
    layer_blob_digest       TEXT NOT NULL,
    media_type              TEXT NOT NULL,
    position                INTEGER NOT NULL,
    PRIMARY KEY (manifest_digest, position),
    FOREIGN KEY (layer_diff_id, layer_blob_digest) REFERENCES image_layer(diff_id, blob_digest) ON DELETE RESTRICT,
    CHECK (position >= 0)
);

CREATE TABLE image_rootfs_artifact (
    image_id                TEXT PRIMARY KEY,
    manifest_digest         TEXT NOT NULL REFERENCES image_manifest(digest) ON DELETE RESTRICT,
    config_digest           TEXT NOT NULL,
    platform_os             TEXT NOT NULL,
    platform_architecture   TEXT NOT NULL,
    platform_variant        TEXT,
    filesystem              TEXT NOT NULL,
    rootfs_path             TEXT NOT NULL,
    size_bytes              INTEGER NOT NULL,
    created_at              INTEGER NOT NULL,
    last_used_at            INTEGER,
    stream_id               TEXT NOT NULL,
    conversion_abi          TEXT NOT NULL
);

CREATE TABLE machine_rootfs (
    machine_id              TEXT PRIMARY KEY REFERENCES machine_config(id) ON DELETE CASCADE,
    source_kind             TEXT NOT NULL CHECK (source_kind IN ('oci', 'disk')),
    requested_reference     TEXT NOT NULL,
    selected_reference      TEXT,
    manifest_digest         TEXT,
    config_digest           TEXT,
    image_id                TEXT,
    created_at              INTEGER NOT NULL
);

CREATE INDEX image_ref_manifest_digest_idx
ON image_ref(manifest_digest);

CREATE INDEX image_manifest_layer_layer_diff_id_idx
ON image_manifest_layer(layer_diff_id);

CREATE INDEX image_rootfs_artifact_manifest_digest_idx
ON image_rootfs_artifact(manifest_digest);

CREATE INDEX machine_rootfs_manifest_digest_idx
ON machine_rootfs(manifest_digest);

CREATE TRIGGER image_manifest_created_at_immutable
BEFORE UPDATE OF created_at ON image_manifest
BEGIN
    SELECT RAISE(ABORT, 'image_manifest.created_at is immutable');
END;

CREATE TRIGGER image_ref_created_at_immutable
BEFORE UPDATE OF created_at ON image_ref
BEGIN
    SELECT RAISE(ABORT, 'image_ref.created_at is immutable');
END;

CREATE TRIGGER image_config_created_at_immutable
BEFORE UPDATE OF created_at ON image_config
BEGIN
    SELECT RAISE(ABORT, 'image_config.created_at is immutable');
END;

CREATE TRIGGER image_layer_created_at_immutable
BEFORE UPDATE OF created_at ON image_layer
BEGIN
    SELECT RAISE(ABORT, 'image_layer.created_at is immutable');
END;

CREATE TRIGGER image_rootfs_artifact_created_at_immutable
BEFORE UPDATE OF created_at ON image_rootfs_artifact
BEGIN
    SELECT RAISE(ABORT, 'image_rootfs_artifact.created_at is immutable');
END;

CREATE TRIGGER machine_rootfs_created_at_immutable
BEFORE UPDATE OF created_at ON machine_rootfs
BEGIN
    SELECT RAISE(ABORT, 'machine_rootfs.created_at is immutable');
END;

CREATE TABLE machine_storage (
    machine_id TEXT PRIMARY KEY NOT NULL REFERENCES machine_config(id) ON DELETE CASCADE,
    record_json BLOB NOT NULL
);


CREATE TABLE storage_operation (
    operation_id TEXT PRIMARY KEY NOT NULL,
    schema INTEGER NOT NULL CHECK (schema = 1),
    kind TEXT NOT NULL CHECK (kind IN ('import', 'convert', 'snapshot', 'capture', 'fork', 'relocate', 'update-boot-assets', 'launch')),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'staging', 'committing', 'cleaning', 'committed', 'aborted')),
    machine_id TEXT,
    run_id TEXT,
    storage_generation INTEGER,
    file_device TEXT NOT NULL,
    file_inode TEXT NOT NULL,
    record_json BLOB NOT NULL,
    CHECK (kind != 'launch' OR (machine_id IS NOT NULL AND run_id IS NOT NULL AND storage_generation IS NOT NULL AND storage_generation >= 0))
);
CREATE INDEX storage_operation_machine_idx ON storage_operation(machine_id);
CREATE TABLE storage_operation_stream (
    operation_id TEXT NOT NULL REFERENCES storage_operation(operation_id) ON DELETE CASCADE,
    stream_id TEXT NOT NULL,
    PRIMARY KEY (operation_id, stream_id)
);
CREATE INDEX storage_operation_stream_reverse_idx ON storage_operation_stream(stream_id, operation_id);
CREATE TABLE storage_operation_object (
    operation_id TEXT NOT NULL REFERENCES storage_operation(operation_id) ON DELETE CASCADE,
    object_digest TEXT NOT NULL,
    PRIMARY KEY (operation_id, object_digest)
);
CREATE INDEX storage_operation_object_reverse_idx ON storage_operation_object(object_digest, operation_id);

CREATE TABLE image_stream_gc (
    stream_id TEXT PRIMARY KEY NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0)
);

CREATE TABLE layer_recipe (
    id TEXT PRIMARY KEY NOT NULL,
    diff_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_bytes BLOB NOT NULL
);
CREATE TABLE layer_result (
    id TEXT PRIMARY KEY NOT NULL,
    recipe_id TEXT NOT NULL UNIQUE REFERENCES layer_recipe(id) ON DELETE RESTRICT,
    pack_stream TEXT NOT NULL,
    pack_length INTEGER NOT NULL CHECK (pack_length >= 0),
    index_root TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_bytes BLOB NOT NULL
);
CREATE TABLE layer_object_dependency (
    result_id TEXT NOT NULL REFERENCES layer_result(id) ON DELETE CASCADE,
    object_digest TEXT NOT NULL,
    PRIMARY KEY (result_id, object_digest)
);
CREATE INDEX layer_object_dependency_digest_idx
ON layer_object_dependency(object_digest, result_id);
CREATE TABLE layer_occurrence_set (
    owner_digest TEXT PRIMARY KEY NOT NULL,
    layer_count INTEGER NOT NULL CHECK (layer_count >= 0 AND layer_count <= 1024)
);
CREATE TABLE layer_occurrence (
    owner_digest TEXT NOT NULL REFERENCES layer_occurrence_set(owner_digest) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 0 AND position < 1024),
    result_id TEXT NOT NULL REFERENCES layer_result(id) ON DELETE RESTRICT,
    PRIMARY KEY (owner_digest, position)
);
CREATE TABLE storage_operation_layer (
    operation_id TEXT NOT NULL REFERENCES storage_operation(operation_id) ON DELETE CASCADE,
    result_id TEXT NOT NULL REFERENCES layer_result(id) ON DELETE RESTRICT,
    PRIMARY KEY (operation_id, result_id)
);
CREATE INDEX storage_operation_layer_reverse_idx ON storage_operation_layer(result_id, operation_id);
CREATE TRIGGER layer_recipe_immutable BEFORE UPDATE ON layer_recipe
BEGIN SELECT RAISE(ABORT, 'layer recipe is immutable'); END;
CREATE TRIGGER layer_result_immutable BEFORE UPDATE ON layer_result
BEGIN SELECT RAISE(ABORT, 'layer result is immutable'); END;
CREATE TRIGGER layer_dependency_immutable BEFORE UPDATE ON layer_object_dependency
BEGIN SELECT RAISE(ABORT, 'layer dependency is immutable'); END;
CREATE TRIGGER layer_occurrence_set_immutable BEFORE UPDATE ON layer_occurrence_set
BEGIN SELECT RAISE(ABORT, 'layer occurrence set is immutable'); END;
CREATE TRIGGER layer_occurrence_immutable BEFORE UPDATE ON layer_occurrence
BEGIN SELECT RAISE(ABORT, 'layer occurrence is immutable'); END;

-- Immutable storage and execution artifacts. Names are image: aliases;
-- explicit retention is independent of every alias.
CREATE TABLE storage_snapshot (
    id TEXT PRIMARY KEY NOT NULL,
    record_digest TEXT NOT NULL,
    record_bytes BLOB NOT NULL,
    retained INTEGER NOT NULL CHECK (retained IN (0, 1)),
    created_at INTEGER NOT NULL
);
CREATE TABLE image_alias (
    name TEXT PRIMARY KEY NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES storage_snapshot(id) ON DELETE RESTRICT
);
CREATE INDEX image_alias_snapshot_idx ON image_alias(snapshot_id);
CREATE TABLE snapshot_stream_dependency (
    snapshot_id TEXT NOT NULL REFERENCES storage_snapshot(id) ON DELETE CASCADE,
    stream_id TEXT NOT NULL,
    PRIMARY KEY(snapshot_id, stream_id)
);
CREATE INDEX snapshot_stream_reverse_idx ON snapshot_stream_dependency(stream_id, snapshot_id);
CREATE TABLE snapshot_object_dependency (
    snapshot_id TEXT NOT NULL REFERENCES storage_snapshot(id) ON DELETE CASCADE,
    object_digest TEXT NOT NULL,
    PRIMARY KEY(snapshot_id, object_digest)
);
CREATE INDEX snapshot_object_reverse_idx ON snapshot_object_dependency(object_digest, snapshot_id);
CREATE TRIGGER storage_snapshot_identity_immutable
BEFORE UPDATE OF id, record_digest, record_bytes, created_at ON storage_snapshot
BEGIN SELECT RAISE(ABORT, 'snapshot identity is immutable'); END;
CREATE TRIGGER snapshot_stream_dependency_immutable BEFORE UPDATE ON snapshot_stream_dependency
BEGIN SELECT RAISE(ABORT, 'snapshot stream dependency is immutable'); END;
CREATE TRIGGER snapshot_object_dependency_immutable BEFORE UPDATE ON snapshot_object_dependency
BEGIN SELECT RAISE(ABORT, 'snapshot object dependency is immutable'); END;

-- Provenance is authenticated independently, never mixed into snapshot identity.
CREATE TABLE snapshot_capture_provenance (
    capture_id TEXT PRIMARY KEY NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES storage_snapshot(id) ON DELETE CASCADE,
    evidence_digest TEXT NOT NULL,
    evidence_bytes BLOB NOT NULL
);
CREATE INDEX snapshot_capture_provenance_reverse_idx ON snapshot_capture_provenance(evidence_digest, snapshot_id);
CREATE TRIGGER snapshot_capture_provenance_immutable BEFORE UPDATE ON snapshot_capture_provenance
BEGIN SELECT RAISE(ABORT, 'capture provenance is immutable'); END;
