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
    source_kind             TEXT NOT NULL CHECK (source_kind IN ('oci', 'disk', 'managed')),
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
CREATE TABLE machine_stream_dependency (
    machine_id TEXT NOT NULL REFERENCES machine_storage(machine_id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(generation>=0),
    stream_id TEXT NOT NULL,
    PRIMARY KEY(machine_id,stream_id)
);
CREATE INDEX machine_stream_reverse ON machine_stream_dependency(stream_id,machine_id);
CREATE TABLE machine_object_dependency (
    machine_id TEXT NOT NULL REFERENCES machine_storage(machine_id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(generation>=0),
    object_digest TEXT NOT NULL,
    PRIMARY KEY(machine_id,object_digest)
);
CREATE INDEX machine_object_reverse ON machine_object_dependency(object_digest,machine_id);


CREATE TABLE storage_operation (
    operation_id TEXT PRIMARY KEY NOT NULL,
    schema INTEGER NOT NULL CHECK (schema = 1),
    kind TEXT NOT NULL CHECK (kind IN ('import', 'convert', 'snapshot', 'capture', 'fork', 'live-fork', 'relocate', 'update-boot-assets', 'launch')),
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
CREATE TABLE restore_memory_reservation (
    operation_id TEXT PRIMARY KEY NOT NULL REFERENCES storage_operation(operation_id) ON DELETE CASCADE,
    budget_id TEXT UNIQUE NOT NULL,
    charge_json BLOB NOT NULL,
    construction_json BLOB,
    batch_id TEXT REFERENCES live_fork(operation_id) ON DELETE RESTRICT
);
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
CREATE TABLE storage_operation_managed (
    operation_id TEXT NOT NULL REFERENCES storage_operation(operation_id) ON DELETE CASCADE,
    managed_kind TEXT NOT NULL CHECK(managed_kind IN ('image','snapshot')),
    managed_id TEXT NOT NULL,
    PRIMARY KEY(operation_id,managed_kind,managed_id)
);
CREATE INDEX storage_operation_managed_reverse ON storage_operation_managed(managed_kind,managed_id,operation_id);

CREATE TABLE storage_cache_entry (
    kind TEXT NOT NULL CHECK(kind IN ('source-blob','transport')),
    digest TEXT NOT NULL,
    size_bytes INTEGER CHECK(size_bytes >= 0),
    last_used_at INTEGER NOT NULL,
    PRIMARY KEY(kind,digest)
);
CREATE TABLE storage_operation_cache (
    operation_id TEXT NOT NULL REFERENCES storage_operation(operation_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('source-blob','transport')),
    digest TEXT NOT NULL,
    PRIMARY KEY(operation_id,kind,digest),
    FOREIGN KEY(kind,digest) REFERENCES storage_cache_entry(kind,digest) ON DELETE RESTRICT
);
CREATE INDEX storage_operation_cache_reverse ON storage_operation_cache(kind,digest,operation_id);

CREATE TABLE storage_stream (
    stream_id TEXT PRIMARY KEY NOT NULL,
    length INTEGER NOT NULL CHECK(length >= 0),
    map_digest TEXT NOT NULL,
    flat_state TEXT NOT NULL CHECK(flat_state IN ('present','evicting','absent'))
);
CREATE TABLE stream_representation (
    stream_id TEXT NOT NULL REFERENCES storage_stream(stream_id) ON DELETE CASCADE,
    root_digest TEXT NOT NULL,
    PRIMARY KEY(stream_id,root_digest)
);
CREATE TABLE stream_representation_profile (
    stream_id TEXT NOT NULL,
    root_digest TEXT NOT NULL,
    encoding TEXT NOT NULL CHECK(encoding IN ('raw','zstd')),
    PRIMARY KEY(stream_id,root_digest,encoding),
    FOREIGN KEY(stream_id,root_digest) REFERENCES stream_representation(stream_id,root_digest) ON DELETE CASCADE
);
CREATE TABLE object_stream_representation (
    object_digest TEXT PRIMARY KEY NOT NULL,
    stream_id TEXT UNIQUE NOT NULL REFERENCES storage_stream(stream_id) ON DELETE CASCADE
);
CREATE TRIGGER stream_representation_profile_immutable BEFORE UPDATE ON stream_representation_profile
BEGIN SELECT RAISE(ABORT,'stream encoding profile is immutable'); END;
CREATE TRIGGER object_stream_representation_immutable BEFORE UPDATE ON object_stream_representation
BEGIN SELECT RAISE(ABORT,'object stream binding is immutable'); END;
CREATE TABLE stream_representation_object (
    stream_id TEXT NOT NULL,
    root_digest TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    PRIMARY KEY(stream_id,root_digest,object_digest),
    FOREIGN KEY(stream_id,root_digest) REFERENCES stream_representation(stream_id,root_digest) ON DELETE CASCADE
);
CREATE INDEX stream_representation_object_reverse ON stream_representation_object(object_digest,stream_id);
CREATE TRIGGER storage_stream_identity_immutable BEFORE UPDATE OF stream_id,length,map_digest ON storage_stream
BEGIN SELECT RAISE(ABORT,'stream identity is immutable'); END;
CREATE TRIGGER stream_representation_immutable BEFORE UPDATE ON stream_representation
BEGIN SELECT RAISE(ABORT,'stream representation is immutable'); END;
CREATE TRIGGER stream_representation_object_immutable BEFORE UPDATE ON stream_representation_object
BEGIN SELECT RAISE(ABORT,'stream representation edge is immutable'); END;

-- Results survive source deletion and retirement of operation roots.
CREATE TABLE live_fork (
    operation_id TEXT PRIMARY KEY NOT NULL,
    capture_id TEXT UNIQUE NOT NULL,
    cancellation_id TEXT UNIQUE NOT NULL,
    request_json BLOB NOT NULL,
    observation_json BLOB NOT NULL,
    result_json BLOB NOT NULL,
    admission_complete INTEGER NOT NULL DEFAULT 0 CHECK(admission_complete IN (0,1))
);
CREATE TABLE live_fork_child (
    operation_id TEXT NOT NULL REFERENCES live_fork(operation_id) ON DELETE RESTRICT,
    child_index INTEGER NOT NULL CHECK(child_index >= 0),
    name TEXT NOT NULL,
    machine_id TEXT UNIQUE NOT NULL,
    run_id TEXT UNIQUE NOT NULL,
    activation_id TEXT UNIQUE NOT NULL,
    consumer_id TEXT UNIQUE NOT NULL,
    launch_id TEXT UNIQUE,
    submitted INTEGER NOT NULL DEFAULT 0 CHECK(submitted IN (0,1)),
    result_json BLOB NOT NULL,
    failure_json BLOB,
    name_reserved INTEGER NOT NULL DEFAULT 1 CHECK(name_reserved IN (0,1)),
    PRIMARY KEY(operation_id,child_index)
);
CREATE UNIQUE INDEX live_fork_reserved_name ON live_fork_child(name) WHERE name_reserved=1;
CREATE TRIGGER live_fork_child_failure_immutable BEFORE UPDATE OF failure_json ON live_fork_child
WHEN OLD.failure_json IS NOT NULL
BEGIN SELECT RAISE(ABORT,'live fork child failure is immutable'); END;
CREATE TRIGGER machine_config_fork_reserved_insert BEFORE INSERT ON machine_config
WHEN EXISTS(SELECT 1 FROM live_fork_child WHERE name=NEW.name AND name_reserved=1 AND machine_id!=NEW.id)
BEGIN SELECT RAISE(ABORT,'machine name reserved by live fork'); END;
CREATE TRIGGER machine_config_fork_reserved_update BEFORE UPDATE OF name ON machine_config
WHEN EXISTS(SELECT 1 FROM live_fork_child WHERE name=NEW.name AND name_reserved=1 AND machine_id!=NEW.id)
BEGIN SELECT RAISE(ABORT,'machine name reserved by live fork'); END;
CREATE TABLE local_cut (
    cut_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT UNIQUE NOT NULL REFERENCES live_fork(operation_id) ON DELETE RESTRICT,
    record_json BLOB NOT NULL
);
CREATE TABLE storage_operation_cut (
    operation_id TEXT NOT NULL REFERENCES storage_operation(operation_id) ON DELETE CASCADE,
    cut_id TEXT NOT NULL REFERENCES local_cut(cut_id) ON DELETE RESTRICT,
    PRIMARY KEY(operation_id,cut_id)
);
CREATE INDEX storage_operation_cut_reverse ON storage_operation_cut(cut_id,operation_id);
CREATE TABLE capture_resource_reservation (
    operation_id TEXT PRIMARY KEY NOT NULL REFERENCES storage_operation(operation_id) ON DELETE CASCADE,
    charge_json BLOB NOT NULL
);
CREATE TABLE fork_event (
    operation_id TEXT NOT NULL REFERENCES live_fork(operation_id) ON DELETE RESTRICT,
    child_index INTEGER,
    phase TEXT NOT NULL,
    monotonic_ns INTEGER NOT NULL CHECK(monotonic_ns>=0)
);
CREATE UNIQUE INDEX fork_parent_event ON fork_event(operation_id,phase) WHERE child_index IS NULL;
CREATE UNIQUE INDEX fork_child_event ON fork_event(operation_id,child_index,phase) WHERE child_index IS NOT NULL;
CREATE TRIGGER live_fork_request_immutable BEFORE UPDATE OF operation_id,capture_id,cancellation_id,request_json,observation_json ON live_fork
BEGIN SELECT RAISE(ABORT,'live fork request is immutable'); END;
CREATE TRIGGER live_fork_child_identity_immutable BEFORE UPDATE OF operation_id,child_index,name,machine_id,run_id,activation_id,consumer_id ON live_fork_child
BEGIN SELECT RAISE(ABORT,'live fork child identity is immutable'); END;
CREATE TRIGGER live_fork_child_launch_immutable BEFORE UPDATE OF launch_id ON live_fork_child
WHEN OLD.launch_id IS NOT NULL AND NEW.launch_id IS NOT OLD.launch_id
BEGIN SELECT RAISE(ABORT,'live fork child launch is immutable'); END;
CREATE TRIGGER live_fork_child_submission_monotonic BEFORE UPDATE OF submitted ON live_fork_child
WHEN OLD.submitted=1 AND NEW.submitted!=1
BEGIN SELECT RAISE(ABORT,'live fork child submission is permanent'); END;
CREATE TRIGGER live_fork_child_name_retirement BEFORE UPDATE OF name_reserved ON live_fork_child
WHEN OLD.name_reserved=0 AND NEW.name_reserved=1
BEGIN SELECT RAISE(ABORT,'live fork child name reservation is retired'); END;
CREATE TRIGGER local_cut_identity_immutable BEFORE UPDATE OF cut_id,operation_id ON local_cut
BEGIN SELECT RAISE(ABORT,'local cut identity is immutable'); END;

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
CREATE TABLE storage_image (
    id TEXT PRIMARY KEY NOT NULL,
    record_digest TEXT NOT NULL,
    record_bytes BLOB NOT NULL,
    retained INTEGER NOT NULL CHECK (retained IN (0, 1)),
    created_at INTEGER NOT NULL
);
CREATE TABLE image_stream_dependency (
    image_id TEXT NOT NULL REFERENCES storage_image(id) ON DELETE CASCADE,
    stream_id TEXT NOT NULL,
    PRIMARY KEY(image_id, stream_id)
);
CREATE INDEX image_stream_reverse_idx ON image_stream_dependency(stream_id, image_id);
CREATE TABLE image_object_dependency (
    image_id TEXT NOT NULL REFERENCES storage_image(id) ON DELETE CASCADE,
    object_digest TEXT NOT NULL,
    PRIMARY KEY(image_id, object_digest)
);
CREATE INDEX image_object_reverse_idx ON image_object_dependency(object_digest, image_id);
CREATE TABLE image_provenance (
    image_id TEXT NOT NULL REFERENCES storage_image(id) ON DELETE CASCADE,
    digest TEXT NOT NULL,
    record_bytes BLOB NOT NULL,
    PRIMARY KEY(image_id, digest)
);
CREATE TABLE raw_conversion_result (
    key_digest TEXT PRIMARY KEY NOT NULL,
    key_bytes BLOB NOT NULL,
    image_id TEXT NOT NULL REFERENCES storage_image(id) ON DELETE CASCADE
);
CREATE INDEX raw_conversion_image_idx ON raw_conversion_result(image_id, key_digest);
CREATE TRIGGER storage_image_identity_immutable
BEFORE UPDATE OF id, record_digest, record_bytes, created_at ON storage_image
BEGIN SELECT RAISE(ABORT, 'image identity is immutable'); END;
CREATE TRIGGER image_stream_dependency_immutable BEFORE UPDATE ON image_stream_dependency
BEGIN SELECT RAISE(ABORT, 'image stream dependency is immutable'); END;
CREATE TRIGGER image_object_dependency_immutable BEFORE UPDATE ON image_object_dependency
BEGIN SELECT RAISE(ABORT, 'image object dependency is immutable'); END;
CREATE TRIGGER image_provenance_immutable BEFORE UPDATE ON image_provenance
BEGIN SELECT RAISE(ABORT, 'image provenance is immutable'); END;
CREATE TRIGGER raw_conversion_result_immutable BEFORE UPDATE ON raw_conversion_result
BEGIN SELECT RAISE(ABORT, 'raw conversion result is immutable'); END;
CREATE TRIGGER image_kind_collision BEFORE INSERT ON storage_image
WHEN EXISTS(SELECT 1 FROM storage_snapshot WHERE id=NEW.id)
BEGIN SELECT RAISE(ABORT, 'managed identity has conflicting record kinds'); END;
CREATE TRIGGER snapshot_kind_collision BEFORE INSERT ON storage_snapshot
WHEN EXISTS(SELECT 1 FROM storage_image WHERE id=NEW.id)
BEGIN SELECT RAISE(ABORT, 'managed identity has conflicting record kinds'); END;
CREATE TABLE image_alias (
    name TEXT PRIMARY KEY NOT NULL,
    snapshot_id TEXT REFERENCES storage_snapshot(id) ON DELETE RESTRICT,
    image_id TEXT REFERENCES storage_image(id) ON DELETE RESTRICT,
    CHECK ((snapshot_id IS NOT NULL) + (image_id IS NOT NULL) = 1)
);
CREATE INDEX image_alias_snapshot_idx ON image_alias(snapshot_id);
CREATE INDEX image_alias_image_idx ON image_alias(image_id, name);
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

CREATE TABLE snapshot_imported_capture (
    snapshot_id TEXT NOT NULL REFERENCES storage_snapshot(id) ON DELETE CASCADE,
    provenance_digest TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    provenance_bytes BLOB NOT NULL,
    PRIMARY KEY(snapshot_id,provenance_digest)
);
CREATE INDEX snapshot_imported_capture_evidence ON snapshot_imported_capture(evidence_digest,snapshot_id);
CREATE TABLE managed_artifact_acquisition (
    managed_kind TEXT NOT NULL CHECK(managed_kind IN ('image','snapshot')),
    managed_id TEXT NOT NULL,
    index_digest TEXT NOT NULL,
    receipt_digest TEXT NOT NULL,
    receipt_bytes BLOB NOT NULL,
    provenance_digest TEXT,
    encoding_bytes BLOB NOT NULL,
    PRIMARY KEY(managed_kind,managed_id,index_digest,receipt_digest),
    CHECK(managed_kind='snapshot' OR provenance_digest IS NULL)
);
CREATE INDEX managed_artifact_acquisition_receipt ON managed_artifact_acquisition(receipt_digest);
CREATE TRIGGER snapshot_imported_capture_immutable BEFORE UPDATE ON snapshot_imported_capture
BEGIN SELECT RAISE(ABORT,'imported capture provenance is immutable'); END;
CREATE TRIGGER managed_artifact_acquisition_immutable BEFORE UPDATE ON managed_artifact_acquisition
BEGIN SELECT RAISE(ABORT,'artifact acquisition is immutable'); END;
CREATE TRIGGER storage_image_acquisition_delete AFTER DELETE ON storage_image
BEGIN DELETE FROM managed_artifact_acquisition WHERE managed_kind='image' AND managed_id=OLD.id; END;
CREATE TRIGGER storage_snapshot_acquisition_delete AFTER DELETE ON storage_snapshot
BEGIN DELETE FROM managed_artifact_acquisition WHERE managed_kind='snapshot' AND managed_id=OLD.id; END;
