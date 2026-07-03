CREATE TABLE IF NOT EXISTS image_manifest (
    digest                  TEXT PRIMARY KEY,
    media_type              TEXT NOT NULL,
    image_id                TEXT NOT NULL,
    platform_os             TEXT NOT NULL,
    platform_architecture   TEXT NOT NULL,
    platform_variant        TEXT,
    config_digest           TEXT,
    layer_count             INTEGER NOT NULL,
    total_size_bytes        INTEGER NOT NULL,
    created_at              INTEGER NOT NULL,
    last_used_at            INTEGER
);

CREATE TABLE IF NOT EXISTS image_ref (
    reference               TEXT PRIMARY KEY,
    manifest_digest         TEXT NOT NULL REFERENCES image_manifest(digest) ON DELETE RESTRICT,
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,
    last_used_at            INTEGER
);

CREATE TABLE IF NOT EXISTS image_config (
    manifest_digest         TEXT PRIMARY KEY REFERENCES image_manifest(digest) ON DELETE CASCADE,
    digest                  TEXT,
    env_json                BLOB NOT NULL,
    cmd_json                BLOB NOT NULL,
    entrypoint_json         BLOB NOT NULL,
    working_dir             TEXT,
    user                    TEXT,
    labels_json             BLOB NOT NULL,
    created_at              INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS image_layer (
    diff_id                 TEXT PRIMARY KEY,
    blob_digest             TEXT NOT NULL,
    media_type              TEXT NOT NULL,
    compressed_size_bytes   INTEGER,
    uncompressed_size_bytes INTEGER,
    created_at              INTEGER NOT NULL,
    last_used_at            INTEGER
);

CREATE TABLE IF NOT EXISTS image_manifest_layer (
    manifest_digest         TEXT NOT NULL REFERENCES image_manifest(digest) ON DELETE CASCADE,
    layer_diff_id           TEXT NOT NULL REFERENCES image_layer(diff_id) ON DELETE RESTRICT,
    position                INTEGER NOT NULL,
    PRIMARY KEY (manifest_digest, layer_diff_id),
    UNIQUE (manifest_digest, position)
);

CREATE TABLE IF NOT EXISTS image_rootfs_artifact (
    image_id                TEXT PRIMARY KEY,
    source_kind             TEXT NOT NULL,
    manifest_digest         TEXT REFERENCES image_manifest(digest) ON DELETE RESTRICT,
    source_reference        TEXT NOT NULL,
    platform_os             TEXT NOT NULL,
    platform_architecture   TEXT NOT NULL,
    platform_variant        TEXT,
    filesystem              TEXT NOT NULL,
    rootfs_path             TEXT NOT NULL,
    size_bytes              INTEGER NOT NULL,
    created_at              INTEGER NOT NULL,
    last_used_at            INTEGER
);

CREATE TABLE IF NOT EXISTS machine_rootfs (
    machine_id              TEXT PRIMARY KEY REFERENCES machine_config(id) ON DELETE CASCADE,
    source_kind             TEXT NOT NULL,
    source_reference        TEXT NOT NULL,
    manifest_digest         TEXT REFERENCES image_manifest(digest) ON DELETE RESTRICT,
    image_id                TEXT,
    root_disk_path          TEXT NOT NULL,
    root_disk_size_bytes    INTEGER NOT NULL,
    created_at              INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS image_ref_manifest_digest_idx
ON image_ref(manifest_digest);

CREATE INDEX IF NOT EXISTS image_manifest_layer_layer_diff_id_idx
ON image_manifest_layer(layer_diff_id);

CREATE INDEX IF NOT EXISTS image_rootfs_artifact_manifest_digest_idx
ON image_rootfs_artifact(manifest_digest);

CREATE INDEX IF NOT EXISTS machine_rootfs_manifest_digest_idx
ON machine_rootfs(manifest_digest);

CREATE TRIGGER IF NOT EXISTS image_manifest_created_at_immutable
BEFORE UPDATE OF created_at ON image_manifest
BEGIN
    SELECT RAISE(ABORT, 'image_manifest.created_at is immutable');
END;

CREATE TRIGGER IF NOT EXISTS image_ref_created_at_immutable
BEFORE UPDATE OF created_at ON image_ref
BEGIN
    SELECT RAISE(ABORT, 'image_ref.created_at is immutable');
END;

CREATE TRIGGER IF NOT EXISTS image_config_created_at_immutable
BEFORE UPDATE OF created_at ON image_config
BEGIN
    SELECT RAISE(ABORT, 'image_config.created_at is immutable');
END;

CREATE TRIGGER IF NOT EXISTS image_layer_created_at_immutable
BEFORE UPDATE OF created_at ON image_layer
BEGIN
    SELECT RAISE(ABORT, 'image_layer.created_at is immutable');
END;

CREATE TRIGGER IF NOT EXISTS image_rootfs_artifact_created_at_immutable
BEFORE UPDATE OF created_at ON image_rootfs_artifact
BEGIN
    SELECT RAISE(ABORT, 'image_rootfs_artifact.created_at is immutable');
END;

CREATE TRIGGER IF NOT EXISTS machine_rootfs_created_at_immutable
BEFORE UPDATE OF created_at ON machine_rootfs
BEGIN
    SELECT RAISE(ABORT, 'machine_rootfs.created_at is immutable');
END;
