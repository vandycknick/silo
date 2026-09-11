type == "object" and
keys == ["activation_contract", "architecture", "data_layout", "engine", "publication_contract", "qualified_silo", "schema", "source_revision", "storage", "versions"] and
.schema == 1 and .engine == "docker" and
.activation_contract == 1 and .publication_contract == 1 and
.data_layout == 1 and .storage == "containerd-snapshotter" and
(.architecture == "amd64" or .architecture == "arm64") and
(.source_revision | type == "string" and length > 0) and
(.versions | type == "object") and
(.versions | keys == ["containerd", "docker"]) and
(.versions.docker | type == "string" and length > 0) and
(.versions.containerd | type == "string" and length > 0)
