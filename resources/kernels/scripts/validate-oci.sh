#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
    printf 'usage: %s <layout> <reference> <workload|rprobe>\n' "$0" >&2
    exit 2
fi

layout=$1
reference=$2
profile=$3

kconfig_type=application/vnd.silo.kernel.kconfig.v1
system_map_type=application/vnd.silo.kernel.system-map.v1
debug_type=application/vnd.silo.kernel.debug.v1+xz

manifest=$(oras manifest fetch --oci-layout "$layout:$reference")
config=$(oras manifest fetch-config --oci-layout "$layout:$reference")
case "$profile" in
    workload)
        artifact_type=application/vnd.silo.kernel.v1
        config_type=application/vnd.silo.kernel.config.v1+json
        image_type=application/vnd.silo.kernel.image.v1
        purpose=workload
        ;;
    rprobe)
        artifact_type=application/vnd.silo.rprobe-kernel.v1
        config_type=application/vnd.silo.rprobe-kernel.config.v1+json
        image_type=application/vnd.silo.rprobe-kernel.image.v1
        purpose=rosetta-acquisition-probe
        ;;
    *)
        printf 'unsupported kernel profile in OCI config: %s\n' "$profile" >&2
        exit 1
        ;;
esac

printf '%s\n' "$manifest" | jq -e \
    --argjson config "$config" \
    --arg artifact_type "$artifact_type" \
    --arg config_type "$config_type" \
    --arg image_type "$image_type" \
    --arg kconfig_type "$kconfig_type" \
    --arg system_map_type "$system_map_type" \
    --arg debug_type "$debug_type" \
    --arg profile "$profile" \
    --arg purpose "$purpose" '
        def layers($type): [.layers[] | select(.mediaType == $type)];
        .artifactType == $artifact_type and
        .config.mediaType == $config_type and
        (layers($image_type) | length) == 1 and
        (layers($image_type)[0].annotations["org.opencontainers.image.title"] | type == "string" and length > 0) and
        (layers($kconfig_type) | length) == 1 and
        (layers($system_map_type) | length) == 1 and
        $config.schemaVersion == 1 and
        $config.profile == $profile and
        $config.purpose == $purpose and
        ($config.identity | type == "string" and length > 0) and
        $config.kernel.mediaType == $image_type and
        ($config.kernel.digest | test("^sha256:[0-9a-f]{64}$")) and
        ($config.kernel.size | type == "number" and . > 0) and
        $config.kernel.digest == layers($image_type)[0].digest and
        $config.kernel.size == layers($image_type)[0].size and
        ($config.resolvedConfig.digest | test("^sha256:[0-9a-f]{64}$")) and
        ($config.resolvedConfig.size | type == "number" and . > 0) and
        $config.resolvedConfig.digest == layers($kconfig_type)[0].digest and
        $config.resolvedConfig.size == layers($kconfig_type)[0].size and
        ($config.source.digest | test("^sha256:[0-9a-f]{64}$")) and
        ($config.source.key | test("^sha256-[0-9a-f]{64}$")) and
        $config.source.key == ("sha256-" + ($config.source.digest | sub("^sha256:"; ""))) and
        ($config.inputs.patchSet | test("^sha256-[0-9a-f]{64}$")) and
        ($config.inputs.config | test("^sha256-[0-9a-f]{64}$")) and
        ($config.inputs.build | test("^sha256-[0-9a-f]{64}$")) and
        ($config.inputs.toolchain | test("^sha256-[0-9a-f]{64}$")) and
        ($config.build.compiler | type == "string" and length > 0) and
        ($config.build.linker | type == "string" and length > 0) and
        (
            (
                $config.architecture == "arm64" and
                $config.platform == {os: "linux", architecture: "arm64"} and
                $config.kernel.format == "arm64-image" and
                (layers($debug_type) | length) == 1 and
                ($profile == "workload" or $profile == "rprobe")
            ) or
            (
                $config.architecture == "x86_64" and
                $config.platform == {os: "linux", architecture: "amd64"} and
                $config.kernel.format == "elf" and
                (layers($debug_type) | length) == 0 and
                $profile == "workload"
            )
        )
    ' >/dev/null

jq -e \
    --arg reference "$reference" '
        [.manifests[] |
            select(.annotations["org.opencontainers.image.ref.name"] == $reference)
        ] | length == 1
    ' "$layout/index.json" >/dev/null
