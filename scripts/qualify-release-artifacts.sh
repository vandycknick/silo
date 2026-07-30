#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPOSITORY_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly PACKAGE_ROOT="$REPOSITORY_ROOT/target/packages"
readonly QUALIFICATION_ROOT="$REPOSITORY_ROOT/target/qualification"
declare -ar TARGETS=(darwin-arm64 linux-amd64-gnu linux-arm64-gnu)

DOWNLOAD=false
RUN_ID=""
RUN_SHA=""
EXPECTED_SOURCE_REVISION=""
DMG_MOUNTED=false
DMG_MOUNT="$QUALIFICATION_ROOT/dmg-mount"

usage() {
  cat <<'EOF'
Usage: scripts/qualify-release-artifacts.sh [OPTIONS]

Download and manually qualify the native Release Tip artifacts. By default the
script reuses artifacts already present below target/packages.

Options:
  --download       Replace the current version's package tree with artifacts
                   downloaded from GitHub Actions.
  --no-download    Reuse existing artifacts (the default).
  --run-id ID      Workflow run ID to download. Required with --download.
  -h, --help       Show this help.

Examples:
  scripts/qualify-release-artifacts.sh
  scripts/qualify-release-artifacts.sh --download --run-id 30501598493
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

section() {
  printf '\n===== %s =====\n' "$1"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_file() {
  [[ -f "$1" ]] || die "required file not found: $1"
}

require_directory() {
  [[ -d "$1" ]] || die "required directory not found: $1"
}

cleanup() {
  if [[ "$DMG_MOUNTED" == true ]]; then
    hdiutil detach "$DMG_MOUNT" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

while (($# > 0)); do
  case "$1" in
    --download)
      DOWNLOAD=true
      shift
      ;;
    --no-download)
      DOWNLOAD=false
      shift
      ;;
    --run-id)
      (($# >= 2)) || die "--run-id requires a value"
      RUN_ID="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

cd "$REPOSITORY_ROOT"

require_file "$REPOSITORY_ROOT/VERSION"
readonly VERSION="$(tr -d '[:space:]' <"$REPOSITORY_ROOT/VERSION")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION is not a semantic version: $VERSION"

[[ "$(uname -s)" == Darwin ]] || die "full artifact qualification must run on macOS"
[[ "$(uname -m)" == arm64 ]] || die "full artifact qualification must run on macOS arm64"

for command in nix jq shasum file objdump otool codesign hdiutil gzip cpio grep cut readlink; do
  require_command "$command"
done

if [[ "$DOWNLOAD" == true ]]; then
  [[ "$RUN_ID" =~ ^[0-9]+$ ]] || die "--download requires a numeric --run-id"
  require_command gh
elif [[ -n "$RUN_ID" ]]; then
  die "--run-id may only be used with --download"
fi

download_artifacts() {
  section "Download Artifacts"

  RUN_SHA="$(gh run view "$RUN_ID" --json headSha --jq .headSha)"
  [[ "$RUN_SHA" =~ ^[0-9a-f]{40}$ ]] || die "workflow run did not report a valid commit SHA"
  EXPECTED_SOURCE_REVISION="$RUN_SHA"

  rm -rf "$PACKAGE_ROOT/$VERSION"
  mkdir -p "$PACKAGE_ROOT"

  for target in "${TARGETS[@]}"; do
    local artifact="silo-$target-archives"
    printf 'Downloading %s from run %s\n' "$artifact" "$RUN_ID"
    gh run download "$RUN_ID" --name "$artifact" --dir "$PACKAGE_ROOT"
  done
}

verify_expected_outputs() {
  section "Expected Outputs"

  for target in "${TARGETS[@]}"; do
    local directory="$PACKAGE_ROOT/$VERSION/$target"
    require_directory "$directory"

    for prefix in silo-runtime silo; do
      local stem="$prefix-$VERSION-$target"
      require_file "$directory/$stem.tar.zst"
      require_file "$directory/$stem.tar.zst.sha256"
      require_file "$directory/$stem.sbom.spdx.json"
      require_file "$directory/$stem.provenance.json"
    done

    printf '%s: archives and sidecars present\n' "$target"
  done

  require_directory "$PACKAGE_ROOT/$VERSION/darwin-arm64/Silo.app"
  require_file "$PACKAGE_ROOT/$VERSION/darwin-arm64/silo-$VERSION-darwin-arm64.dmg"
  printf 'darwin-arm64: app and DMG present\n'
}

verify_checksums_and_metadata() {
  section "Checksums And Metadata"

  for target in "${TARGETS[@]}"; do
    (
      cd "$PACKAGE_ROOT/$VERSION/$target"
      shasum -a 256 --check ./*.tar.zst.sha256
    )
  done

  local json_files=("$PACKAGE_ROOT/$VERSION"/*/*.json)
  jq empty "${json_files[@]}"
  printf 'All SBOM and provenance files contain valid JSON\n'

  for target in "${TARGETS[@]}"; do
    for prefix in silo-runtime silo; do
      local stem="$prefix-$VERSION-$target"
      local provenance="$PACKAGE_ROOT/$VERSION/$target/$stem.provenance.json"
      local source_revision

      jq -e \
        --arg version "$VERSION" \
        --arg target "$target" \
        --arg archive "$stem.tar.zst" \
        '.version == $version and .target == $target and .archive.name == $archive' \
        "$provenance" >/dev/null || die "invalid provenance identity: $provenance"

      source_revision="$(jq -er '.source_revision | select(type == "string" and length == 40)' "$provenance")"
      [[ "$source_revision" =~ ^[0-9a-f]{40}$ ]] || die "$provenance has an invalid source revision"
      if [[ -z "$EXPECTED_SOURCE_REVISION" ]]; then
        EXPECTED_SOURCE_REVISION="$source_revision"
      fi
      [[ "$source_revision" == "$EXPECTED_SOURCE_REVISION" ]] ||
        die "$provenance has source revision $source_revision, expected $EXPECTED_SOURCE_REVISION"

      printf '%s\t%s\t%s\n' "$target" "$stem.tar.zst" "$source_revision"
    done
  done
}

list_and_extract_archives() {
  section "Archive Layouts And Extraction"

  rm -rf "$QUALIFICATION_ROOT"
  mkdir -p "$QUALIFICATION_ROOT"

  nix develop .#release --command /bin/bash -c '
      set -euo pipefail

      VERSION="$1"
      PACKAGE_ROOT="$2"
      QUALIFICATION_ROOT="$3"
      targets=(darwin-arm64 linux-amd64-gnu linux-arm64-gnu)

      for target in "${targets[@]}"; do
        for prefix in silo-runtime silo; do
          archive="$PACKAGE_ROOT/$VERSION/$target/$prefix-$VERSION-$target.tar.zst"
          printf "\n--- %s ---\n" "$archive"
          tar --use-compress-program=unzstd --list --verbose --file "$archive"
        done

        destination="$QUALIFICATION_ROOT/$target"
        portable="$PACKAGE_ROOT/$VERSION/$target/silo-$VERSION-$target.tar.zst"
        mkdir -p "$destination"
        tar \
          --use-compress-program=unzstd \
          --extract \
          --file "$portable" \
          --directory "$destination"
      done
    ' _ "$VERSION" "$PACKAGE_ROOT" "$QUALIFICATION_ROOT"
}

assert_mode() {
  local path="$1"
  local expected="$2"
  local actual

  require_file "$path"
  actual="$(/usr/bin/stat -f '%Lp' "$path")"
  [[ "$actual" == "$expected" ]] || die "$path has mode $actual, expected $expected"
}

verify_extracted_layouts() {
  section "Extracted Layouts And Modes"

  for target in "${TARGETS[@]}"; do
    local root="$QUALIFICATION_ROOT/$target/silo-$VERSION-$target"
    require_directory "$root"

    for name in silo vmmon netd krun; do
      assert_mode "$root/bin/$name" 755
    done
    assert_mode "$root/assets/agent" 755
    assert_mode "$root/assets/kernel-default" 644
    assert_mode "$root/assets/initramfs" 644

    printf '%s: extracted layout and modes are correct\n' "$target"
  done
}

extract_linux_initramfs() {
  section "Linux Initramfs Extraction"

  for target in linux-amd64-gnu linux-arm64-gnu; do
    local root="$QUALIFICATION_ROOT/$target/silo-$VERSION-$target"
    local destination="$root/initramfs-unpacked"

    mkdir -p "$destination"
    (
      cd "$destination"
      gzip -dc "$root/assets/initramfs" | cpio -id
    )
    require_file "$destination/init"
    printf '%s: guest init extracted\n' "$target"
  done
}

inspect_linux_target() {
  local target="$1"
  local architecture="$2"
  local loader="$3"
  local root="$QUALIFICATION_ROOT/$target/silo-$VERSION-$target"
  local dynamic_binaries=("$root/bin/silo" "$root/bin/vmmon" "$root/bin/krun")
  local static_binaries=("$root/bin/netd" "$root/assets/agent" "$root/initramfs-unpacked/init")

  section "Linux Binary Inspection: $target"

  for binary in "${dynamic_binaries[@]}"; do
    local description
    description="$(file "$binary")"
    printf '%s\n' "$description"
    [[ "$description" == *"$architecture"* ]] || die "$binary has the wrong architecture"
    [[ "$description" == *'dynamically linked'* ]] || die "$binary is not dynamically linked"
    [[ "$description" == *"$loader"* ]] || die "$binary does not use system loader $loader"
  done

  local dependencies
  if ! dependencies="$(objdump -p "${dynamic_binaries[@]}" | grep 'NEEDED')"; then
    die "$target host binaries have no visible dynamic dependencies"
  fi
  printf '%s\n' "$dependencies"

  for binary in "${static_binaries[@]}"; do
    local description
    description="$(file "$binary")"
    printf '%s\n' "$description"
    [[ "$description" == *"$architecture"* ]] || die "$binary has the wrong architecture"
    [[ "$description" == *'statically linked'* ]] || die "$binary is not statically linked"
    if objdump -p "$binary" | grep -q 'NEEDED'; then
      die "$binary has an unexpected dynamic dependency"
    fi
  done

  printf '%s: native loader and static guest checks passed\n' "$target"
}

verify_extracted_cli_hashes() {
  section "Extracted CLI Provenance"

  for target in "${TARGETS[@]}"; do
    local root="$QUALIFICATION_ROOT/$target/silo-$VERSION-$target"
    local provenance="$PACKAGE_ROOT/$VERSION/$target/silo-$VERSION-$target.provenance.json"
    local actual expected

    actual="$(shasum -a 256 "$root/bin/silo" | cut -d ' ' -f 1)"
    expected="$(jq -er '.file_hashes["bin/silo"]' "$provenance")"
    [[ "$actual" == "$expected" ]] || die "$target extracted CLI does not match provenance"
    printf '%s: extracted CLI matches provenance\n' "$target"
  done
}

inspect_darwin_binaries() {
  section "Darwin Binary Inspection"

  local root="$QUALIFICATION_ROOT/darwin-arm64/silo-$VERSION-darwin-arm64"
  local binaries=("$root/bin/silo" "$root/bin/vmmon" "$root/bin/netd" "$root/bin/krun")

  for binary in "${binaries[@]}"; do
    local description
    description="$(file "$binary")"
    printf '%s\n' "$description"
    [[ "$description" == *'Mach-O 64-bit arm64 executable'* ]] || die "$binary is not arm64 Mach-O"
  done

  local dependencies
  dependencies="$(otool -L "${binaries[@]}")"
  printf '%s\n' "$dependencies"
  if grep -q '/nix/store' <<<"$dependencies"; then
    die "Darwin archive contains a Nix-store dynamic dependency"
  fi

  "$root/bin/silo" --help >/dev/null
  printf 'darwin-arm64: Apple linkage and CLI startup checks passed\n'
}

verify_signed_app() {
  section "Uploaded Application"

  local app="$PACKAGE_ROOT/$VERSION/darwin-arm64/Silo.app"
  local executables=(
    "$app/Contents/MacOS/silo"
    "$app/Contents/Helpers/vmmon"
    "$app/Contents/Helpers/netd"
    "$app/Contents/Helpers/krun"
  )

  for executable in "${executables[@]}"; do
    require_file "$executable"
    codesign --verify --strict --verbose=4 "$executable"
  done
  codesign --verify --strict --verbose=4 "$app"

  file "${executables[@]}"
  local dependencies
  dependencies="$(otool -L "${executables[@]}")"
  printf '%s\n' "$dependencies"
  if grep -q '/nix/store' <<<"$dependencies"; then
    die "uploaded application contains a Nix-store dynamic dependency"
  fi

  printf 'darwin-arm64: uploaded application signatures are valid\n'
}

verify_dmg() {
  section "DMG"

  local dmg="$PACKAGE_ROOT/$VERSION/darwin-arm64/silo-$VERSION-darwin-arm64.dmg"
  local app="$DMG_MOUNT/Silo.app"
  local applications="$DMG_MOUNT/Applications"

  mkdir -p "$DMG_MOUNT"
  hdiutil attach -readonly -nobrowse -mountpoint "$DMG_MOUNT" "$dmg" >/dev/null
  DMG_MOUNTED=true

  require_directory "$app"
  for executable in \
    "$app/Contents/MacOS/silo" \
    "$app/Contents/Helpers/vmmon" \
    "$app/Contents/Helpers/netd" \
    "$app/Contents/Helpers/krun"
  do
    codesign --verify --strict --verbose=4 "$executable"
  done
  codesign --verify --strict --verbose=4 "$app"

  [[ -L "$applications" ]] || die "$applications is not a symlink"
  [[ "$(readlink "$applications")" == /Applications ]] ||
    die "$applications does not point to /Applications"

  "$app/Contents/MacOS/silo" --help >/dev/null

  hdiutil detach "$DMG_MOUNT" >/dev/null
  DMG_MOUNTED=false
  rmdir "$DMG_MOUNT"
  printf 'darwin-arm64: DMG mount, signatures, layout, and CLI startup checks passed\n'
}

if [[ "$DOWNLOAD" == true ]]; then
  download_artifacts
fi

verify_expected_outputs
verify_checksums_and_metadata
list_and_extract_archives
verify_extracted_layouts
extract_linux_initramfs
inspect_linux_target linux-amd64-gnu x86-64 /lib64/ld-linux-x86-64.so.2
inspect_linux_target linux-arm64-gnu 'ARM aarch64' /lib/ld-linux-aarch64.so.1
verify_extracted_cli_hashes
inspect_darwin_binaries
verify_signed_app
verify_dmg

section "Qualification Complete"
printf 'Version: %s\n' "$VERSION"
printf 'Source revision: %s\n' "$EXPECTED_SOURCE_REVISION"
printf 'Packages: %s/%s\n' "$PACKAGE_ROOT" "$VERSION"
printf 'Extracted archives: %s\n' "$QUALIFICATION_ROOT"
