# macOS Release Packaging

The macOS packager consumes the canonical `darwin-arm64` output from
`release-stage`. It does not rebuild or replace staged components. Packaging
must run from the same clean Git revision recorded by staging; component bytes,
modes, and sizes must still match `release.json`.

For a local ad-hoc signed app and DMG:

```bash
cargo run -p xtask -- package-macos --build-number 1
```

For a Developer ID signed release:

```bash
cargo run -p xtask -- package-macos \
  --build-number "$RELEASE_BUILD_NUMBER" \
  --signing-identity "Developer ID Application: Example (TEAMID)" \
  --notary-keychain-profile silo-release
```

The signing identity must already be available to `codesign`. Configure the
notary profile separately with `xcrun notarytool store-credentials`; never pass
an Apple ID password or App Store Connect private key to the packaging command.
The build number is a positive, one-to-three-part integer version and must be
monotonically increased by the protected release workflow.

Production packaging signs `vmmon`, `netd`, and `krun` individually, then signs
the outer app. It never uses `codesign --deep` for signing. The app and final
DMG are separately submitted, stapled, and validated so the copied app remains
usable without network access after it leaves the DMG.

Outputs are installed atomically below:

```text
target/silo-artifacts/darwin-arm64/macos/
  Silo.app/
  Silo-<version>-darwin-arm64.dmg
  macos.json
```

The output directory must not already exist. Ad-hoc signing is only a local
development convenience and does not satisfy the release trust contract.

After the notarized DMG is uploaded to the matching `v<version>` GitHub
release, generate the Cask for the official tap:

```bash
cargo run -p xtask -- package-homebrew-cask
```

The generator validates the local DMG's Developer ID signature, stapled ticket,
and Gatekeeper assessment. It then downloads the published release asset and
requires an exact size and checksum match. Ad-hoc, unnotarized, missing, or
mismatched artifacts are rejected. The generator writes:

```text
target/silo-artifacts/darwin-arm64/homebrew/Casks/vandycknick-silo.rb
```

The token includes the GitHub username because Homebrew already has an
unrelated `silo` Cask. The generated Cask installs `Silo.app` and exposes
`Contents/MacOS/silo` as the `silo` command. Publication to the separate tap
repository remains a protected release-workflow operation.
