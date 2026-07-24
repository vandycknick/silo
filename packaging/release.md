# Release Workflow

`.github/workflows/release.yml` is currently a manual, non-publishing
qualification workflow. It runs on GitHub's native arm64 macOS 26 image and
uses the stable kernel at:

```text
ghcr.io/vandycknick/silo/kernel:stable
```

The workflow builds the canonical release stage, creates an ad-hoc signed app
and DMG, verifies them, and retains the result as a workflow artifact rather
than a release asset. It does not create or modify a GitHub release and does
not write to the Homebrew tap.

GitHub's arm64 macOS runners do not support nested virtualization. They can
qualify builds, layouts, signatures, and disk images, but cannot satisfy the VZ
boot gate. Final VM boot qualification requires a clean native macOS 26 host
with virtualization available.

## Protected Release Contract

Production publishing remains disabled until a GitHub `release` environment is
configured with required reviewers and the credential import design is
implemented. The reserved secret contract is:

| Name | Purpose |
| --- | --- |
| `APPLE_SIGNING_CERTIFICATE_P12_BASE64` | Base64-encoded Developer ID Application identity and private key |
| `APPLE_SIGNING_CERTIFICATE_PASSWORD` | Password protecting the PKCS#12 payload |
| `APPLE_NOTARY_API_KEY_P8_BASE64` | Base64-encoded App Store Connect API private key |
| `APPLE_NOTARY_KEY_ID` | App Store Connect API key ID |
| `APPLE_NOTARY_ISSUER_ID` | App Store Connect issuer UUID |
| `HOMEBREW_TAP_TOKEN` | Fine-grained token with contents write access only to `vandycknick/homebrew-tap` |

The non-secret Developer ID common name belongs in the release environment as
`APPLE_SIGNING_IDENTITY`.

Production activation must preserve this order:

1. Import the signing identity into an ephemeral keychain.
2. Store the notary API credentials in an ephemeral Keychain profile.
3. Run `release-stage` from the exact clean tagged revision.
4. Run `package-macos` with the monotonic workflow run number, Developer ID
   identity, and notary profile.
5. Upload the DMG to a draft GitHub release for the exact `v<version>` tag.
6. Generate the Cask only after the uploaded DMG is independently revalidated.
7. Commit the generated Cask to the protected Homebrew tap.
8. Publish the GitHub release only after clean-host VZ boot qualification.

The public tap repository is <https://github.com/vandycknick/homebrew-tap>.
It remains empty until the protected publication path is activated.
