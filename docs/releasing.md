# Releasing

Releases are **never** published automatically. The release workflow
(`.github/workflows/release.yml`) runs only when a maintainer pushes a version
tag. It creates a **draft** GitHub release that a maintainer must review and
publish by hand.

## One-time setup (repository owner)

1. **Settings → Environments → New environment** named `release`. Add
   *Required reviewers* (yourself or the release team). Every release build
   then waits for an explicit approval.
2. **Settings → Actions → General → Workflow permissions**: allow
   *Read and write permissions* (needed to create the draft release).
3. *Optional*: add signing secrets (below) to the `release` environment.

## Cutting a release

1. Bump the version in `package.json`, `src-tauri/tauri.conf.json` and
   `[workspace.package]` in `Cargo.toml`. The workflow refuses a tag that does
   not match the first two. Update `CHANGELOG.md`.
2. Commit, then tag and push:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
3. The workflow does the following:
   - Checks that the tag matches the versions.
   - Runs lint, typecheck, Vitest, clippy and `cargo test`.
   - Waits for approval in the `release` environment.
   - Builds on five runners: Windows x64, Linux x64, Linux ARM64, macOS ARM64
     and macOS x64 (cross-compiled on Apple Silicon).
   - Uploads the installers to a draft release.
   - Attaches `SHA256SUMS.txt`.
4. Download and smoke-test the assets, then publish the draft.

Users verify downloads with:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing         # Linux
shasum -a 256 -c SHA256SUMS.txt --ignore-missing     # macOS
Get-FileHash .\BreachFrame_0.2.0_x64-setup.exe -Algorithm SHA256   # Windows
```

## Code signing

### macOS (signing + notarization)

Without the following secrets, the macOS builds are **unsigned and not
notarized**. Gatekeeper blocks the first launch, and users must right-click →
Open (or run `xattr -dr com.apple.quarantine /Applications/BreachFrame.app`).
The README states this.

To sign, add an Apple Developer ID to the `release` environment:

| Secret | Value |
|--------|-------|
| `APPLE_CERTIFICATE` | base64 of the exported *Developer ID Application* `.p12` |
| `APPLE_CERTIFICATE_PASSWORD` | password of the `.p12` |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` | Apple ID, app-specific password and team id for notarization |

`tauri-action` signs and notarizes automatically when they are present.

### Windows

Builds are currently **unsigned**, so SmartScreen shows "Windows protected your
PC" (More info → Run anyway). To sign, configure
`bundle.windows.certificateThumbprint` (local certificate) or a `signCommand`
(e.g. Azure Trusted Signing) in `src-tauri/tauri.conf.json`, as described in
the Tauri documentation.

### Linux

AppImage, .deb and .rpm packages are not signed. Verify them with
`SHA256SUMS.txt`.
