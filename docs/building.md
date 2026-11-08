# Building from source

## Prerequisites

| Tool | Version |
|------|---------|
| Rust | stable (developed with 1.99) via [rustup](https://rustup.rs) |
| Node.js | 22 LTS or newer (build-time only; not needed by end users) |

### Platform dependencies

**Windows 10/11**: Microsoft C++ Build Tools ("Desktop development with C++")
and the WebView2 runtime (preinstalled on Windows 11 and current Windows 10).

**macOS**: Xcode Command Line Tools: `xcode-select --install`.

**Debian / Ubuntu / Linux Mint**:

```bash
sudo apt-get install -y build-essential curl wget file libssl-dev \
  libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf
```

**Fedora**:

```bash
sudo dnf install -y webkit2gtk4.1-devel openssl-devel curl wget file \
  libappindicator-gtk3-devel librsvg2-devel
sudo dnf group install -y "c-development"
```

**Arch Linux**:

```bash
sudo pacman -S --needed webkit2gtk-4.1 base-devel curl wget file openssl \
  libappindicator-gtk3 librsvg
```

These package lists follow the Tauri 2 prerequisites. Only the Ubuntu 22.04
list is exercised by CI.

## Commands

```bash
npm ci                         # install front-end dependencies
npm run tauri dev              # run the app with hot reload
npm run tauri build            # release build + installers for the current OS

npm run lint                   # ESLint
npm run typecheck              # tsc --noEmit
npm test                       # Vitest (UI, IPC contract, graph helpers)
cargo test --workspace         # engine, CLI and app-service tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# End-to-end tests against the real desktop binary (Windows only, see below)
npx vite build && cargo build -p breachframe-app
npx playwright install chromium
npm run test:e2e               # SCREENSHOTS=1 also refreshes docs/screenshots
```

The CLI:

```bash
cargo run -p breachframe-cli -- analyze examples/kubernetes/rbac.yaml
cargo build -p breachframe-cli --release   # target/release/breachframe(.exe)
```

## Installer outputs

`npm run tauri build` writes installers to `target/release/bundle/`:

| OS | Formats |
|----|---------|
| Windows | `nsis/*.exe` (per-user install, downloads WebView2 if missing), `msi/*.msi` |
| Linux | `appimage/*.AppImage`, `deb/*.deb`, `rpm/*.rpm` |
| macOS | `dmg/*.dmg`, `macos/BreachFrame.app` |

Cross-compiling installers between operating systems is not supported. Use the
CI matrix (`.github/workflows/ci.yml`) to build all platforms.

## End-to-end tests

`e2e/desktop.spec.ts` launches the real debug binary with:

- an isolated temporary data directory (`BREACHFRAME_DATA_DIR`);
- `BREACHFRAME_CDP_PORT`, which in **debug builds only** opens the WebView2
  DevTools protocol.

Playwright then attaches over CDP. Every action goes through IPC, the Rust
engine and SQLite, and nothing is mocked. WKWebView (macOS) and WebKitGTK
(Linux) do not expose CDP, so this suite runs on Windows. On Linux and macOS
the UI is covered by the Vitest component tests.

### Refreshing screenshots and the demo GIF

`SCREENSHOTS=1 npm run test:e2e` writes `docs/screenshots/*.png` and numbered
frames to `test-results/demo-frames/`. Each frame is a real capture of the app
during the labs test. To assemble the frames into `docs/demo.gif` with ffmpeg:

```bash
cd test-results/demo-frames
for f in *.png; do echo "file '$f'"; echo "duration 1"; done > list.txt
ffmpeg -f concat -safe 0 -i list.txt \
  -vf "scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse" \
  -loop 0 ../../docs/demo.gif
```
