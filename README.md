# OTS Manager

<img src="src/assets/logo.png" width="96" align="right" alt="OTS Manager logo">

**OpenTimestamp Manager**: a desktop app for Windows, macOS and Linux that creates, upgrades and verifies [OpenTimestamps](https://opentimestamps.org) proofs (`.ots`) **in bulk**.

Everything is bundled. You don't need Python, Node or a Bitcoin node.

## Features

| Tab | What it does |
|---|---|
| **Create** | Drop files or folders, or pick them. The app detects existing compliant `.ots` proofs and skips them. The other files are timestamped together in one calendar round-trip (Merkle tree, with a private nonce for each file). |
| **Upgrade** | Drop `.ots` files from any locations. Each one is upgraded in place, once Bitcoin has confirmed it. An optional `.ots.bak` backup can be kept. Statuses: Pending, Upgraded, Already complete, Not confirmed yet. |
| **Verify** | Drop original files and `.ots` files together. Proofs are matched by name, and anything unmatched can be assigned manually with the **+** button. The table shows the format, the OTS status (Partial / Complete), the SHA-256 hash and the check status (**VALID** / PENDING / **INVALID**). Each row has two buttons that reveal the original file and its proof in the file explorer. |

### Where proofs are saved

- By default: `<folder>/OTS-Files/<file>.<ext>.ots`.
- Option: next to the original file, as `<folder>/<file>.<ext>.ots`.
- An existing proof that does not match the file is never deleted. It is kept as `.ots.bak` before a new one is written.

### Settings (gear icon)

- **Language**: English and Français.
- **Calendar servers**: defaults are `a.pool` / `b.pool.opentimestamps.org`, `a.pool.eternitywall.com` and `ots.btc.catallaxy.com`.
- **Block explorers**: any **Esplora**-compatible API, tried in order. Defaults are `mempool.space/api` and `blockstream.info/api`. You can also add a self-hosted instance.

Verification is "lite". The app fetches the Bitcoin block header from the explorer and checks that the header hashes to the announced block hash. It then compares the header's Merkle root with the proof. This means you trust the explorer to serve the correct chain. To remove that trust, use your own Esplora instance.

## Install

Download the installer for your system from [Releases](https://github.com/farsightbs/ots-batch-manager/releases):

- **Windows**: `.msi` or `.exe`.
- **macOS**: `.dmg` (universal, Intel and Apple Silicon).
- **Linux**: `.AppImage`, `.deb` or `.rpm`.

The builds are **not code-signed** yet, so each system will warn you the first time:

- **macOS**: right-click the app and choose **Open**. If macOS says the app is "damaged", run `xattr -cr "/Applications/OTS Manager.app"`.
- **Windows**: in the SmartScreen dialog, click **More info**, then **Run anyway**.

## Develop

Requirements: Rust (stable) and Node 18 or later. On Linux you also need the [Tauri system dependencies](https://v2.tauri.app/start/prerequisites/).

```bash
npm install
npm run dev        # run the app
npm run build      # build installers for the current OS
cargo test --manifest-path src-tauri/Cargo.toml                    # unit tests
cargo test --manifest-path src-tauri/Cargo.toml -- --ignored       # live tests (real calendars + explorers)
```

### Project layout

- **Stack**: [Tauri 2](https://tauri.app). The backend is in Rust and the UI is plain HTML/CSS/JS with no build step.
- `src-tauri/src/ots.rs`: the `.ots` format (parse, serialize, merge). Mirrors `python-opentimestamps`.
- `src-tauri/src/net.rs`: calendar servers and Esplora explorers.
- `src-tauri/src/main.rs`: the commands called by the UI (create / upgrade / verify), the path conventions and the calendar whitelist.
- `src/`: the UI. Translations live in `src/i18n.js`.

### Adding a language

In `src/i18n.js`, add an entry to `LANGUAGES` and a dictionary to `I18N`. Any key you leave out falls back to English.

### Releasing

Push a tag such as `v0.1.0`. GitHub Actions then builds all the installers into a draft release.

To regenerate the app icons from `app-icon.png`, run `npx tauri icon app-icon.png`.
