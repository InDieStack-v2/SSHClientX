# Repository Guidelines

SSHClientX is a Tauri 2 + Rust + React SSH/SFTP client (terminal, dual-pane SFTP, tunnels, desktop folder-mirror) for Windows, macOS, Linux, and Android. Fully local — no account, no backend server; a vault never leaves the device it's on except by manual export/import. Fork of Submarine; crate `sshclientx`, lib `sshclientx_lib`, bundle id `com.sshclientx.app`. MIT code (copyright Sina Xhpm); name/logo are marks. Governance: `.specify/memory/constitution.md` (wins over README).

## Architecture & Data Flow

Thin desktop bin `src-tauri/src/main.rs` calls `sshclientx_lib::run()`. The same `run()` is the Android entry (`#[cfg_attr(mobile, tauri::mobile_entry_point)]`). Webview is UI only.

```
ProfileSelectPage --invoke select_profile / setup_master_db--> DbState (Argon2id → AES-256-GCM vault)
DesktopApp --invoke snake_case { camelCase }--> Rust commands
         <--listen kebab-id events-- SshState / MirrorMap / MonitorMap
vault save: sqlite serialize → zstd → AES-GCM → <app_data>/profiles/<name>.sshclientx
```

- Privileged work (crypto, russh, SFTP, local FS, tunnels, mirror, Docker) **must** stay in Rust `#[tauri::command]`s.
- Do **not** implement Argon2/AES in TS; do **not** persist credentials in `localStorage` / IndexedDB.
- TOFU: events `fingerprint-prompt-{sid}` require `verify_fingerprint_response({ nonce, accepted })`. Monitor pollers use `known_hosts` only — no fingerprint UX.
- Terminal payload is **base64** on `terminal-output-{tid}`, not a JSON byte array.

## Key Directories

| Path | Owns |
|------|------|
| `src/DesktopApp.tsx` | Unlocked shell: sidebar views, session tabs, Wall |
| `src/components/` | Session/terminal/SFTP/tunnels/mirror/Docker/Info/monitor UI |
| `src/fs/` | `FileProvider`; transfers call `sftp_*` / `local_*` — bytes do not stream through JS |
| `src/hooks/`, `src/ui/`, `src/util/platform.ts` | `useTauriListen`, viewport; confirm/broadcast; `IS_ANDROID` vs `useIsNarrow()` |
| `src-tauri/src/lib.rs` | Vault, SQLite, most commands, `guard_local_path`, `generate_handler`, `run()` |
| `src-tauri/src/ssh_manager.rs` | `SshState`, TOFU `ClientHandler` |
| `src-tauri/src/tunnel.rs` | L/D/R forwards on `SshState` |
| `src-tauri/src/mirror.rs` | Two-way sync + watcher; `.submarine-trash` / `.submarine-tmp` |
| `src-tauri/src/docker.rs` | Allow-listed `docker` over exec; no `rm`/`remove`/`down` |
| `src-tauri/src/hlc.rs` | Hybrid logical clock; stamps `updated_at` locally (no backend consumes it) |
| `src-tauri/src/monitor.rs` | Separate SSH pollers (not interactive `SshState`) |
| `src-tauri/src/about.rs` | Version + GitHub `InDieStack-v2/SSHClientX` |
| `src-tauri/capabilities/` | Minimal ACL |
| `scripts/` | Android env + USB `adb reverse` helper |
| `.specify/` | Spec Kit + constitution |

New SSH/SFTP/crypto behavior extends those Rust modules — do not grow ad-hoc JS. Do not reintroduce a network backend, account system, or cloud sync — see `.specify/memory/constitution.md` Principle I and `specs/001-local-only-mode/` for why they were removed.

## Development Commands

```bash
npm install
npm run typecheck          # tsc --noEmit (strict)
npm run tauri dev          # Vite :1420 + Rust (OpenSSL-free default)
npm run tauri build        # still default features unless you pass flags
cd src-tauri && cargo test
```

Release/RSA host keys (needs Perl on Windows):

```bash
npm run tauri build -- --features full-ssh-algos
```

Android:

```powershell
. .\scripts\android-env.ps1    # machine-local SDK path inside the script
npm run android:init
npm run android:dev            # adb reverse 1420/1421 + --host 127.0.0.1
npm run android:dev:raw        # skip USB helper
npm run android:build          # apk aarch64+armv7 + full-ssh-algos
```

Release: `git tag vX.Y.Z && git push origin vX.Y.Z`. CI stamps `package.json` / `Cargo.toml` / `tauri.conf.json` (keep versions in lockstep). Do not run a extra `npm run build` in CI — `tauri-action` already runs `beforeBuildCommand`.

## Code Conventions & Common Patterns

**IPC:** `invoke("setup_master_db", { password })`. Commands `snake_case`; args `camelCase` (`sessionId`, `serverId`). Events `kebab-case-{id}`.

**Errors:** `Result<T, String>` with prefixes `[SYSTEM] [CRYPTO] [VAULT] [DATABASE] [STATE] [FILE] [SSH] [UPDATE] [OPEN]`. Wrong vault password → `[CRYPTO] DECRYPT_FAILURE`. SFTP overwrite probe → `EXISTS:<path>` then retry `overwrite: true`.

**Async:** Tauri `async fn` + `tauri::async_runtime::spawn` for PTY/tunnels/mirror/monitor. `spawn_blocking` for Argon2, vault serialize/encrypt/fsync. Never hold a rusqlite `Mutex` across `.await`. Never run Argon2 on the tokio worker pool.

**State:** Rust `.manage`: `DbState` (conn + `Zeroizing` master key), `SshState`, `MirrorMap`, `MonitorMap`, `DockerStreams`. UI prefs only in `localStorage` under `sshclientx-*` (colors, font, SFTP layout). Dispatch `sshclientx-settings-changed` after font changes.

**Platform:** `isMobile` = `useIsNarrow() < 640` (resized desktop). `IS_ANDROID` gates export/import, folder picker, live-edit, Open/Reveal. Desktop-only crates (`rfd`, `open`, `window-state`) are `cfg(not(target_os = "android"))`. Secondary transports use real session ids `${id}::sftp` / `${id}::fwd`.

**Security (non-negotiable):**

- No `shell:*`, `fs:*`, or `webview:*` capabilities. `opener:allow-open-url` only. `window-state:default` stays in `capabilities/desktop.json`.
- Do not widen CSP (`script-src 'self'`; `connect-src` self + IPC only — no network origin; `frame-src`/`object-src` none). There is no backend to add one for.
- Path guards: `guard_local_path`, `is_safe_dir_entry_name`, `safe_temp_leaf_name`, `app_temp_root`. Docker: `shq` / `is_safe_name`; no string-built `sh -c`.
- `open_external_url`: http(s) only.

**Do not change (compat freeze):** vault magic `OMNV`; remote `.submarine-trash` / `.submarine-tmp`; backfill domain `b"submarine-backfill-v1\0"`; Argon2 params (`m_cost` 64 MiB, `t=3`, `p=4`); CI secrets `SUBMARINE_KEYSTORE_*`. Write vaults as `.sshclientx`; still **read** leftover `.submarine` files.

## Important Files

- `src/main.tsx`, `src/App.tsx`, `src/DesktopApp.tsx` — UI entry
- `src-tauri/src/main.rs`, `src-tauri/src/lib.rs` — native entry + command registry
- `src-tauri/tauri.conf.json` — `productName`, identifier, CSP, Vite `:1420`
- `src-tauri/tauri.android.conf.json` — decorated Android window, `minSdkVersion` 24
- `src-tauri/capabilities/default.json`, `desktop.json`
- `src-tauri/Cargo.toml` — `default = []`; `full-ssh-algos` optional
- `package.json`, `vite.config.ts` (port 1420 `strictPort`, ignore `src-tauri/**`)
- `.github/workflows/release.yml`, `packaging/arch/PKGBUILD`
- `.specify/memory/constitution.md`

## Runtime/Tooling Preferences

- **npm** + `package-lock.json` only. Do not add bun/pnpm/yarn.
- Node 20+, TypeScript strict, Vite 5, React 18, Tailwind 3, xterm.js.
- Rust edition 2021, MSRV 1.70; CI uses stable. Tauri 2.1 / `@tauri-apps/api` ^2.11.
- Default `cargo build` stays OpenSSL/Perl-free. `full-ssh-algos` is for release + `android:build` only.
- `scripts/android-env.ps1` hard-codes a machine SDK path — edit locally; do not treat as portable CI.
- No ESLint/Prettier config in-repo; match surrounding style.

## Testing & QA

Rust in-crate `#[cfg(test)]` only (~18 tests). No Jest/Vitest/Playwright; no `npm test`.

```bash
cargo test --manifest-path src-tauri/Cargo.toml
# modules: sync_trigger_tests (local uuid/updated_at stamping, still used —
#          see hlc.rs), tests (is_safe_dir_entry_name), hlc::tests, tunnel_tests
npm run typecheck
```

Covered: HLC, local sync-trigger stamping, tunnel bind/pump, SFTP name traversal.

**Not covered:** UI, live SSH/TOFU, `guard_local_path`, vault disk I/O, mirror, Docker, monitor, Android. Constitution still requires tests when you touch vault/path guards/host keys.

Manual smoke: `npm run tauri dev`; Android `npm run android:dev`. Release CI builds artifacts; it does not run `cargo test`.
