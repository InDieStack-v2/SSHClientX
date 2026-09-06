# Quickstart: Validating Local-Only Mode

Prerequisites:

- A built app (`npm run tauri dev` or a packaged build).
- A test machine where you can fully disconnect network access
  (airplane mode / unplug Ethernet / disable Wi-Fi).
- A vault file created by the prior (pre-removal) version of the app,
  ideally one that was previously cloud-linked or shared, for the
  migration scenario.
- Optional: a packet-capture tool (Wireshark, Little Snitch, `nettop`,
  etc.) scoped to the app's process, for the network-verification
  scenario.

## Scenario 1 — Fresh install works fully offline

Validates: User Story 1, FR-001, FR-002, SC-001, SC-002.

1. Disconnect the test machine from all networks.
2. Launch the app. The very first screen MUST be local vault
   create/select — no sign-up, sign-in, or "connect to cloud" step.
3. Create a new local vault (set a master password).
4. Add a server entry pointing at a reachable host on the local
   network (e.g. another LAN machine, or a local `sshd`).
5. Connect over SSH and confirm the terminal opens and works.
6. Open a local port forward / tunnel to a service on the target host
   and confirm it connects successfully (SC-002 "tunneling").
7. Set up a folder mirror between a local directory and a directory on
   the target host and confirm a file change propagates in both
   directions (SC-002 "mirroring").
8. Confirm steps 2–7 all succeeded with the machine still fully
   disconnected. Elapsed time from launch to a successful SSH
   connection (step 5) should be under 2 minutes.

## Scenario 2 — No hidden network calls to the removed backend

Validates: FR-003, FR-004, SC-003.

1. Reconnect network access; start a packet capture scoped to the
   app's process.
2. Repeat vault creation, then add/edit a server, credential, and
   note; connect; transfer a file; close the app.
3. Inspect the capture: there MUST be zero requests to the former
   backend hosts (`submarine.sinaxhpm.com`, `api.sinaxhpm.com`). SSH/
   SFTP traffic to the user's own target host is expected. A request
   to `api.github.com` (the pre-existing update check) is expected and
   is explicitly out of scope for this feature — see
   [research.md](research.md) Decision 7.

## Scenario 3 — Existing vaults keep working, silently

Validates: User Story 2, FR-007, FR-008, FR-012.

1. Copy the pre-removal-version vault file into the updated app's
   profile directory.
2. Open it with its correct master password.
3. Confirm every previously saved server, credential, key, folder,
   command, and note is present and usable.
4. Confirm no cloud-linked status, sync controls, or sharing UI
   appears anywhere for this profile.
5. Confirm no migration notice, banner, or dialog appears about the
   change — the transition MUST be silent.
6. Separately, place a leftover `cloud_token.json` file (copied from a
   prior version's app-data directory, or a dummy file with that name)
   in the updated app's app-data directory, then launch the app with a
   packet capture running. Confirm the app starts normally, makes no
   network call related to that file, and the file is simply ignored
   (FR-008).

## Scenario 4 — No leftover account/sharing surface

Validates: User Story 3, SC-005.

1. Walk every screen: profile picker, profile settings/status panel,
   sidebar, any help/about screen.
2. Confirm no control, label, or text mentions signing in, cloud
   accounts, multi-device sync, or profile sharing/inviting.
3. Read `README.md` and confirm it no longer markets "zero-knowledge
   cloud sync" or an account dashboard (see
   [contracts/tauri-command-contract.md](contracts/tauri-command-contract.md)
   for the exact sections that must be gone).

## Pass/fail

All four scenarios must pass, with no exceptions, for this feature to
be considered complete.
