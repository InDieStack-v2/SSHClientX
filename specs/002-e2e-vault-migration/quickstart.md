# Quickstart: validating the encrypted vault migration

**Feature**: `002-e2e-vault-migration` | **Date**: 2026-09-06

How to prove this feature works end to end. Scenarios map to the spec's Success Criteria;
details of the container and the IPC surface are in [contracts/](contracts/) and
[data-model.md](data-model.md) rather than repeated here.

---

## 0. Before you start

> **This feature rewrites real vault files and deletes the pre-migration copy once you
> acknowledge the notice.** Back up your profiles directory before testing, and prefer a
> throwaway profile for anything destructive.

| Platform | Profiles directory |
| --- | --- |
| macOS | `~/Library/Application Support/com.sshclientx.app/profiles/` |
| Windows | `%APPDATA%\com.sshclientx.app\profiles\` |
| Linux | `~/.local/share/com.sshclientx.app/profiles/` |

```bash
cp -r "<profiles dir>" ~/sshclientx-profiles-backup
```

You also need a **second machine** (or a second OS user account with its own secure store)
for the cross-device scenarios. A VM is fine. What matters is that it has its own keychain —
copying a disk image that includes the keystore defeats the point of the test.

## 1. Build and run

```bash
npm install
npm run typecheck          # frontend must typecheck
cargo test --manifest-path src-tauri/Cargo.toml    # Rust module tests
npm run tauri dev          # run the app
```

Constitution requires Rust changes touching vault, path guards, or host-key handling to ship
with module tests in the same crate — `cargo test` is a gate, not a convenience.

---

## 2. Scenario A — migration is safe and complete (SC-001, SC-009)

**Setup**: start from a build *before* this feature, create a profile with at least one
server, one SSH key, and some command history. Note what you created. Then switch to the
feature build.

1. Launch, pick the profile, enter its password.
2. Expect: the vault opens, everything you created is present, and a one-time notice says
   the file will no longer open on your other machines.
3. Before acknowledging, check the profiles directory — the legacy `OMNV` file is still
   there.
4. Acknowledge the notice. The legacy file is now gone.
5. Confirm the remaining file starts with `SSHCLTX1`:

```bash
head -c 8 "<profiles dir>/<name>.sshclientx"; echo
```

6. Search every app-written path for the key. Nothing should match:

```bash
grep -rl "BEGIN OPENSSH PRIVATE KEY" "<profiles dir>" || echo "clean"
```

**Fails if**: any content is missing, the legacy file survives acknowledgement, or plaintext
key material appears anywhere on disk.

---

## 3. Scenario B — the file no longer travels (SC-002)

1. Copy the migrated `.sshclientx` to the second machine's profiles directory.
2. Launch there and try to open it, using the correct password.

**Expect**: refused as sealed for another device's key, pointing at the recovery kit. Not a
wrong-password error, not a corrupt-file error.

**Fails if**: it opens, or the message is generic.

---

## 4. Scenario C — recovery kit, both forms (SC-006, SC-010, SC-013, SC-013a, SC-014)

> The kit is sealed under a **recovery passphrase** chosen for it — *not* machine A's vault
> password. A's vault password is never typed on B at any point in this scenario. If you find
> yourself entering it, that is a failure.

On machine A, for each form in turn:

1. Create a recovery kit. Choose **phrase**, then repeat the whole scenario with **file**.
   You will be asked for a recovery passphrase; use one that is *not* your vault password so
   the distinction is actually being tested.
2. For the file form, confirm the save dialog does not default to a cloud-synced or
   backed-up folder.
3. Move the kit and an exported vault file to machine B.
4. **SC-013a** — before moving on, inspect both kit forms for machine A's vault password.
   For the file form: `strings kit.file | grep -F "<your vault password>"`. For the phrase
   form: read the words. Neither may contain it, in any encoding.
5. On B, consume the kit **without** the recovery passphrase → expect refusal, nothing
   established.
6. Consume it with machine A's **vault password** instead of the recovery passphrase →
   expect the same refusal. This is the specific regression this scenario exists to catch.
7. Consume it with a **wrong** recovery passphrase → expect "wrong passphrase for this kit",
   not "damaged kit".
8. For the phrase form, mistype one word → expect a phrase-entry error *before* any
   passphrase prompt.
9. Consume correctly → B prompts you to set a vault password **for this device**. Set one
   that differs from A's.
10. Import the vault file → a new profile appears owning that key, and it opens with **B's**
    password.
11. Confirm the vault still opens on B after deleting the kit from B's disk.
12. Change the vault password on A → confirm B is unaffected and still opens with its own.

**Fails if**: kit plus file alone reveals anything, A's vault password appears in a kit or
opens anything on B, the error kinds are indistinguishable, access depends on the kit staying
present, or a password change on A affects B.

---

## 5. Scenario D — import failure vocabulary (SC-004, SC-005)

Prepare five files from one good export:

```bash
cp good.sshclientx older.sshclientx        # export again after a change; keep the earlier one
cp good.sshclientx corrupt.sshclientx
printf '\x00' | dd of=corrupt.sshclientx bs=1 seek=200 count=1 conv=notrunc
head -c 100 good.sshclientx > truncated.sshclientx
echo "not a vault" > garbage.sshclientx
# plus a file exported from a different device for the unknown-key case
```

Import each. Expect five clearly different messages: not a vault file, damaged or tampered,
sealed for another device's key, older than local, and — after editing the vault on both
sides to the same revision — a same-revision conflict.

After each failure, reopen the local profile and confirm its content is unchanged.

**Fails if**: any two failures read the same, or the local vault changes after a rejection.

---

## 6. Scenario E — lock lifecycle (SC-015, SC-017, SC-018)

1. Unlock a profile and start a long SFTP transfer.
2. Alt-tab to another window. Expect: the vault locks, all content is concealed **including
   terminal scrollback**, and the transfer keeps running.
3. Alt-tab back. Expect: platform authentication only — **no password prompt**.
4. Repeat 20 times. The transfer must complete and no connection may drop.
5. Now lock the OS screen, or wait out the idle timeout. Expect: on return, the **password**
   is required and platform authentication alone is refused.
6. On a machine with no biometric enrolled, repeat: the password works everywhere and no
   feature is withheld.

**Fails if**: a password is demanded on an alt-tab return, biometrics satisfy an idle or
screen-lock wake, connections drop, or scrollback stays readable while locked.

---

## 7. Scenario F — rollback detection (SC-023)

1. Open a profile, make a change, let it save. Note the revision.
2. Quit the app. Copy the current file aside, then restore an older copy over it.
3. Reopen the profile.

**Expect**: a possible-rollback warning naming both revisions, with the choice to accept the
older file or restore a newer revision from history. Accept it, reopen — the warning must not
reappear.

**Fails if**: the older file opens silently, or the warning repeats forever after acceptance.

---

## 8. Scenario G — single writer (SC-020, SC-021)

1. Open a profile. Launch a second instance and try to open the same profile → refused,
   naming the profile.
2. `kill -9` the first instance. Launch again and open that profile.

**Expect**: it opens, with no manual file deletion.

**Fails if**: the second instance opens it concurrently, or a killed instance leaves the
profile permanently blocked.

---

## 9. Scenario H — secure store refusal (SC-022)

1. Trigger an operation that reads the key and **dismiss** the OS keychain prompt.
2. Expect: a retryable message offering another attempt — not the no-secure-store refusal —
   with unsaved changes intact.
3. Retry and allow it. The operation completes.
4. On Linux only, stop the secret service entirely and create a new profile. Expect the
   terminal no-secure-store refusal, saying what to change on the machine.

**Fails if**: a dismissed prompt reports the machine as unable to run the app, or unsaved
work is lost.

---

## 10. Scenario I — diagnostics stay clean (SC-024, SC-025)

After running scenarios A through H, read the diagnostic log end to end.

**Expect**: enough to identify which failure happened and which file was involved — outcome
codes, revisions, short identifier and hash prefixes.

**Fails if**: it contains any hostname, file path, user-chosen filename, credential, recovery
phrase word, or vault content.

---

## 11. Android (SC-012)

1. Migrate on desktop, create a kit, export the vault file.
2. On Android, use the recovery flow with the kit, the file, and the kit's **recovery
   passphrase** together — not the desktop's vault password.
3. Set a vault password for the phone when prompted.
4. Expect: the vault opens, is usable, and **saves**.
5. Try Settings → Export and Import on Android → both refuse, naming the platform.
6. Try creating a new profile on Android → refuses, naming desktop as where to do it.
7. Confirm an existing unmigrated Android vault still opens and is never nagged to migrate.

---

## 12. Coverage map

| Scenario | Success Criteria |
| --- | --- |
| A | SC-001, SC-003, SC-009 |
| B | SC-002, SC-011 |
| C | SC-006, SC-010, SC-013, SC-013a, SC-014 |
| D | SC-004, SC-005, SC-008, SC-026 |
| E | SC-007, SC-015, SC-016, SC-017, SC-018, SC-019 |
| F | SC-023 |
| G | SC-020, SC-021 |
| H | SC-022 |
| I | SC-024, SC-025 |
| Android | SC-012 |
