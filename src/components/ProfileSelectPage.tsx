import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Plus, Trash2, X, AlertTriangle, ArrowRight, Download, Upload,
  CheckCircle2, ChevronDown, RefreshCw, ArrowUpCircle, Heart, KeyRound, CloudCog,
  Fingerprint,
} from "lucide-react";
import AboutPanel from "./AboutPanel";
import RecoveryKitPanel from "./RecoveryKitPanel";
import logoUrl from "../assets/logo.png";
import { IS_ANDROID } from "../util/platform";
import { useConfirm, useTextPrompt } from "../ui/confirm";
import { describeVaultError } from "../util/vaultErrors";

// Result of the GitHub release check (backend: about::check_for_updates).
// `has_update` is true only when `latest` is a strictly newer semver than the
// running build. Mirrors the shape AboutPanel already consumes.
interface UpdateInfo { current: string; latest: string | null; has_update: boolean; release_url: string | null; }

// contracts/tauri-command-contract.md §1.
interface ProfileSummary {
  name: string;
  format: "sealed" | "legacy";
  revision: number;
  busy: boolean;
}

// contracts/tauri-command-contract.md §2, extended with "needs_password":
// the file's key matches a specific key on this device (another profile's
// own, or an unclaimed recovery-kit key) that isn't already unlocked, so
// `profile` names/describes it and the picker asks for its password before
// re-trying, rather than sending the user into the recovery-kit flow for a
// key this device already holds. A key already owned by a profile never
// restores over it — it always lands as a new, separately-named copy.
interface StagedImport {
  staging_id: string;
  disposition: "create_profile" | "restore_over" | "no_op" | "needs_password";
  profile: string | null;
  confirmation_needed: "none" | "older" | "conflict";
  incoming_revision: number;
  sender_name: string;
  created_at: number;
}

interface Props {
  onUnlocked: (profileName: string) => void;
}

// Cloud-sync folder markers for T114's warning (research.md Decision 11:
// `flock` gives no cross-machine exclusion inside one of these). A plain
// substring match on the resolved profiles directory path — good enough to
// warn, not meant to be exhaustive or authoritative.
const CLOUD_SYNC_MARKERS = [
  "Dropbox", "OneDrive", "Google Drive", "GoogleDrive", "iCloudDrive",
  "Mobile Documents", "Nextcloud", "pCloud", "Box Sync", "Syncthing",
];

const ProfileSelectPage = ({ onUnlocked }: Props) => {
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // The expanded row (by profile name). Expands to a password + Open + actions.
  const [selected, setSelected] = useState<string>("");
  const [password, setPassword] = useState("");

  // FR-054a: Touch ID/Windows Hello on the profile-selection screen itself —
  // available only when the backend already holds a cached quick-unlock
  // reference for this profile (i.e. it's been fully unlocked at least once
  // since that reference was last released). `forcePassword` is the same
  // "give up on biometrics, show the password form" fallback LockScreen.tsx
  // already uses for its own quick-unlock.
  const [quickAvailable, setQuickAvailable] = useState(false);
  const [forcePassword, setForcePassword] = useState(false);
  const [quickBusy, setQuickBusy] = useState(false);

  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newConfirmPassword, setNewConfirmPassword] = useState("");

  // Import is now stage-then-commit against `import_vault_pick`/`_commit`/
  // `_discard` (contract §2) — replaces the old sniff-and-copy pair.
  const [staged, setStaged] = useState<StagedImport | null>(null);
  const [importName, setImportName] = useState("");
  // Only ever set for a "needs_password" staged import — the password for
  // whichever specific key this file matched, re-sent to both the pick
  // retry and the eventual commit (T102).
  const [keyPassword, setKeyPassword] = useState("");

  // T073: set only on a VAULT_ROLLBACK-coded unlock failure. No race with
  // unmounting (unlike migration-notice, this is a synchronous catch on
  // the same call this screen is already showing), so it lives here rather
  // than in DesktopApp.
  const [rollbackInfo, setRollbackInfo] = useState<{ name: string; fileRevision: number; highWater: number } | null>(null);

  // T087, T088, T089: reachable from this screen only in "consume" mode —
  // "create" needs an already-open, already-unlocked profile to confirm
  // identity against (recovery_kit_create requires it), which never exists
  // here. The post-migration "create a kit now?" offer (T090) lives in
  // DesktopApp instead, where a profile really is open by the time it fires.
  const [recoveryOpen, setRecoveryOpen] = useState(false);

  const [aboutOpen, setAboutOpen] = useState(false);
  const [cloudSyncFolder, setCloudSyncFolder] = useState<string | null>(null);

  // A newer published release than the running build, if any. Set only when
  // one actually exists, so the notice by "About" appears solely when there's
  // something to announce.
  const [update, setUpdate] = useState<UpdateInfo | null>(null);

  const confirm = useConfirm();
  const textPrompt = useTextPrompt();

  const passwordInputRef = useRef<HTMLInputElement | null>(null);
  const nameInputRef = useRef<HTMLInputElement | null>(null);

  const reload = async () => {
    setLoading(true); setError(null);
    try {
      const list = await invoke<ProfileSummary[]>("list_profiles");
      setProfiles(list);
      // Keep whichever row was already open (if it still exists); otherwise
      // nothing is pre-selected — the picker starts closed, not auto-opened
      // to the first profile, so a fresh app launch never fires a Touch ID
      // prompt before the user has clicked anything.
      setSelected((prev) => (prev && list.some((p) => p.name === prev) ? prev : ""));
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { reload(); /* eslint-disable-next-line */ }, []);

  // T114: resolve once — the profiles directory doesn't move during a run.
  useEffect(() => {
    invoke<string>("profiles_dir_path")
      .then((dir) => {
        const hit = CLOUD_SYNC_MARKERS.find((m) => dir.toLowerCase().includes(m.toLowerCase()));
        if (hit) setCloudSyncFolder(hit);
      })
      .catch(() => {});
  }, []);

  // Check GitHub for a newer release once per app open (this page mounts on
  // launch and on every return to the picker). Best-effort and silent: the
  // fetch+semver-compare happens in Rust (about::check_for_updates), and any
  // failure — offline, rate-limited, no releases — simply shows nothing.
  useEffect(() => {
    invoke<UpdateInfo>("check_for_updates")
      .then((u) => { if (u.has_update && u.latest) setUpdate(u); })
      .catch(() => {});
  }, []);

  const openReleaseNotes = () => {
    if (update?.release_url) invoke("open_external_url", { url: update.release_url }).catch(() => {});
  };
  // Donate → the project's GitHub, anchored at #donate (placeholder section the
  // owner fills in later). Goes through the backend URL-opener like every other
  // external link so the CSP stays tight.
  const openDonate = () => {
    invoke("open_external_url", { url: "https://github.com/InDieStack-v2/SSHClientX#donate" }).catch(() => {});
  };

  // When the expanded row changes, reset + focus the password so opening a
  // profile is always "click row, type, Enter".
  useEffect(() => {
    setPassword("");
    setError(null);
    setRollbackInfo(null);
    setQuickAvailable(false);
    setForcePassword(false);
    requestAnimationFrame(() => passwordInputRef.current?.focus());
  }, [selected]);

  // FR-054a: check once per row-open whether a quick re-unlock is even
  // possible, so the button can render — deliberately does NOT auto-attempt
  // it. Auto-firing here duplicated the explicit "Unlock" button below (two
  // ways of triggering the same platform-authentication prompt, occasionally
  // both at once); the button is the only trigger now, same as the password
  // path requiring its own explicit click/Enter.
  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    invoke<boolean>("profile_quick_unlock_available", { name: selected })
      .then((available) => { if (!cancelled) setQuickAvailable(available); })
      .catch(() => { if (!cancelled) setQuickAvailable(false); });
    return () => { cancelled = true; };
  }, [selected]);

  useEffect(() => {
    if (creating) requestAnimationFrame(() => nameInputRef.current?.focus());
  }, [creating]);

  const sortedProfiles = [...profiles].sort((a, b) => a.name.localeCompare(b.name));

  const toggle = (name: string) => setSelected((prev) => (prev === name ? "" : name));

  // FR-054a: Touch ID/Windows Hello from a cold profile-selection screen —
  // no password typed. Same `select_profile` first step the password path
  // uses (writer claim, active_profile), then the backend supplies the DEK
  // from its cached quick-unlock entry instead of re-deriving it.
  const attemptQuickCold = async (name: string) => {
    setQuickBusy(true); setError(null); setRollbackInfo(null);
    try {
      await invoke("select_profile", { name });
      await invoke("vault_unlock_quick_cold", { name });
      onUnlocked(name);
    } catch (e) {
      // The backend already stops offering platform auth after enough
      // consecutive failures (FR-057) — nothing to count client-side, just
      // fall back to the password field.
      setError(describeVaultError(e).message);
      setForcePassword(true);
    } finally {
      setQuickBusy(false);
    }
  };

  const unlockSelected = async () => {
    if (!selected) { setError("Pick a profile first."); return; }
    if (!password) { setError("Type your password."); return; }
    setBusy(true); setError(null); setRollbackInfo(null);
    try {
      await invoke("select_profile", { name: selected });
      await invoke("setup_master_db", { password });
      // The migration-completion notice (if any) is handled at the
      // DesktopApp level — it survives this component's unmount, which
      // `onUnlocked` triggers right below, so there is no race to guard
      // against here.
      onUnlocked(selected);
    } catch (e) {
      const info = describeVaultError(e);
      if (info.code === "VAULT_ROLLBACK") {
        const prof = profiles.find((p) => p.name === selected);
        // Fetched only now, for this one profile — not for every profile
        // on every list load, which used to mean a keychain-access prompt
        // per profile just to render the picker (each profile's high-water
        // mark is its own keychain item).
        const highWater = await invoke<number>("profile_high_water", { name: selected }).catch(() => 0);
        setRollbackInfo({ name: selected, fileRevision: prof?.revision ?? 0, highWater });
      } else {
        setError(info.message);
      }
    } finally {
      setBusy(false);
    }
  };

  const resolveRollback = async (choice: "accept_older" | "restore_newer") => {
    if (!rollbackInfo) return;
    setBusy(true); setError(null);
    try {
      await invoke("rollback_resolve", {
        name: rollbackInfo.name,
        choice,
        revision: choice === "restore_newer" ? rollbackInfo.highWater : undefined,
      });
      setRollbackInfo(null);
      // The file's own revision changed underneath us either way — re-fetch
      // before retrying so a second rollback isn't spuriously reported.
      await reload();
      await unlockSelected();
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  const createNew = async () => {
    setError(null);
    if (!newName.trim()) { setError("Pick a name."); return; }
    if (!newPassword) { setError("Set a password."); return; }
    // The backend enforces this too — say it here so the rule shows up while
    // they're still typing, not as a rejection after they've confirmed it twice.
    if (newPassword.length < 8) { setError("Use at least 8 characters — this password protects every saved credential."); return; }
    if (newPassword !== newConfirmPassword) { setError("Passwords don't match."); return; }
    setBusy(true);
    try {
      await invoke("create_profile", { name: newName.trim(), password: newPassword });
      onUnlocked(newName.trim());
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  // T096: identity confirmation before export — the vault password proves
  // it's really you, even though the exported bytes are already encrypted
  // (FR-023). export_profile already generates the suggested filename
  // server-side (date/time/revision), nothing else to pass.
  const exportProfile = async (name: string) => {
    const pwd = await textPrompt({
      title: "Confirm your identity",
      message: `Enter the password for "${name}" to export it.`,
      password: true,
      okLabel: "Export",
      validate: (v) => (v ? null : "Password required."),
    });
    if (pwd === null) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      const saved = await invoke<string | null>("export_profile", { name, password: pwd });
      if (saved) setInfo(`Exported to ${saved}`);
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  // T106: stage-then-commit against the verified import pipeline.
  // `vaultBytes`, when given, is a vault file already read into memory (the
  // recovery-kit consume flow's own "vault file" pick) — skips a second
  // native dialog for the same file.
  const startImport = async (vaultBytes?: Uint8Array) => {
    setError(null); setInfo(null);
    setKeyPassword("");
    setBusy(true);
    try {
      const picked = await invoke<StagedImport | null>("import_vault_pick", {
        bytes: vaultBytes ? Array.from(vaultBytes) : undefined,
      });
      if (!picked) { setBusy(false); return; }
      setStaged(picked);
      setImportName(picked.disposition === "create_profile" ? (picked.profile || "") : "");
    } catch (e) {
      const info = describeVaultError(e);
      setError(info.message);
      if (info.code === "BOX_UNKNOWN_KEY") {
        // Genuinely unrecognized by every key this device holds — the only
        // way in is a recovery kit. A file matching a KNOWN key (this
        // device's own profile or an unclaimed recovery-kit key) never
        // reaches here — it comes back as a "needs_password" staged import
        // instead (FR-031).
        setRecoveryOpen(true);
      }
    } finally {
      setBusy(false);
    }
  };

  // Retries the same already-staged file with a password for whichever
  // specific key `startImport` identified — no re-picking the file.
  const submitKeyPassword = async () => {
    if (!staged || !keyPassword) return;
    setBusy(true); setError(null);
    try {
      const resumed = await invoke<StagedImport | null>("import_vault_pick", {
        keyPassword,
        retryStagingId: staged.staging_id,
      });
      if (resumed) {
        setStaged(resumed);
        setImportName(resumed.disposition === "create_profile" ? (resumed.profile || "") : "");
      }
    } catch (e) {
      // Staged file stays put on a wrong password — same field, try again.
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  const cancelImport = async () => {
    if (!staged) return;
    try { await invoke("import_vault_discard", { stagingId: staged.staging_id }); } catch { /* best-effort */ }
    setStaged(null);
    setKeyPassword("");
    setError(null);
  };

  // Cleans up an abandoned staging if the user navigates away mid-flow
  // (contract: staged copies are also cleaned up on commit and app exit,
  // but a mid-session abandon shouldn't linger either). The cleanup must
  // only run once, at actual unmount — but a `[]`-deps effect's own
  // closure captures `staged` as it was AT MOUNT (always null) forever,
  // so a plain `if (staged)` in that closure never sees a real value. A
  // ref kept in sync on every `staged` change sidesteps the stale closure:
  // the unmount-only cleanup below reads the ref's current value instead.
  const stagedRef = useRef<StagedImport | null>(null);
  useEffect(() => { stagedRef.current = staged; }, [staged]);
  useEffect(() => {
    return () => {
      if (stagedRef.current) invoke("import_vault_discard", { stagingId: stagedRef.current.staging_id }).catch(() => {});
    };
  }, []);

  const commitImport = async () => {
    if (!staged) return;
    if (staged.disposition === "create_profile" && !importName.trim()) {
      setError("Pick a name for the imported profile.");
      return;
    }
    setBusy(true); setError(null);
    try {
      // Per product direction: a key already owned by a profile is never
      // restored over — it always lands as a new, separately-named copy
      // (auto-suffixed "[IMPORT]" on a name collision), so re-importing a
      // backup can never clobber newer local changes, and the backend
      // reports back whichever name it actually used.
      const landed = await invoke<string>("import_vault_commit", {
        stagingId: staged.staging_id,
        name: staged.disposition === "create_profile" ? importName.trim() : undefined,
        keyPassword: keyPassword || undefined,
      });
      const wasNoOp = staged.disposition === "no_op";
      setStaged(null);
      setKeyPassword("");
      setInfo(wasNoOp ? "Already up to date — nothing imported." : `Imported as "${landed}".`);
      await reload();
      setSelected(landed);
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  // Remove the on-disk copy for good — there is no cloud to keep a spare in.
  const removeLocal = async (name: string) => {
    const ok = await confirm({
      title: "Remove profile",
      message: `Remove "${name}" from this device?\n\nThe encrypted file here is deleted. This can't be undone.`,
      destructive: true,
      okLabel: "Remove",
    });
    if (!ok) return;
    setBusy(true); setError(null);
    try {
      await invoke("delete_profile", { name });
      await reload();
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  const inputBase =
    "w-full h-11 px-4 bg-zinc-900/40 border border-white/5 rounded-xl text-[14px] text-zinc-50 placeholder:text-zinc-600 outline-none focus:border-primary/50 focus:bg-zinc-900/60 transition-colors";

  // First run (no profiles yet) drops straight into create. `creating` is the
  // explicit "New profile" toggle.
  const showCreate = creating || (!loading && profiles.length === 0);

  return (
    <div className="flex-1 flex items-center justify-center px-6 py-10 bg-background overflow-y-auto">
      <div className="w-full max-w-[340px] flex flex-col">
        {/* Brand */}
        <div className="flex flex-col items-center mb-8 select-none">
          <img
            src={logoUrl}
            alt=""
            draggable={false}
            className="h-28 w-auto max-w-full object-contain mb-4 drop-shadow-[0_0_32px_rgba(var(--primary),0.22)]"
          />
          <h1 className="text-[22px] font-semibold text-white tracking-tight leading-none">SSHClientX</h1>
          <p className="text-[10px] text-primary/80 mt-1.5 tracking-[0.22em] uppercase font-semibold">
            SSH & SFTP Client
          </p>
          <p className="text-[12.5px] text-zinc-500 mt-2">
            {loading
              ? " "
              : showCreate
                ? (profiles.length === 0 ? "Let's set up your first profile." : "Create a new profile.")
                : null}
          </p>
        </div>

        {cloudSyncFolder && (
          <div className="mb-3 px-3 py-2 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-200 text-[11.5px] flex items-center gap-2">
            <CloudCog size={13} className="shrink-0" />
            Your profiles folder looks like it's inside {cloudSyncFolder}. Two machines syncing the same file can conflict — this app doesn't coordinate across a sync service.
          </div>
        )}

        {error && (
          <div className="mb-3 px-3 py-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-200 text-[12.5px] flex items-center gap-2">
            <AlertTriangle size={13} className="shrink-0" /> {error}
          </div>
        )}

        {info && !error && (
          <div className="mb-3 px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-100 text-[12.5px] flex items-center gap-2">
            <CheckCircle2 size={13} className="shrink-0" /> <span className="truncate flex-1">{info}</span>
            <button onClick={() => setInfo(null)} className="text-emerald-200/70 hover:text-white shrink-0"><X size={13} /></button>
          </div>
        )}

        {/* T073: rollback-resolution dialog — names both revisions. */}
        {rollbackInfo && (
          <div className="mb-3 px-3 py-3 bg-zinc-900/60 border border-amber-500/30 rounded-lg space-y-2 animate-in fade-in">
            <div className="text-[11.5px] text-zinc-300 leading-snug">
              <span className="text-amber-300 font-semibold">"{rollbackInfo.name}"</span> on disk is revision{" "}
              <span className="font-mono">{rollbackInfo.fileRevision}</span>, but this device last saved revision{" "}
              <span className="font-mono">{rollbackInfo.highWater}</span>. It may have been restored from a backup.
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => resolveRollback("accept_older")}
                disabled={busy}
                className="flex-1 h-9 rounded-lg text-[12.5px] font-semibold bg-white/5 hover:bg-white/10 border border-white/10 text-zinc-200 disabled:opacity-50"
              >
                Use this file (revision {rollbackInfo.fileRevision})
              </button>
              <button
                onClick={() => resolveRollback("restore_newer")}
                disabled={busy}
                className="flex-1 h-9 rounded-lg text-[12.5px] font-semibold bg-primary text-black disabled:opacity-50"
              >
                Restore newer (revision {rollbackInfo.highWater})
              </button>
            </div>
          </div>
        )}

        {/* T106: staged import — branches on disposition. A popup rather
            than an inline card: it needs full attention (it's about to
            write a profile file), and the picker's own card underneath is
            mid-scroll/mid-form while this is up. */}
        {staged && (
          <div
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-3 animate-in fade-in"
            onClick={cancelImport}
          >
            <div
              className="w-full max-w-sm bg-[#121214] border border-primary/30 rounded-xl shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="shrink-0 px-4 py-3 border-b border-white/5 flex items-center justify-between">
                <span className="text-[12px] font-bold uppercase tracking-widest text-white flex items-center gap-2">
                  <Upload size={13} className="text-primary" /> Import vault
                </span>
                <button onClick={cancelImport} className="text-zinc-400 hover:text-white"><X size={16} /></button>
              </div>

              <div className="p-4 space-y-3">
                {/* The page's own error banner renders behind this popup
                    (fixed + z-50 covers the whole screen), so a failure
                    while this is open — e.g. a wrong password — needs its
                    own copy here or it's invisible. */}
                {error && (
                  <div className="px-3 py-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-200 text-[11.5px] flex items-center gap-2">
                    <AlertTriangle size={13} className="shrink-0" /> {error}
                  </div>
                )}
                {staged.disposition === "create_profile" && (
                  <>
                    <div className="text-[11.5px] text-zinc-300 leading-snug">
                      New vault from {staged.sender_name || "another device"} (revision {staged.incoming_revision}). Pick a name.
                    </div>
                    <input
                      value={importName}
                      onChange={(e) => setImportName(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && commitImport()}
                      className={inputBase + " h-9 text-[13px]"}
                      placeholder="Profile name"
                      autoFocus
                    />
                  </>
                )}
                {staged.disposition === "needs_password" && (
                  <>
                    <div className="text-[11.5px] text-zinc-300 leading-snug">
                      This file matches <span className="text-primary font-semibold">{staged.profile}</span> already on
                      this device. Enter its password to continue.
                    </div>
                    <input
                      type="password"
                      value={keyPassword}
                      onChange={(e) => setKeyPassword(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && submitKeyPassword()}
                      className={inputBase + " h-9 text-[13px]"}
                      placeholder="Password"
                      autoFocus
                    />
                  </>
                )}
                {/* FR-031/scope: a matched key never overwrites the profile
                    that already owns it — importing always adds a
                    separate copy instead (auto-suffixed on a name
                    collision), sharing the same key so it unlocks with
                    that profile's own password. */}
                {staged.disposition === "restore_over" && (
                  <div className="text-[11.5px] text-zinc-300 leading-snug">
                    This device already has <span className="font-semibold">"{staged.profile}"</span>. Importing will add
                    a separate copy (named "{staged.profile} [IMPORT]", or an auto-numbered variant), sharing its
                    password — <span className="font-semibold">"{staged.profile}"</span> itself is left untouched.
                  </div>
                )}
                {staged.disposition === "no_op" && (
                  <div className="text-[11.5px] text-zinc-300 leading-snug">
                    This file matches <span className="font-semibold">"{staged.profile}"</span> exactly — nothing to import.
                  </div>
                )}
                <div className="flex gap-2">
                  <button
                    onClick={staged.disposition === "needs_password" ? submitKeyPassword : () => commitImport()}
                    disabled={
                      busy ||
                      (staged.disposition === "create_profile" && !importName.trim()) ||
                      (staged.disposition === "needs_password" && !keyPassword)
                    }
                    className="flex-1 h-9 rounded-lg text-[12.5px] font-semibold bg-primary text-black disabled:opacity-50"
                  >
                    {busy
                      ? (staged.disposition === "needs_password" ? "Checking…" : "Importing…")
                      : staged.disposition === "no_op"
                        ? "Dismiss"
                        : staged.disposition === "needs_password"
                          ? "Continue"
                          : "Import"}
                  </button>
                  <button
                    onClick={cancelImport}
                    className="h-9 px-3 rounded-lg text-[12.5px] font-semibold text-zinc-300 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {loading ? (
          <div className="text-center text-zinc-500 text-[12.5px] py-6">Loading…</div>
        ) : showCreate ? (
          /* ---- Create a profile ---- */
          <div className="space-y-3 animate-in fade-in">
            <input
              ref={nameInputRef}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Profile name"
              className={inputBase}
            />
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Password"
              className={inputBase}
            />
            <input
              type="password"
              value={newConfirmPassword}
              onChange={(e) => setNewConfirmPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && createNew()}
              placeholder="Confirm password"
              className={inputBase}
            />
            <button
              onClick={createNew}
              disabled={busy}
              className="w-full h-11 rounded-xl text-[14px] font-semibold bg-primary text-black hover:shadow-[0_0_24px_rgba(var(--primary),0.3)] disabled:opacity-50 flex items-center justify-center transition-all"
            >
              {busy ? "Creating…" : "Create profile"}
            </button>

            <div className="flex gap-2 pt-1">
              {profiles.length > 0 && (
                <button
                  onClick={() => { setCreating(false); setNewName(""); setNewPassword(""); setNewConfirmPassword(""); setError(null); }}
                  className="flex-1 h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5"
                >
                  <X size={12} /> Cancel
                </button>
              )}
              {!IS_ANDROID && (
                <button
                  onClick={() => startImport()}
                  disabled={busy}
                  title="Import an exported .sshclientx or .submarine file"
                  className="flex-1 h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
                >
                  <Upload size={12} /> Import
                </button>
              )}
            </div>

            <button
              onClick={() => setRecoveryOpen(true)}
              className="w-full h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5"
            >
              <KeyRound size={12} /> Recover with a kit
            </button>

            <p className="text-[11.5px] text-zinc-500 leading-relaxed text-center px-2 pt-1">
              Profiles are encrypted. If you forget the password, the data is gone for good.
            </p>
          </div>
        ) : (
          /* ---- Your profiles ---- */
          <div className="space-y-3">
            <div className="px-0.5">
              <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">Your profiles</span>
            </div>

            <div className="rounded-xl border border-white/5 bg-white/[0.02] overflow-hidden divide-y divide-white/5">
              {sortedProfiles.map((p) => {
                const open = selected === p.name;
                return (
                  <div key={p.name}>
                    <button
                      onClick={() => toggle(p.name)}
                      disabled={p.busy}
                      className={`w-full flex items-center gap-2.5 px-3 h-11 text-left transition-colors disabled:opacity-50 ${open ? "bg-white/[0.03]" : "hover:bg-white/[0.02]"}`}
                    >
                      <span className="flex-1 min-w-0 truncate text-[13.5px] text-zinc-100">{p.name}</span>
                      {p.format === "legacy" && (
                        <span className="shrink-0 text-[9.5px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
                          will upgrade
                        </span>
                      )}
                      {p.busy && (
                        <span className="shrink-0 text-[9.5px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
                          in use elsewhere
                        </span>
                      )}
                      <ChevronDown size={13} className={`text-zinc-600 shrink-0 transition-transform ${open ? "rotate-180" : ""}`} />
                    </button>

                    {open && (
                      <div className="px-3 pb-3 pt-1 bg-black/20 space-y-2.5 animate-in fade-in">
                        {quickAvailable && !forcePassword ? (
                          <div className="flex gap-2">
                            <button
                              onClick={() => attemptQuickCold(p.name)}
                              disabled={quickBusy}
                              className="flex-1 h-10 rounded-lg text-[13px] font-semibold bg-primary text-black disabled:opacity-50 flex items-center justify-center gap-1.5 transition-all"
                            >
                              {quickBusy ? <RefreshCw size={14} className="animate-spin" /> : <Fingerprint size={14} />}
                              {quickBusy ? "Waiting…" : "Unlock"}
                            </button>
                            <button
                              onClick={() => setForcePassword(true)}
                              title="Use password instead"
                              className="h-10 px-3 rounded-lg text-[12px] font-medium text-zinc-400 hover:text-zinc-100 bg-white/[0.03] border border-white/10 hover:bg-white/[0.07] shrink-0 transition-colors"
                            >
                              Password
                            </button>
                          </div>
                        ) : (
                          <div className="flex gap-2">
                            <input
                              ref={passwordInputRef}
                              type="password"
                              placeholder="Password"
                              value={password}
                              onChange={(e) => setPassword(e.target.value)}
                              onKeyDown={(e) => e.key === "Enter" && unlockSelected()}
                              className="flex-1 h-10 px-3.5 bg-zinc-900/50 border border-white/5 rounded-lg text-[13.5px] text-zinc-50 placeholder:text-zinc-600 outline-none focus:border-primary/50 transition-colors"
                            />
                            <button
                              onClick={unlockSelected}
                              disabled={busy || !password}
                              title="Open"
                              className="h-10 px-3.5 rounded-lg text-[13px] font-semibold bg-primary text-black hover:shadow-[0_0_20px_rgba(var(--primary),0.3)] disabled:opacity-40 flex items-center gap-1.5 shrink-0 transition-all"
                            >
                              {busy ? <RefreshCw size={14} className="animate-spin" /> : <>Open <ArrowRight size={14} /></>}
                            </button>
                          </div>
                        )}
                        {quickAvailable && forcePassword && (
                          <button
                            onClick={() => { setForcePassword(false); attemptQuickCold(p.name); }}
                            className="text-[11.5px] text-zinc-500 hover:text-zinc-300"
                          >
                            Try quick unlock again
                          </button>
                        )}
                        <div className="flex flex-wrap items-center gap-1.5">
                          {!IS_ANDROID && (
                            <RowAction onClick={() => exportProfile(p.name)} disabled={busy} icon={<Download size={12} />} label="Export" />
                          )}
                          <RowAction onClick={() => removeLocal(p.name)} disabled={busy} icon={<Trash2 size={12} />} label="Remove" danger />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="flex gap-2 pt-0.5">
              <button
                onClick={() => setCreating(true)}
                className="flex-1 h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5"
              >
                <Plus size={12} /> New profile
              </button>
              {!IS_ANDROID && (
                <button
                  onClick={() => startImport()}
                  disabled={busy}
                  title="Import an exported .sshclientx or .submarine file"
                  className="flex-1 h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
                >
                  <Upload size={12} /> Import
                </button>
              )}
            </div>
            <button
              onClick={() => setRecoveryOpen(true)}
              className="w-full h-9 rounded-lg bg-white/[0.02] border border-white/5 hover:bg-white/5 hover:border-white/10 text-zinc-400 hover:text-zinc-100 text-[12px] font-medium transition-colors flex items-center justify-center gap-1.5"
            >
              <KeyRound size={12} /> Recover with a kit
            </button>
          </div>
        )}

        {/* About + Donate — a matched pair of pills, with a live "new version"
            notice underneath when one is available. */}
        <div className="mt-4 flex flex-col items-center gap-2.5">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setAboutOpen(true)}
              className="h-8 px-4 rounded-lg text-[12.5px] font-bold text-zinc-200 bg-white/[0.04] border border-white/10 hover:bg-white/[0.09] hover:text-white transition-colors"
            >
              About
            </button>
            <button
              onClick={openDonate}
              title="Support SSHClientX on GitHub"
              className="h-8 px-4 rounded-lg text-[12.5px] font-bold text-rose-200 bg-rose-500/10 border border-rose-500/25 hover:bg-rose-500/20 hover:text-rose-100 transition-colors flex items-center gap-1.5"
            >
              <Heart size={13} className="fill-rose-400/40" /> Donate
            </button>
          </div>
          {update?.has_update && update.latest && (
            <button
              onClick={openReleaseNotes}
              title="Open the release notes on GitHub"
              className="group flex items-center gap-1.5 text-[10.5px] text-primary/90 hover:text-primary animate-in fade-in slide-in-from-bottom-1 duration-700"
            >
              {/* pulsing dot — the "something new" signal */}
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary/70 opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-primary" />
              </span>
              <ArrowUpCircle size={11} className="shrink-0" />
              <span>New version <span className="font-mono font-semibold">v{update.latest}</span> available</span>
              <span className="opacity-60 transition-transform group-hover:translate-x-0.5">→</span>
            </button>
          )}
        </div>
      </div>

      <AboutPanel isOpen={aboutOpen} onClose={() => setAboutOpen(false)} />
      <RecoveryKitPanel
        isOpen={recoveryOpen}
        mode="consume"
        onClose={() => setRecoveryOpen(false)}
        onImportNow={(vaultBytes) => { setRecoveryOpen(false); startImport(vaultBytes); }}
        onProfileLanded={async (name) => {
          setInfo(`Profile "${name}" is ready — sign in below.`);
          await reload();
          setSelected(name);
        }}
      />
    </div>
  );
};

// A compact secondary action inside an expanded row.
const RowAction = ({
  onClick, disabled, icon, label, danger,
}: {
  onClick: () => void; disabled?: boolean; icon: React.ReactNode; label: string; danger?: boolean;
}) => (
  <button
    onClick={onClick}
    disabled={disabled}
    title={label}
    className={`h-7 px-2 rounded-md text-[11px] font-medium border flex items-center gap-1 disabled:opacity-40 transition-colors ${
      danger
        ? "text-rose-300/90 bg-rose-500/5 border-rose-500/15 hover:bg-rose-500/15 hover:text-rose-200"
        : "text-zinc-400 bg-white/[0.03] border-white/10 hover:bg-white/[0.07] hover:text-zinc-100"
    }`}
  >
    {icon} {label}
  </button>
);

export default ProfileSelectPage;
