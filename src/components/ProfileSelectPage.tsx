import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Plus, Trash2, X, AlertTriangle, ArrowRight, Download, Upload,
  CheckCircle2, ChevronDown, RefreshCw, ArrowUpCircle, Heart, KeyRound, CloudCog,
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

// contracts/tauri-command-contract.md §1, plus `high_water` (not in the
// documented contract — added alongside `list_profiles` specifically so
// the rollback dialog below can name both revisions without a separate
// command or a structured-error mechanism the rest of the backend doesn't
// have; see src-tauri/src/lib.rs's `list_profiles`).
interface ProfileSummary {
  name: string;
  format: "sealed" | "legacy";
  revision: number;
  busy: boolean;
  high_water: number;
}

// contracts/tauri-command-contract.md §2. `profile` is only set for
// `restore_over`; `confirmation_needed` is "none" unless the disposition
// needs an explicit choice first.
interface StagedImport {
  staging_id: string;
  disposition: "create_profile" | "restore_over" | "no_op";
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

  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newConfirmPassword, setNewConfirmPassword] = useState("");

  // Import is now stage-then-commit against `import_vault_pick`/`_commit`/
  // `_discard` (contract §2) — replaces the old sniff-and-copy pair.
  const [staged, setStaged] = useState<StagedImport | null>(null);
  const [importName, setImportName] = useState("");

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
      setSelected((prev) => (prev && list.some((p) => p.name === prev) ? prev : list[0]?.name || ""));
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
    requestAnimationFrame(() => passwordInputRef.current?.focus());
  }, [selected]);

  useEffect(() => {
    if (creating) requestAnimationFrame(() => nameInputRef.current?.focus());
  }, [creating]);

  const sortedProfiles = [...profiles].sort((a, b) => a.name.localeCompare(b.name));

  const toggle = (name: string) => setSelected((prev) => (prev === name ? "" : name));

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
        setRollbackInfo({ name: selected, fileRevision: prof?.revision ?? 0, highWater: prof?.high_water ?? 0 });
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
  const startImport = async () => {
    setError(null); setInfo(null);
    setBusy(true);
    try {
      const picked = await invoke<StagedImport | null>("import_vault_pick");
      if (!picked) { setBusy(false); return; }
      setStaged(picked);
      setImportName(picked.profile || "");
    } catch (e) {
      const info = describeVaultError(e);
      setError(info.message);
      if (info.code === "BOX_UNKNOWN_KEY") {
        // Not for any key this device holds — the only way in is a
        // recovery kit (spec Edge Cases / contract §2).
        setRecoveryOpen(true);
      }
    } finally {
      setBusy(false);
    }
  };

  const cancelImport = async () => {
    if (!staged) return;
    try { await invoke("import_vault_discard", { stagingId: staged.staging_id }); } catch { /* best-effort */ }
    setStaged(null);
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

  const commitImport = async (opts?: { confirmOlder?: boolean; resolveConflict?: boolean }) => {
    if (!staged) return;
    if (staged.disposition === "create_profile" && !importName.trim()) {
      setError("Pick a name for the imported profile.");
      return;
    }
    setBusy(true); setError(null);
    try {
      await invoke("import_vault_commit", {
        stagingId: staged.staging_id,
        name: staged.disposition === "create_profile" ? importName.trim() : undefined,
        // Rust declares these as plain `bool`, not `Option<bool>` — an
        // omitted key (which `undefined` becomes once JSON-serialized) is
        // a hard IPC deserialization error ("missing required key"), not a
        // default. Must always send a concrete boolean.
        confirmOlder: opts?.confirmOlder ?? false,
        resolveConflict: opts?.resolveConflict ?? false,
      });
      const wasNoOp = staged.disposition === "no_op";
      setStaged(null);
      setInfo(wasNoOp ? "Already up to date — nothing imported." : `Imported${importName ? ` as "${importName.trim()}"` : ""}.`);
      await reload();
      if (importName.trim()) setSelected(importName.trim());
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

        {/* T106: staged import — branches on disposition/confirmation_needed. */}
        {staged && (
          <div className="mb-3 px-3 py-3 bg-zinc-900/60 border border-primary/30 rounded-lg space-y-2 animate-in fade-in">
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
            {staged.disposition === "restore_over" && staged.confirmation_needed === "none" && (
              <div className="text-[11.5px] text-zinc-300 leading-snug">
                Restore over <span className="text-primary font-semibold">"{staged.profile}"</span> with revision{" "}
                {staged.incoming_revision} from {staged.sender_name || "another device"}?
              </div>
            )}
            {staged.confirmation_needed === "older" && (
              <div className="text-[11.5px] text-amber-200 leading-snug">
                This file (revision {staged.incoming_revision}) is OLDER than the local revision of{" "}
                <span className="font-semibold">"{staged.profile}"</span>. Restoring will replace the newer local content.
              </div>
            )}
            {staged.confirmation_needed === "conflict" && (
              <div className="text-[11.5px] text-amber-200 leading-snug">
                This file is the SAME revision as <span className="font-semibold">"{staged.profile}"</span> but the
                content differs. Restoring will overwrite the local copy.
              </div>
            )}
            {staged.disposition === "no_op" && (
              <div className="text-[11.5px] text-zinc-300 leading-snug">
                This file matches <span className="font-semibold">"{staged.profile}"</span> exactly — nothing to import.
              </div>
            )}
            <div className="flex gap-2">
              <button
                onClick={() => commitImport({
                  confirmOlder: staged.confirmation_needed === "older",
                  resolveConflict: staged.confirmation_needed === "conflict",
                })}
                disabled={busy || (staged.disposition === "create_profile" && !importName.trim())}
                className="flex-1 h-9 rounded-lg text-[12.5px] font-semibold bg-primary text-black disabled:opacity-50"
              >
                {busy ? "Importing…" : staged.disposition === "no_op" ? "Dismiss" : "Import"}
              </button>
              <button
                onClick={cancelImport}
                className="h-9 px-3 rounded-lg text-[12.5px] font-semibold text-zinc-300 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10"
              >
                Cancel
              </button>
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
                  onClick={startImport}
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
                  onClick={startImport}
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
        onImportNow={() => { setRecoveryOpen(false); startImport(); }}
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
