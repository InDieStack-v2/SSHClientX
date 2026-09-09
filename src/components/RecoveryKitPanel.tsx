import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { KeyRound, X, AlertTriangle, CheckCircle2, FileUp, Type } from "lucide-react";
import PasswordField from "./PasswordField";
import LocalFileBrowser from "./LocalFileBrowser";
import { IS_ANDROID } from "../util/platform";
import { describeVaultError } from "../util/vaultErrors";

interface Props {
  isOpen: boolean;
  mode: "create" | "consume";
  onClose: () => void;
  /** Consume succeeded — offer the normal import flow. The user selects the
   * vault again there, so import bytes remain entirely in Rust. Android's
   * single-action restore remains a convenient alternative. */
  onImportNow?: () => void;
  /** Consume landed the vault file as a new profile in the same call
   * (Android's convenient single-action restore) — names it so the caller
   * can reload/select it. */
  onProfileLanded?: (name: string) => void;
}

const inputBase =
  "w-full h-10 px-3.5 bg-zinc-900/50 border border-white/5 rounded-lg text-[13px] text-zinc-50 placeholder:text-zinc-600 outline-none focus:border-primary/50 transition-colors";

// T087-090. "create" only works with a profile already open — the backend's
// `recovery_kit_create` confirms identity against the currently active
// profile's password, so this mode is only ever opened from inside the
// unlocked app (see DesktopApp's post-migration offer). "consume" needs no
// open profile — it establishes a fresh, unclaimed key — and is reachable
// from the picker too.
const RecoveryKitPanel = ({ isOpen, mode, onClose, onImportNow, onProfileLanded }: Props) => {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // --- create ---
  const [createForm, setCreateForm] = useState<"phrase" | "file">("phrase");
  const [recoveryPassphrase, setRecoveryPassphrase] = useState("");
  const [vaultPassword, setVaultPassword] = useState("");
  const [createdWords, setCreatedWords] = useState<string[] | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);

  // --- consume ---
  const [consumeSource, setConsumeSource] = useState<"phrase" | "file">("phrase");
  const [typedWords, setTypedWords] = useState("");
  const [kitFileBytes, setKitFileBytes] = useState<Uint8Array | null>(null);
  const [kitFileName, setKitFileName] = useState<string | null>(null);
  const [vaultFileBytes, setVaultFileBytes] = useState<Uint8Array | null>(null);
  const [vaultFileName, setVaultFileName] = useState<string | null>(null);
  const [consumePassphrase, setConsumePassphrase] = useState("");
  const [newVaultPassword, setNewVaultPassword] = useState("");
  const [consumed, setConsumed] = useState(false);
  // Android's single-action restore may land the vault file under this name.
  // General import is also available after a key is established, but this
  // path avoids a second confirmation step when the user has both files.
  const [profileName, setProfileName] = useState("");
  const [landedProfile, setLandedProfile] = useState<string | null>(null);

  // T113: Android has no native file dialog (`rfd` has no Android
  // backend), so file selection there opens the in-app browser instead —
  // this tracks which field the browser's next pick should land in.
  const [browserTarget, setBrowserTarget] = useState<"kit" | "vault" | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    setBusy(false); setError(null);
    setCreateForm("phrase"); setRecoveryPassphrase(""); setVaultPassword("");
    setCreatedWords(null); setSavedPath(null);
    setConsumeSource("phrase"); setTypedWords("");
    setKitFileBytes(null); setKitFileName(null);
    setVaultFileBytes(null); setVaultFileName(null);
    setConsumePassphrase(""); setNewVaultPassword(""); setConsumed(false);
    setProfileName(""); setLandedProfile(null);
    setBrowserTarget(null);
  }, [isOpen, mode]);

  if (!isOpen) return null;

  // Desktop: native dialog, one round trip. Android: opens the in-app
  // browser (`browserTarget`) and returns immediately — the actual bytes
  // land via `handleBrowserPick` once the user taps a file.
  const pickFile = async (target: "kit" | "vault", title: string, exts: string[]) => {
    if (IS_ANDROID) {
      setBrowserTarget(target);
      return;
    }
    const bytes = await invoke<number[] | null>("pick_and_read_file", { title, extensions: exts });
    if (!bytes) return;
    applyPicked(target, new Uint8Array(bytes), "file selected");
  };

  const applyPicked = (target: "kit" | "vault", bytes: Uint8Array, name: string) => {
    if (target === "kit") { setKitFileBytes(bytes); setKitFileName(name); }
    else { setVaultFileBytes(bytes); setVaultFileName(name); }
  };

  const handleBrowserPick = async (path: string, name: string) => {
    const target = browserTarget;
    setBrowserTarget(null);
    if (!target) return;
    try {
      const bytes = await invoke<number[]>("read_local_file_bytes", { path });
      applyPicked(target, new Uint8Array(bytes), name);
    } catch (e) {
      setError(describeVaultError(e).message);
    }
  };

  const submitCreate = async () => {
    if (!recoveryPassphrase) { setError("Set a recovery passphrase."); return; }
    if (!vaultPassword) { setError("Enter this profile's vault password to confirm your identity."); return; }
    setBusy(true); setError(null);
    try {
      const result = await invoke<{ form: "phrase"; words: string[] } | { form: "file"; bytes: number[] }>(
        "recovery_kit_create",
        { form: createForm, recoveryPassphrase, password: vaultPassword },
      );
      if (result.form === "phrase") {
        setCreatedWords(result.words);
      } else {
        const path = await invoke<string | null>("recovery_kit_save_file", { bytes: result.bytes });
        setSavedPath(path);
      }
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  // Android may either land this file with the recovered key now or use the
  // general import flow afterward. This form keeps the single-action
  // restore available, so it still asks for a name up front.
  const needsNameNow = IS_ANDROID && !!vaultFileBytes;
  // The vault file is required for the phrase form everywhere (FR-019g —
  // its salt comes from the file's kid) AND, on Android specifically, for
  // the file form too — Android has no way to land it later, so skipping
  // it here would just strand the key exactly like the "come back with
  // the vault file" dead end this session's fix is meant to avoid.
  const vaultFileRequired = consumeSource === "phrase" || IS_ANDROID;

  const submitConsume = async () => {
    if (consumeSource === "phrase" && !typedWords.trim()) { setError("Type the recovery phrase."); return; }
    if (consumeSource === "file" && !kitFileBytes) { setError("Pick the recovery kit file."); return; }
    if (vaultFileRequired && !vaultFileBytes) {
      setError(
        IS_ANDROID
          ? "Pick the matching vault file too — Android needs it to create the profile in this same step."
          : "Pick the vault file too — the phrase alone isn't enough.",
      );
      return;
    }
    if (!consumePassphrase) { setError("Enter the recovery passphrase."); return; }
    if (!newVaultPassword || newVaultPassword.length < 8) { setError("Set a vault password for this device (at least 8 characters)."); return; }
    if (needsNameNow && !profileName.trim()) { setError("Pick a name for the profile."); return; }
    setBusy(true); setError(null);
    try {
      const result = await invoke<{ kid: string; profile?: string }>("recovery_kit_consume", {
        phrase: consumeSource === "phrase" ? typedWords.trim() : undefined,
        kitFileBytes: consumeSource === "file" ? Array.from(kitFileBytes!) : undefined,
        vaultFileBytes: vaultFileBytes ? Array.from(vaultFileBytes) : undefined,
        recoveryPassphrase: consumePassphrase,
        newVaultPassword,
        name: needsNameNow ? profileName.trim() : undefined,
      });
      setLandedProfile(result.profile ?? null);
      setConsumed(true);
    } catch (e) {
      const info = describeVaultError(e);
      // Consume runs kit-derivation, then establish, then (only here)
      // landing, in that order — a `KIT_*` or `VAULT_*` code means it
      // failed before or during establish, so the key was never actually
      // established. Anything else (a `BOX_*` verification code, or a
      // bare message like "Profile 'X' already exists") can only have
      // come from the landing step, meaning establish already succeeded —
      // the key exists even though this call still failed overall.
      const establishFailed = info.code !== null && (info.code.startsWith("KIT_") || info.code.startsWith("VAULT_"));
      setError(
        needsNameNow && !establishFailed
          ? `${info.message} The key itself was still established — find it back on the sign-in screen under "Recovered keys" to try a different name.`
          : info.message,
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-3" onClick={onClose}>
      <div
        className="w-full max-w-md max-h-[90vh] flex flex-col bg-[#121214] border border-white/10 rounded-xl shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="shrink-0 px-4 py-3 border-b border-white/5 flex items-center justify-between">
          <span className="text-[12px] font-bold uppercase tracking-widest text-white flex items-center gap-2">
            <KeyRound size={13} className="text-primary" /> {mode === "create" ? "Create recovery kit" : "Recover with a kit"}
          </span>
          <button onClick={onClose} className="text-zinc-400 hover:text-white"><X size={16} /></button>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-3">
          {error && (
            <div className="px-3 py-2 bg-rose-500/15 border border-rose-500/30 rounded text-rose-200 text-[11.5px] flex items-center gap-2">
              <AlertTriangle size={12} className="shrink-0" /> {error}
            </div>
          )}

          {mode === "create" ? (
            createdWords ? (
              /* T087: display for transcription — never persisted anywhere client-side. */
              <div className="space-y-3">
                <div className="px-3 py-2 bg-amber-500/10 border border-amber-500/25 rounded-lg text-amber-200 text-[11.5px]">
                  Write these {createdWords.length} words down now. They will not be shown again.
                </div>
                <div className="grid grid-cols-3 gap-1.5 p-3 bg-black/40 border border-white/10 rounded-lg font-mono text-[12px] text-zinc-100 select-all">
                  {createdWords.map((w, i) => (
                    <div key={i}><span className="text-zinc-600">{i + 1}.</span> {w}</div>
                  ))}
                </div>
                <button onClick={onClose} className="w-full h-10 rounded-lg text-[13px] font-semibold bg-primary text-black">
                  Done — I've written it down
                </button>
              </div>
            ) : savedPath !== null ? (
              <div className="space-y-3">
                <div className="px-3 py-2 bg-emerald-500/10 border border-emerald-500/25 rounded-lg text-emerald-100 text-[12px] flex items-center gap-2">
                  <CheckCircle2 size={13} className="shrink-0" /> Saved to {savedPath}
                </div>
                <button onClick={onClose} className="w-full h-10 rounded-lg text-[13px] font-semibold bg-primary text-black">Done</button>
              </div>
            ) : (
              <>
                <div className="px-3 py-2 bg-amber-500/10 border border-amber-500/25 rounded-lg text-amber-200 text-[11.5px] leading-relaxed space-y-1">
                  {/* T089 */}
                  <p>Together, this kit, your vault file, and the recovery passphrase below grant full access to every saved secret.</p>
                  <p>The recovery passphrase is <strong>separate from your vault password</strong> — choose a different one.</p>
                  {createForm === "phrase" && (
                    /* T088 */
                    <p>The phrase form also needs your vault file to recover — keep both together.</p>
                  )}
                </div>

                <div className="flex gap-2">
                  <ModeButton active={createForm === "phrase"} onClick={() => setCreateForm("phrase")} icon={<Type size={12} />} label="Phrase" />
                  <ModeButton active={createForm === "file"} onClick={() => setCreateForm("file")} icon={<FileUp size={12} />} label="File" />
                </div>

                <Field label="Recovery passphrase">
                  <PasswordField value={recoveryPassphrase} onChange={setRecoveryPassphrase} placeholder="A new, separate passphrase" className={inputBase} />
                </Field>
                <Field label="Your vault password (to confirm it's you)">
                  <PasswordField value={vaultPassword} onChange={setVaultPassword} placeholder="Current vault password" className={inputBase} />
                </Field>

                <button
                  onClick={submitCreate}
                  disabled={busy}
                  className="w-full h-10 rounded-lg text-[13px] font-semibold bg-primary text-black disabled:opacity-50"
                >
                  {busy ? "Creating…" : "Create kit"}
                </button>
              </>
            )
          ) : consumed ? (
            landedProfile ? (
              // FR-041: Android's single-action restore already landed it.
              <div className="space-y-3">
                <div className="px-3 py-2 bg-emerald-500/10 border border-emerald-500/25 rounded-lg text-emerald-100 text-[12px] flex items-center gap-2">
                  <CheckCircle2 size={13} className="shrink-0" /> Profile "{landedProfile}" is ready.
                </div>
                <p className="text-[12px] text-zinc-400 leading-relaxed">
                  Sign in to it with the vault password you just set to open it.
                </p>
                <button
                  onClick={() => { onProfileLanded?.(landedProfile); onClose(); }}
                  className="w-full h-10 rounded-lg text-[13px] font-semibold bg-primary text-black"
                >
                  Done
                </button>
              </div>
            ) : (
              // Desktop only: `vaultFileRequired` means Android's own path
              // through here always has a landed profile by now (a landing
              // failure keeps `consumed` false — the error banner shows
              // instead — so this branch never fires there).
              <div className="space-y-3">
                <div className="px-3 py-2 bg-emerald-500/10 border border-emerald-500/25 rounded-lg text-emerald-100 text-[12px] flex items-center gap-2">
                  <CheckCircle2 size={13} className="shrink-0" /> Key established on this device.
                </div>
                <p className="text-[12px] text-zinc-400 leading-relaxed">
                  {vaultFileBytes
                    ? "The key alone doesn't create a profile — import that vault file to finish."
                    : "Now use Import and pick that same vault file to finish — the key alone doesn't create a profile."}
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => onImportNow?.()}
                    className="flex-1 h-10 rounded-lg text-[13px] font-semibold bg-primary text-black"
                  >
                    Import now
                  </button>
                  <button onClick={onClose} className="h-10 px-4 rounded-lg text-[13px] font-semibold text-zinc-300 bg-white/5 border border-white/10">
                    Later
                  </button>
                </div>
              </div>
            )
          ) : (
            <>
              <div className="flex gap-2">
                <ModeButton active={consumeSource === "phrase"} onClick={() => setConsumeSource("phrase")} icon={<Type size={12} />} label="Typed phrase" />
                <ModeButton active={consumeSource === "file"} onClick={() => setConsumeSource("file")} icon={<FileUp size={12} />} label="Kit file" />
              </div>

              {consumeSource === "phrase" ? (
                <Field label="Recovery phrase (24 words)">
                  <textarea
                    value={typedWords}
                    onChange={(e) => setTypedWords(e.target.value)}
                    placeholder="word1 word2 word3 …"
                    rows={3}
                    className={inputBase + " h-auto py-2 resize-none font-mono"}
                  />
                </Field>
              ) : (
                <Field label="Recovery kit file">
                  <PickButton
                    fileName={kitFileName}
                    onPick={() => pickFile("kit", "Select recovery kit", ["sshclientx-kit"])}
                  />
                </Field>
              )}

              {/* FR-019g: required for the phrase form always; optional for
                  the file form (the kit is self-contained then). */}
              <Field label={vaultFileRequired ? "Vault file (required)" : "Vault file (optional — or import separately)"}>
                <PickButton
                  fileName={vaultFileName}
                  onPick={() => pickFile("vault", "Select the vault file", ["sshclientx", "submarine"])}
                />
              </Field>

              {/* FR-041: Android has no general Import flow, so it needs
                  the profile's name now, to land the vault file as a new
                  profile in this same call. Desktop keeps naming it later,
                  on the Import popup, so this never shows there. */}
              {needsNameNow && (
                <Field label="Profile name">
                  <input
                    value={profileName}
                    onChange={(e) => setProfileName(e.target.value)}
                    placeholder="What to call it on this device"
                    className={inputBase}
                  />
                </Field>
              )}

              <Field label="Recovery passphrase">
                <PasswordField value={consumePassphrase} onChange={setConsumePassphrase} placeholder="The passphrase this kit was sealed under" className={inputBase} />
              </Field>
              <Field label="New vault password for this device">
                <PasswordField value={newVaultPassword} onChange={setNewVaultPassword} placeholder="At least 8 characters" className={inputBase} />
              </Field>

              <button
                onClick={submitConsume}
                disabled={busy}
                className="w-full h-10 rounded-lg text-[13px] font-semibold bg-primary text-black disabled:opacity-50"
              >
                {busy ? "Recovering…" : "Recover key"}
              </button>
            </>
          )}
        </div>
      </div>
      <LocalFileBrowser
        isOpen={browserTarget !== null}
        title={browserTarget === "kit" ? "Select recovery kit" : "Select vault file"}
        onPick={handleBrowserPick}
        onClose={() => setBrowserTarget(null)}
      />
    </div>
  );
};

const Field = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="space-y-1">
    <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider ml-0.5">{label}</label>
    {children}
  </div>
);

const ModeButton = ({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) => (
  <button
    onClick={onClick}
    className={`flex-1 h-9 rounded-lg text-[12px] font-semibold border flex items-center justify-center gap-1.5 transition-colors ${
      active ? "bg-primary/15 border-primary/40 text-primary" : "bg-white/[0.03] border-white/10 text-zinc-400 hover:bg-white/[0.06]"
    }`}
  >
    {icon} {label}
  </button>
);

const PickButton = ({ fileName, onPick }: { fileName: string | null; onPick: () => void }) => (
  <button
    onClick={onPick}
    className="w-full h-10 px-3.5 rounded-lg text-[12.5px] font-medium border border-dashed border-white/15 text-zinc-400 hover:border-primary/40 hover:text-zinc-200 transition-colors text-left"
  >
    {fileName || "Choose file…"}
  </button>
);

export default RecoveryKitPanel;
