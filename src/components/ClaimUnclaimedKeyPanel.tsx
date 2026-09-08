import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { KeyRound, X, AlertTriangle } from "lucide-react";
import PasswordField from "./PasswordField";
import LocalFileBrowser from "./LocalFileBrowser";
import { IS_ANDROID } from "../util/platform";
import { describeVaultError } from "../util/vaultErrors";

interface Props {
  isOpen: boolean;
  /** Which unclaimed key (hex `kid`) to claim — from `unclaimed_keys_list`. */
  kidHex: string | null;
  onClose: () => void;
  /** Claim succeeded — names the profile it landed as. */
  onClaimed: (name: string) => void;
}

const inputBase =
  "w-full h-10 px-3.5 bg-zinc-900/50 border border-white/5 rounded-lg text-[13px] text-zinc-50 placeholder:text-zinc-600 outline-none focus:border-primary/50 transition-colors";

// Finishes what a recovery kit's single-action land step either wasn't
// asked to do (desktop's own `recovery_kit_consume` never passes a name,
// so this is always its route to actually landing an unclaimed key) or
// failed at (Android: most commonly a name collision) — the key is
// already established in the secure store either way; this only needs
// its own device password, the matching vault file, and a name.
const ClaimUnclaimedKeyPanel = ({ isOpen, kidHex, onClose, onClaimed }: Props) => {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [vaultFileBytes, setVaultFileBytes] = useState<Uint8Array | null>(null);
  const [vaultFileName, setVaultFileName] = useState<string | null>(null);
  const [keyPassword, setKeyPassword] = useState("");
  const [name, setName] = useState("");
  const [browserOpen, setBrowserOpen] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setBusy(false); setError(null);
    setVaultFileBytes(null); setVaultFileName(null);
    setKeyPassword(""); setName("");
    setBrowserOpen(false);
  }, [isOpen, kidHex]);

  if (!isOpen || !kidHex) return null;

  const pickVaultFile = async () => {
    if (IS_ANDROID) { setBrowserOpen(true); return; }
    const bytes = await invoke<number[] | null>("pick_and_read_file", {
      title: "Select the vault file",
      extensions: ["sshclientx", "submarine"],
    });
    if (!bytes) return;
    setVaultFileBytes(new Uint8Array(bytes));
    setVaultFileName("file selected");
  };

  const handleBrowserPick = async (path: string, pickedName: string) => {
    setBrowserOpen(false);
    try {
      const bytes = await invoke<number[]>("read_local_file_bytes", { path });
      setVaultFileBytes(new Uint8Array(bytes));
      setVaultFileName(pickedName);
    } catch (e) {
      setError(describeVaultError(e).message);
    }
  };

  const submit = async () => {
    if (!vaultFileBytes) { setError("Pick the vault file this key belongs to."); return; }
    if (!keyPassword) { setError("Enter the device password you set when this key was recovered."); return; }
    if (!name.trim()) { setError("Pick a name for the profile."); return; }
    setBusy(true); setError(null);
    try {
      const landed = await invoke<string>("unclaimed_key_claim", {
        kidHex,
        keyPassword,
        vaultFileBytes: Array.from(vaultFileBytes),
        name: name.trim(),
      });
      onClaimed(landed);
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-3" onClick={onClose}>
      <div
        className="w-full max-w-sm bg-[#121214] border border-primary/30 rounded-xl shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="shrink-0 px-4 py-3 border-b border-white/5 flex items-center justify-between">
          <span className="text-[12px] font-bold uppercase tracking-widest text-white flex items-center gap-2">
            <KeyRound size={13} className="text-primary" /> Finish creating this profile
          </span>
          <button onClick={onClose} className="text-zinc-400 hover:text-white"><X size={16} /></button>
        </div>

        <div className="p-4 space-y-3">
          {error && (
            <div className="px-3 py-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-200 text-[11.5px] flex items-center gap-2">
              <AlertTriangle size={13} className="shrink-0" /> {error}
            </div>
          )}

          <div className="text-[11.5px] text-zinc-300 leading-snug">
            Key <span className="font-mono text-primary">{kidHex.slice(0, 16)}…</span> was recovered from a kit but
            never matched to a vault file. Pick that file, the device password you set for it, and a name.
          </div>

          <Field label="Vault file">
            <button
              onClick={pickVaultFile}
              className="w-full h-10 px-3.5 rounded-lg text-[12.5px] font-medium border border-dashed border-white/15 text-zinc-400 hover:border-primary/40 hover:text-zinc-200 transition-colors text-left"
            >
              {vaultFileName || "Choose file…"}
            </button>
          </Field>
          <Field label="Device password (set when this key was recovered)">
            <PasswordField value={keyPassword} onChange={setKeyPassword} placeholder="Password" className={inputBase} />
          </Field>
          <Field label="Profile name">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submit()}
              placeholder="What to call it on this device"
              className={inputBase}
              autoFocus
            />
          </Field>

          <button
            onClick={submit}
            disabled={busy}
            className="w-full h-10 rounded-lg text-[13px] font-semibold bg-primary text-black disabled:opacity-50"
          >
            {busy ? "Creating…" : "Create profile"}
          </button>
        </div>
      </div>
      <LocalFileBrowser
        isOpen={browserOpen}
        title="Select the vault file"
        onPick={handleBrowserPick}
        onClose={() => setBrowserOpen(false)}
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

export default ClaimUnclaimedKeyPanel;
