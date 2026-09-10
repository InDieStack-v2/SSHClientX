import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { CheckCircle2, ScanLine } from "lucide-react";
import QrScanCamera from "./QrScanCamera";
import { describeVaultError } from "../util/vaultErrors";

interface Scanned { session_id: string; verification_code: string; host_label: string | null; }
interface Result { landed_profile_name?: string; disposition: string; }
interface Preflight { needs_credentials: boolean; needs_key: boolean; }
const input = "w-full h-10 px-3 rounded-lg bg-zinc-900/60 border border-white/10 text-sm text-white outline-none focus:border-primary/50";

const QrGuestScanPanel = () => {
  const [ticket, setTicket] = useState("");
  const [scanned, setScanned] = useState<Scanned | null>(null);
  const [manual, setManual] = useState("");
  const [password, setPassword] = useState("");
  const [profileName, setProfileName] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [needsCredentials, setNeedsCredentials] = useState(false);
  const [preflighted, setPreflighted] = useState(false);

  const scan = async (text: string) => {
    if (!text.trim()) return;
    setBusy(true); setError(null); setTicket(text); setNeedsCredentials(false); setPreflighted(false);
    try { setScanned(await invoke<Scanned>("qr_transfer_guest_scan", { ticketText: text.trim() })); }
    catch (e) { setError(describeVaultError(e).message); }
    finally { setBusy(false); }
  };
  const confirm = async () => {
    if (!scanned) return;
    setBusy(true); setError(null);
    try {
      if (!preflighted) {
        const preflight = await invoke<Preflight>("qr_transfer_guest_preflight", { sessionId: scanned.session_id });
        setPreflighted(true);
        if (preflight.needs_credentials) {
          setNeedsCredentials(true);
          return;
        }
      }
      setResult(await invoke<Result>("qr_transfer_guest_confirm", { sessionId: scanned.session_id, keyPassword: password || null, profileName: profileName || null }));
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally { setBusy(false); }
  };
  const cancel = async () => {
    if (scanned) await invoke("qr_transfer_guest_cancel", { sessionId: scanned.session_id }).catch(() => {});
    setScanned(null); setResult(null); setTicket(""); setError(null); setNeedsCredentials(false); setPreflighted(false);
  };

  if (result) return <div className="flex-1 grid place-items-center p-5"><div className="max-w-md w-full rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-6 text-center space-y-3"><CheckCircle2 size={30} className="mx-auto text-emerald-300" /><h2 className="text-lg font-bold text-white">Transfer complete</h2><p className="text-sm text-zinc-300">{result.disposition === "push_sent" ? "The vault was sent to the other device for import." : <>Profile <strong>{result.landed_profile_name}</strong> is ready on this device.</>}</p><button onClick={cancel} className="h-10 px-5 rounded-lg bg-primary text-black text-sm font-semibold">Start another transfer</button></div></div>;
  if (scanned) return (
    <div className="flex-1 overflow-y-auto p-4 sm:p-8"><div className="max-w-md mx-auto space-y-4">
      <header><h2 className="text-xl font-bold text-white">Verify the other device</h2><p className="text-sm text-zinc-400 mt-1">{scanned.host_label ? `Connecting to ${scanned.host_label}.` : "Connecting to the scanned device."} Compare this code with the host screen.</p></header>
      <div className="rounded-xl border border-primary/30 bg-primary/10 p-5 text-center"><span className="text-[10px] uppercase tracking-widest text-primary">Verification code</span><strong className="block mt-2 font-mono text-2xl tracking-widest text-white">{scanned.verification_code}</strong></div>
      {needsCredentials && <><label className="block space-y-1"><span className="text-[10px] uppercase tracking-wider text-zinc-500">New vault password, or existing profile password</span><input type="password" value={password} onChange={e => setPassword(e.target.value)} className={input} placeholder="At least 8 characters for a new device" /></label>
      <label className="block space-y-1"><span className="text-[10px] uppercase tracking-wider text-zinc-500">Profile name when onboarding a new device</span><input value={profileName} onChange={e => setProfileName(e.target.value)} className={input} placeholder="e.g. Laptop" /></label></>}
      {error && <p className="text-sm text-rose-300">{error}</p>}
      <div className="flex gap-2"><button onClick={cancel} className="flex-1 h-10 rounded-lg border border-white/10 text-sm text-zinc-300">Cancel</button><button onClick={confirm} disabled={busy} className="flex-1 h-10 rounded-lg bg-primary text-black text-sm font-semibold disabled:opacity-50">{busy ? "Transferring…" : "Confirm and transfer"}</button></div>
    </div></div>
  );
  return <div className="flex-1 overflow-y-auto p-4 sm:p-8"><div className="max-w-md mx-auto space-y-4"><header><h2 className="text-xl font-bold text-white">Scan a nearby vault</h2><p className="text-sm text-zinc-400 mt-1">The code is only valid for one short local-network session.</p></header><QrScanCamera disabled={busy} onScan={scan} onError={setError} /><div className="flex items-center gap-3 text-[10px] uppercase tracking-widest text-zinc-600"><span className="h-px flex-1 bg-white/10" />or enter manually<span className="h-px flex-1 bg-white/10" /></div><div className="space-y-2"><textarea value={manual} onChange={e => setManual(e.target.value)} className={input + " h-20 py-2 resize-none font-mono text-xs"} placeholder="Paste the transfer code" /><button onClick={() => scan(manual)} disabled={busy || !manual.trim()} className="w-full h-10 rounded-lg bg-primary text-black text-sm font-semibold disabled:opacity-50"><ScanLine size={14} className="inline mr-1" />{busy ? "Checking…" : "Use transfer code"}</button></div>{error && <p className="text-sm text-rose-300">{error}</p>}{ticket && <p className="select-text break-all text-[10px] text-zinc-600">{ticket}</p>}</div></div>;
};
export default QrGuestScanPanel;
