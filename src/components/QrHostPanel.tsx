import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Copy, Radio, X } from "lucide-react";
import { useTauriListen } from "../hooks/useTauriListen";
import { describeVaultError } from "../util/vaultErrors";

interface HostSession {
  session_id: string;
  qr_svg: string;
  ticket_text: string;
  verification_code: string;
  expires_at: number;
}

const QrHostPanel = () => {
  const [session, setSession] = useState<HostSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [receivePassword, setReceivePassword] = useState("");
  const [receiveProfileName, setReceiveProfileName] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const [transferState, setTransferState] = useState<string | null>(null);

  const start = async (action: "share" | "receive") => {
    setBusy(true); setError(null);
    try {
      setSession(await invoke<HostSession>("qr_transfer_host_start", {
        action,
        keyPassword: action === "receive" ? receivePassword : null,
        profileName: action === "receive" ? receiveProfileName : null,
      }));
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally { setBusy(false); }
  };
  const cancel = async () => {
    if (!session) return;
    await invoke("qr_transfer_host_cancel", { sessionId: session.session_id }).catch(() => {});
    setSession(null);
  };

  useEffect(() => () => { if (session) void invoke("qr_transfer_host_cancel", { sessionId: session.session_id }).catch(() => {}); }, [session]);
  useTauriListen<{ state: string; outcome_code?: string }>(
    session ? `qr-transfer-state-${session.session_id}` : "qr-transfer-state-inactive",
    (event) => {
      setTransferState(event.payload.outcome_code
        ? `${event.payload.state}: ${describeVaultError(event.payload.outcome_code).message}`
        : event.payload.state);
    },
    [session?.session_id],
  );

  useEffect(() => {
    if (!session) return;
    const interval = window.setInterval(() => {
      const current = Date.now();
      setNow(current);
      if (session.expires_at <= Math.floor(current / 1000)) {
        void invoke("qr_transfer_host_cancel", { sessionId: session.session_id }).catch(() => {});
        setSession(null);
      }
    }, 1_000);
    return () => window.clearInterval(interval);
  }, [session]);

  if (!session) return (
    <div className="flex-1 overflow-y-auto p-4 sm:p-8">
      <div className="max-w-xl mx-auto space-y-5">
        <header><h2 className="text-xl font-bold text-white">Nearby transfer</h2><p className="text-sm text-zinc-400 mt-1">Move a sealed vault directly between devices on the same Wi-Fi or hotspot.</p></header>
        <div className="grid sm:grid-cols-2 gap-3">
          <button onClick={() => start("share")} disabled={busy} className="rounded-xl border border-primary/30 bg-primary/10 p-5 text-left hover:bg-primary/15 disabled:opacity-50"><Radio size={20} className="text-primary mb-3" /><strong className="block text-white">Share this vault</strong><span className="text-xs text-zinc-400">Show a QR for the other device to scan.</span></button>
          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5 space-y-3"><Radio size={20} className="text-zinc-300" /><strong className="block text-white">Receive a vault</strong><input value={receiveProfileName} onChange={e => setReceiveProfileName(e.target.value)} placeholder="New profile name" className="w-full h-9 px-2 rounded bg-black/20 border border-white/10 text-xs text-white" /><input type="password" value={receivePassword} onChange={e => setReceivePassword(e.target.value)} placeholder="New vault password (8+ chars)" className="w-full h-9 px-2 rounded bg-black/20 border border-white/10 text-xs text-white" /><button onClick={() => start("receive")} disabled={busy || !receivePassword || !receiveProfileName} className="w-full h-9 rounded bg-zinc-700 text-xs text-white disabled:opacity-50">Start receiving</button></div>
        </div>
        {error && <p className="text-sm text-rose-300">{error}</p>}
      </div>
    </div>
  );

  const seconds = Math.max(0, session.expires_at - Math.floor(now / 1000));
  return (
    <div className="flex-1 overflow-y-auto p-4 sm:p-8">
      <div className="max-w-xl mx-auto space-y-5">
        <div className="flex items-start justify-between"><div><h2 className="text-xl font-bold text-white">Scan this code</h2><p className="text-sm text-zinc-400 mt-1">Keep both devices on the same local network.</p></div><button onClick={cancel} className="p-2 rounded-lg hover:bg-white/10 text-zinc-400"><X size={18} /></button></div>
        <div className="rounded-2xl bg-white p-5 w-fit mx-auto"><img src={`data:image/svg+xml;utf8,${encodeURIComponent(session.qr_svg)}`} alt="QR transfer code" className="w-64 h-64" /></div>
        <div className="rounded-xl border border-primary/30 bg-primary/10 p-4 text-center"><span className="text-[10px] uppercase tracking-widest text-primary">Verification code</span><strong className="block mt-2 font-mono text-2xl tracking-widest text-white">{session.verification_code}</strong><p className="text-xs text-zinc-400 mt-2">The other device must show the same code before transfer.</p></div>
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3"><div className="flex items-center justify-between mb-1"><span className="text-[10px] uppercase tracking-wider text-zinc-500">Manual entry fallback</span><button onClick={() => { navigator.clipboard?.writeText(session.ticket_text); setCopied(true); setTimeout(() => setCopied(false), 1500); }} className="text-xs text-primary flex items-center gap-1"> <Copy size={12} /> {copied ? "Copied" : "Copy"}</button></div><p className="select-text break-all font-mono text-[10px] leading-relaxed text-zinc-400">{session.ticket_text}</p></div>
        {transferState && <p className="text-center text-xs text-primary capitalize">Transfer {transferState}</p>}
        <p className="text-center text-xs text-zinc-500">Expires in {seconds}s</p>
      </div>
    </div>
  );
};

export default QrHostPanel;
