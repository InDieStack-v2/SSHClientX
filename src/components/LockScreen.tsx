import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Fingerprint, Lock, ArrowRight, RefreshCw } from "lucide-react";
import PasswordField from "./PasswordField";
import { useTauriListen } from "../hooks/useTauriListen";
import { describeVaultError } from "../util/vaultErrors";
import logoUrl from "../assets/logo.png";

interface Props {
  lockState: "locked_soft" | "locked_hard";
  onUnlocked: () => void;
}

// T070/T071. Rendered as a full-viewport, fully OPAQUE overlay (no
// backdrop-blur, unlike the confirm.tsx dialogs) on top of the still-
// mounted app — sessions/tunnels/transfers keep running underneath
// (FR-049), so this is a pure visual conceal, not a state teardown. A blur
// would partially let terminal content show through, which FR-046
// forbids outright: "MUST NOT display any vault content."
const LockScreen = ({ lockState, onUnlocked }: Props) => {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // `locked_soft` starts by trying platform auth automatically (minimizes
  // taps — re-unlock latency is a first-class concern given focus-loss
  // locking can fire dozens of times a day); the user can always fall back
  // to the password without waiting for it to fail first.
  const [forcePassword, setForcePassword] = useState(false);
  const [activity, setActivity] = useState<{ kind: string; status: string } | null>(null);

  useTauriListen<{ kind: string; status: string }>(
    "vault-background-activity",
    (e) => setActivity(e.payload),
    [],
  );

  const attemptQuick = async () => {
    setBusy(true); setError(null);
    try {
      await invoke("vault_unlock_quick");
      onUnlocked();
    } catch (e) {
      // The backend already stops offering platform auth after enough
      // consecutive failures (FR-057) — nothing to count client-side, just
      // let the user reach the password form.
      setError(describeVaultError(e).message);
      setForcePassword(true);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    setError(null);
    setPassword("");
    if (lockState === "locked_soft") {
      setForcePassword(false);
      attemptQuick();
    } else {
      setForcePassword(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lockState]);

  const unlockFull = async () => {
    if (!password) { setError("Type your password."); return; }
    setBusy(true); setError(null);
    try {
      await invoke("vault_unlock_full", { password });
      onUnlocked();
    } catch (e) {
      setError(describeVaultError(e).message);
    } finally {
      setBusy(false);
    }
  };

  const showQuick = lockState === "locked_soft" && !forcePassword;

  return (
    <div className="fixed inset-0 z-[10000] bg-background flex items-center justify-center px-6">
      <div className="w-full max-w-[320px] flex flex-col items-center text-center">
        <img src={logoUrl} alt="" draggable={false} className="h-20 w-auto mb-6 opacity-90" />
        <div className="flex items-center gap-2 text-zinc-400 mb-1">
          <Lock size={14} />
          <span className="text-[11px] font-bold uppercase tracking-[0.18em]">
            {lockState === "locked_soft" ? "Locked" : "Locked — password required"}
          </span>
        </div>
        <p className="text-[12px] text-zinc-500 mb-6">
          Your live sessions and transfers are still running.
        </p>

        {error && (
          <div className="w-full mb-3 px-3 py-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-200 text-[12px]">
            {error}
          </div>
        )}

        {activity && (
          <div className="w-full mb-3 px-3 py-2 bg-zinc-900/50 border border-white/5 rounded-lg text-zinc-400 text-[11px]">
            {activity.kind}: {activity.status}
          </div>
        )}

        {showQuick ? (
          <div className="w-full space-y-3">
            <button
              onClick={attemptQuick}
              disabled={busy}
              className="w-full h-11 rounded-xl text-[14px] font-semibold bg-primary text-black disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {busy ? <RefreshCw size={16} className="animate-spin" /> : <Fingerprint size={16} />}
              {busy ? "Waiting…" : "Unlock"}
            </button>
            <button
              onClick={() => setForcePassword(true)}
              className="text-[12px] text-zinc-500 hover:text-zinc-300"
            >
              Use password instead
            </button>
          </div>
        ) : (
          <div className="w-full space-y-3">
            <PasswordField
              value={password}
              onChange={setPassword}
              placeholder="Password"
              autoFocus
              onKeyDown={(e: any) => e.key === "Enter" && unlockFull()}
              className="w-full h-11 px-4 bg-zinc-900/40 border border-white/5 rounded-xl text-[14px] text-zinc-50 placeholder:text-zinc-600 outline-none focus:border-primary/50"
            />
            <button
              onClick={unlockFull}
              disabled={busy || !password}
              className="w-full h-11 rounded-xl text-[14px] font-semibold bg-primary text-black disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {busy ? <RefreshCw size={16} className="animate-spin" /> : <>Unlock <ArrowRight size={16} /></>}
            </button>
            {lockState === "locked_soft" && (
              <button
                onClick={() => { setForcePassword(false); attemptQuick(); }}
                className="text-[12px] text-zinc-500 hover:text-zinc-300"
              >
                Try quick unlock again
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default LockScreen;
