import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Settings, Palette, RefreshCw, Pipette, List, Lock, KeyRound, Trash2 } from "lucide-react";

const SettingsPanel = ({ settings, setSettings, onOpenLogs, onOpenRecoveryKit }: any) => {
  // Recovery-kit edge case: a kit consumed but never matched to a vault
  // file leaves an unclaimed key sitting in the secure store, owning
  // nothing — otherwise invisible and permanent. Device-wide, not tied to
  // the profile that happens to be open right now, so it's loaded
  // independently of everything else here.
  const [unclaimedKeys, setUnclaimedKeys] = useState<string[]>([]);
  const [discardingKid, setDiscardingKid] = useState<string | null>(null);

  const reloadUnclaimedKeys = () => {
    invoke<string[]>("unclaimed_keys_list").then(setUnclaimedKeys).catch(() => {});
  };
  useEffect(() => { reloadUnclaimedKeys(); }, []);

  const discardUnclaimedKey = async (kidHex: string) => {
    if (!window.confirm("Discard this recovered key? If you haven't imported its vault file yet, this can't be undone.")) return;
    setDiscardingKid(kidHex);
    try {
      await invoke("unclaimed_key_discard", { kidHex });
      setUnclaimedKeys((prev) => prev.filter((k) => k !== kidHex));
    } catch {
      // best-effort — the list stays as-is, user can retry
    } finally {
      setDiscardingKid(null);
    }
  };

  // Idle-lock timeout (FR-045) — backend-persisted (a device-wide sidecar
  // file, not this component's own localStorage-backed `settings`/
  // `setSettings`), so it gets its own state and IPC round-trip rather
  // than folding into the prop-drilled UI-preference object above.
  const [idleMinutes, setIdleMinutes] = useState<number | null>(null);
  const [idleError, setIdleError] = useState<string | null>(null);
  const [idleSaving, setIdleSaving] = useState(false);

  useEffect(() => {
    invoke<number>("idle_timeout_get").then(setIdleMinutes).catch(() => {});
  }, []);

  const commitIdleMinutes = async (minutes: number) => {
    setIdleSaving(true); setIdleError(null);
    try {
      await invoke("idle_timeout_set", { minutes });
      setIdleMinutes(minutes);
    } catch (e) {
      // Backend rejects out-of-range rather than clamping (FR-045) — show
      // its message and leave the displayed value at the last-known-good one.
      setIdleError(String(e).replace(/^\[[A-Z_]+\]\s*/, ""));
      invoke<number>("idle_timeout_get").then(setIdleMinutes).catch(() => {});
    } finally {
      setIdleSaving(false);
    }
  };
  const accentColors = [
    { name: 'Light Blue', value: '#60a5fa' },
    { name: 'Sky', value: '#38bdf8' },
    { name: 'Cyan', value: '#22d3ee' },
    { name: 'Indigo', value: '#818cf8' },
    { name: 'Emerald', value: '#10b981' },
    { name: 'Rose', value: '#f43f5e' },
  ];

  const bgColors = [
    { name: 'Onyx', value: '#050505' },
    { name: 'Charcoal', value: '#0a0a0c' },
    { name: 'Slate', value: '#0f172a' },
    { name: 'Nord', value: '#2e3440' },
    { name: 'Dark Gray', value: '#1a1a1a' },
    { name: 'Deep Space', value: '#0d0d10' },
  ];

  return (
    <div className="flex-1 p-4 sm:p-10 overflow-y-auto custom-scrollbar animate-in">
      <header className="mb-6 sm:mb-10">
        <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex items-center gap-3">
          <Settings size={24} className="text-primary" /> Settings
        </h2>
        <p className="text-[13px] text-zinc-400 mt-2">
          Tweak how SSHClientX looks and feels.
          {' '}
          <span className="text-zinc-500 italic">Per-device — preferences live in this machine's local storage.</span>
        </p>
      </header>

      {/* Columns rather than a grid: the sections are very different heights, and
          a 2-col grid rows them up so a short card leaves a tall empty gap beside
          it. Column flow packs them, and break-inside-avoid keeps a card whole. */}
      <div className="columns-1 md:columns-2 gap-4 sm:gap-8">
        {/* Appearance Section */}
        <section className="break-inside-avoid space-y-3 mb-4 sm:mb-8">
          <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
            <Palette size={14} /> UI Customization
          </div>

          <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-8 shadow-xl">
            {/* Accent Color */}
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Primary Accent Color</label>
                <div className="flex items-center gap-2">
                  <input 
                    type="color" 
                    value={settings.primaryColor} 
                    onChange={(e) => setSettings({ ...settings, primaryColor: e.target.value })}
                    className="w-6 h-6 rounded-md bg-transparent cursor-pointer border-none p-0"
                  />
                  <input 
                    type="text" 
                    value={settings.primaryColor} 
                    onChange={(e) => setSettings({ ...settings, primaryColor: e.target.value })}
                    className="w-20 h-6 bg-black border border-white/10 rounded px-1.5 text-[10px] font-mono text-zinc-400 focus:border-primary/50 outline-none"
                  />
                </div>
              </div>
              <div className="grid grid-cols-6 gap-3">
                {accentColors.map(c => (
                  <button
                    key={c.value}
                    onClick={() => setSettings({ ...settings, primaryColor: c.value })}
                    className={`w-full aspect-square rounded-xl border-2 transition-all ${settings.primaryColor === c.value ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'}`}
                    style={{ backgroundColor: c.value }}
                    title={c.name}
                  />
                ))}
              </div>
            </div>

            {/* Background Theme */}
            <div className="space-y-4 pt-6 border-t border-white/5">
              <div className="flex justify-between items-center">
                <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Background Theme</label>
                <div className="flex items-center gap-2">
                  <input 
                    type="color" 
                    value={settings.backgroundColor} 
                    onChange={(e) => setSettings({ ...settings, backgroundColor: e.target.value })}
                    className="w-6 h-6 rounded-md bg-transparent cursor-pointer border-none p-0"
                  />
                  <input 
                    type="text" 
                    value={settings.backgroundColor} 
                    onChange={(e) => setSettings({ ...settings, backgroundColor: e.target.value })}
                    className="w-20 h-6 bg-black border border-white/10 rounded px-1.5 text-[10px] font-mono text-zinc-400 focus:border-primary/50 outline-none"
                  />
                </div>
              </div>
              <div className="grid grid-cols-6 gap-3">
                {bgColors.map(c => (
                  <button
                    key={c.value}
                    onClick={() => setSettings({ ...settings, backgroundColor: c.value })}
                    className={`w-full aspect-square rounded-xl border-2 transition-all ${settings.backgroundColor === c.value ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'}`}
                    style={{ backgroundColor: c.value }}
                    title={c.name}
                  />
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Terminal Section */}
        <section className="break-inside-avoid space-y-3 mb-4 sm:mb-8">
          <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
            <Settings size={14} /> Terminal Configuration
          </div>
          
          <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Font Size (px)</label>
                <input 
                  type="number" 
                  value={settings.terminalFontSize || 14} 
                  onChange={(e) => setSettings({ ...settings, terminalFontSize: parseInt(e.target.value) || 14 })}
                  className="w-16 h-8 bg-black border border-white/10 rounded-lg px-2 text-[12px] font-bold text-white focus:border-primary/50 outline-none text-center"
                />
              </div>
              <input
                type="range"
                min="1"
                max="24"
                value={settings.terminalFontSize || 14}
                onChange={(e) => setSettings({ ...settings, terminalFontSize: parseInt(e.target.value) || 14 })}
                className="w-full accent-primary"
              />
            </div>
          </div>
        </section>

        {/* Vault Security Section */}
        <section className="break-inside-avoid space-y-3 mb-4 sm:mb-8">
          <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
            <Lock size={14} /> Vault Security
          </div>

          <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Idle lock timeout (minutes)</label>
                <input
                  type="number"
                  min={1}
                  max={60}
                  value={idleMinutes ?? ""}
                  onChange={(e) => setIdleMinutes(parseInt(e.target.value) || 1)}
                  onBlur={(e) => {
                    const v = Math.max(1, Math.min(60, parseInt(e.target.value) || 15));
                    commitIdleMinutes(v);
                  }}
                  disabled={idleSaving || idleMinutes === null}
                  className="w-16 h-8 bg-black border border-white/10 rounded-lg px-2 text-[12px] font-bold text-white focus:border-primary/50 outline-none text-center disabled:opacity-50"
                />
              </div>
              <input
                type="range"
                min="1"
                max="60"
                value={idleMinutes ?? 15}
                disabled={idleSaving || idleMinutes === null}
                onChange={(e) => setIdleMinutes(parseInt(e.target.value))}
                onMouseUp={(e) => commitIdleMinutes(parseInt((e.target as HTMLInputElement).value))}
                onTouchEnd={(e) => commitIdleMinutes(parseInt((e.target as HTMLInputElement).value))}
                className="w-full accent-primary"
              />
              <p className="text-[11px] text-zinc-500 leading-relaxed">
                Locking after inactivity is always on — this only sets how long. 1–60 minutes, default 15.
              </p>
              {idleError && <p className="text-[11px] text-rose-300">{idleError}</p>}
            </div>

            {onOpenRecoveryKit && (
              <div className="space-y-2 pt-4 border-t border-white/5">
                <p className="text-[11px] text-zinc-500 leading-relaxed">
                  A recovery kit lets you re-establish this vault's key on another device you control, without your vault password ever leaving this one.
                </p>
                <button
                  onClick={onOpenRecoveryKit}
                  className="px-4 h-9 bg-primary/10 border border-primary/30 text-primary rounded-xl text-xs font-bold uppercase hover:bg-primary hover:text-zinc-950 transition-all w-full flex items-center justify-center gap-2"
                >
                  <KeyRound size={14} /> Create Recovery Kit
                </button>
              </div>
            )}

            {unclaimedKeys.length > 0 && (
              <div className="space-y-2 pt-4 border-t border-white/5">
                <p className="text-[11px] text-zinc-500 leading-relaxed">
                  {unclaimedKeys.length === 1 ? "A key" : `${unclaimedKeys.length} keys`} recovered from a kit on
                  this device but never matched to a vault file yet — owns nothing until you import that file, or
                  discard it if you don't plan to.
                </p>
                <div className="space-y-1.5">
                  {unclaimedKeys.map((kidHex) => (
                    <div
                      key={kidHex}
                      className="flex items-center justify-between gap-2 h-9 px-3 bg-black/30 border border-white/5 rounded-lg"
                    >
                      <span className="text-[11px] font-mono text-zinc-400 truncate" title={kidHex}>
                        {kidHex.slice(0, 16)}…
                      </span>
                      <button
                        onClick={() => discardUnclaimedKey(kidHex)}
                        disabled={discardingKid === kidHex}
                        title="Discard this unclaimed key"
                        className="h-6 px-2 rounded-md text-[11px] font-medium text-rose-300/90 bg-rose-500/5 border border-rose-500/15 hover:bg-rose-500/15 hover:text-rose-200 disabled:opacity-40 flex items-center gap-1 shrink-0"
                      >
                        <Trash2 size={11} /> Discard
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Activity Section — moved out of the sidebar so the top-level
            navigation stays focused on primary workflows. Logs are diagnostic
            only; keeping them one click deep here cleans up the sidebar on
            mobile (six icons → five) without burying the data. */}
        {onOpenLogs && (
          <section className="break-inside-avoid space-y-3 mb-4 sm:mb-8">
            <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
              <List size={14} /> Activity Log
            </div>

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
              <p className="text-sm text-zinc-400 leading-relaxed">
                Diagnostic timeline of what the app has been doing this session. Useful for confirming a connection actually failed or watching a transfer's progress in retrospect.
              </p>
              <button
                onClick={onOpenLogs}
                className="px-4 h-9 bg-primary/10 border border-primary/30 text-primary rounded-xl text-xs font-bold uppercase hover:bg-primary hover:text-zinc-950 transition-all w-full flex items-center justify-center gap-2"
              >
                <List size={14} /> View Activity Log
              </button>
            </div>
          </section>
        )}

        {/* Maintenance Section */}
        <section className="break-inside-avoid space-y-3 mb-4 sm:mb-8">
          <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
            <RefreshCw size={14} /> Maintenance
          </div>

          <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
            <p className="text-sm text-zinc-400 leading-relaxed">
              These preferences are persisted in your local environment. Resetting will revert all UI aesthetics to factory defaults.
            </p>
            <button
              onClick={() => {
                if(window.confirm('Reset all UI customizations?')) {
                  setSettings((s: any) => ({ ...s, primaryColor: '#60a5fa', backgroundColor: '#0a0a0c', terminalFontSize: 14 }));
                }
              }}
              className="px-4 h-9 bg-zinc-900 border border-white/5 text-zinc-300 rounded-xl text-xs font-bold uppercase hover:bg-white/5 transition-all w-full"
            >
              Reset to Defaults
            </button>
          </div>
        </section>
      </div>
    </div>
  );
};

export default SettingsPanel;
