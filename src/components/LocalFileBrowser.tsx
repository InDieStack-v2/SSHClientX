import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Folder, File as FileIcon, ChevronLeft, X } from "lucide-react";

interface Entry { name: string; path: string; is_dir: boolean; size: number }
interface QuickDir { label: string; path: string }

interface Props {
  isOpen: boolean;
  title: string;
  /** Case-insensitive file extensions without their dots; directories remain visible. */
  allowedExtensions?: string[];
  onPick: (path: string, name: string) => void;
  onClose: () => void;
}

// T113: Android has no native file-picker dialog at all (`rfd` has no
// Android backend), so file selection there goes through the app's own
// in-app browser instead — the same `local_list_dir`/`android_quick_dirs`
// commands FilePanel already uses for SFTP-side local browsing, just
// wrapped as a single-purpose "pick one file" modal for the recovery-kit
// flow. Works on desktop too (falls back to the OS home dir as the start
// point there), so it's one component either platform can use, even
// though desktop's RecoveryKitPanel prefers the native dialog when it can.
const LocalFileBrowser = ({ isOpen, title, allowedExtensions, onPick, onClose }: Props) => {
  const [quickDirs, setQuickDirs] = useState<QuickDir[] | null>(null);
  const [path, setPath] = useState<string | null>(null);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    setPath(null); setEntries([]); setError(null);
    invoke<QuickDir[]>("android_quick_dirs").then(setQuickDirs).catch(() => setQuickDirs([]));
  }, [isOpen]);

  const enter = async (p: string) => {
    setLoading(true); setError(null);
    try {
      const raw = await invoke<Entry[]>("local_list_dir", { path: p });
      setPath(p);
      setEntries(raw.sort((a, b) => (a.is_dir === b.is_dir ? a.name.localeCompare(b.name) : a.is_dir ? -1 : 1)));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[60] bg-black/60 backdrop-blur-sm flex items-center justify-center p-3" onClick={onClose}>
      <div
        className="w-full max-w-sm max-h-[80vh] flex flex-col bg-[#121214] border border-white/10 rounded-xl shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="shrink-0 px-4 py-3 border-b border-white/5 flex items-center justify-between">
          <span className="text-[12px] font-bold uppercase tracking-widest text-white flex items-center gap-2">
            {path && (
              <button onClick={() => setPath(null)} className="text-zinc-400 hover:text-white">
                <ChevronLeft size={14} />
              </button>
            )}
            {title}
          </span>
          <button onClick={onClose} className="text-zinc-400 hover:text-white"><X size={16} /></button>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar p-2">
          {error && <div className="px-3 py-2 text-rose-300 text-[11.5px]">{error}</div>}
          {loading && <div className="px-3 py-2 text-zinc-500 text-[11.5px]">Loading…</div>}

          {!path && !loading && (
            <div className="space-y-1">
              {(quickDirs || []).map((d) => (
                <button
                  key={d.path}
                  onClick={() => enter(d.path)}
                  className="w-full flex items-center gap-2 px-3 h-10 rounded-lg text-left text-[13px] text-zinc-200 hover:bg-white/5"
                >
                  <Folder size={14} className="text-primary shrink-0" /> {d.label}
                </button>
              ))}
              {quickDirs !== null && quickDirs.length === 0 && (
                <div className="px-3 py-2 text-zinc-500 text-[11.5px]">No accessible folders found.</div>
              )}
            </div>
          )}

          {path && !loading && (
            <div className="space-y-1">
              {entries
                .filter((entry) => entry.is_dir || !allowedExtensions || allowedExtensions.some(
                  (extension) => entry.name.toLowerCase().endsWith(`.${extension.toLowerCase()}`),
                ))
                .map((entry) => (
                  <button
                    key={entry.path}
                    onClick={() => (entry.is_dir ? enter(entry.path) : onPick(entry.path, entry.name))}
                    className="w-full flex items-center gap-2 px-3 h-10 rounded-lg text-left text-[13px] text-zinc-200 hover:bg-white/5"
                  >
                    {entry.is_dir ? <Folder size={14} className="text-primary shrink-0" /> : <FileIcon size={14} className="text-zinc-500 shrink-0" />}
                    <span className="truncate flex-1">{entry.name}</span>
                  </button>
                ))}
              {entries.filter((entry) => entry.is_dir || !allowedExtensions || allowedExtensions.some(
                (extension) => entry.name.toLowerCase().endsWith(`.${extension.toLowerCase()}`),
              )).length === 0 && <div className="px-3 py-2 text-zinc-500 text-[11.5px]">No matching files.</div>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LocalFileBrowser;
