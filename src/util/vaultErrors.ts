// Every vault-related Tauri command failure crosses the IPC boundary as a
// string shaped "[CODE] message" (see `Outcome::to_string()` in
// src-tauri/src/vault.rs) — the Rust side already writes a good, complete,
// user-facing message per code, so this module does NOT re-author its own
// English strings (that would just drift out of sync with the source of
// truth). Its only job is pulling the code back out for behavioral
// branching (which dialog to show, whether to offer a retry) and handing
// back the backend's own message with the bracket stripped.
//
// Mirrors `outcome_code_from_error` in src-tauri/src/vault.rs: recognizing
// only a real outcome code (never an internal "[FILE]"/"[STATE]"/"[CRYPTO]"/
// "[VALIDATION]" plumbing error) matters less here than on the Rust side
// (there's no diagnostic log to keep clean on this side), but the same
// regex naturally only matches the same shape either way.
export interface VaultErrorInfo {
  /** e.g. "VAULT_AUTH", or null if the error didn't have a "[CODE]" prefix at all. */
  code: string | null;
  /** User-facing text, with the "[CODE]" prefix stripped if present. */
  message: string;
  /** True only for VAULT_KEYSTORE_DENIED — the one outcome that's meaningfully retryable (T074). */
  retryable: boolean;
}

const CODE_PATTERN = /^\[([A-Z_]+)\]\s*(.*)$/s;

export function describeVaultError(e: unknown): VaultErrorInfo {
  const raw = String(e instanceof Error ? e.message : e);
  const match = raw.match(CODE_PATTERN);
  if (!match) {
    return { code: null, message: raw, retryable: false };
  }
  const [, code, rest] = match;
  return { code, message: rest || raw, retryable: code === "VAULT_KEYSTORE_DENIED" };
}
