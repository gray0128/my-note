import initDesktopWasm, {
  WasmVaultSession,
  detectSecretPattern as wasmDetectRaw,
  formatSnippet as wasmFormatRaw,
  initSync,
} from "./pkg/mynote_wasm.js";

export type { DecryptedBlockPayload, Tier2EncryptedOp, WasmVaultSession } from "./pkg/mynote_wasm.js";

let initPromise: Promise<void> | null = null;
let initialized = false;

export function initDesktopWasmSync(bytes: BufferSource): void {
  if (initialized) return;
  initSync({ module: bytes });
  initialized = true;
}

export async function ensureDesktopWasm(): Promise<void> {
  if (initialized) return;
  if (!initPromise) {
    initPromise = initDesktopWasm().then(() => {
      initialized = true;
    });
  }
  await initPromise;
}

export function isDesktopWasmReady(): boolean {
  return initialized;
}

export function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function parseWasmError(err: unknown): { code: string; message: string; hint?: string } {
  const raw = typeof err === "string" ? err : err instanceof Error ? err.message : String(err);
  try {
    const parsed = JSON.parse(raw) as { code?: string; message?: string; hint?: string };
    if (parsed && typeof parsed === "object" && parsed.code) {
      return { code: parsed.code, message: parsed.message ?? parsed.code, hint: parsed.hint };
    }
  } catch {
    // plain string error
  }
  return { code: "WASM_ERROR", message: raw };
}

export async function createVaultHeaderWasm(
  passphrase: string,
  recoveryPkB64: string,
): Promise<{ gen: number; blob_b64: string }> {
  await ensureDesktopWasm();
  const raw = WasmVaultSession.createVaultHeader(passphrase, b64ToBytes(recoveryPkB64));
  return JSON.parse(raw) as { gen: number; blob_b64: string };
}

export async function unlockVaultWithPassphraseWasm(
  passphrase: string,
  vaultHeaderB64: string,
): Promise<WasmVaultSession> {
  await ensureDesktopWasm();
  return WasmVaultSession.unlockWithPassphrase(passphrase, b64ToBytes(vaultHeaderB64));
}

export async function unlockVaultWithRecoveryWordsWasm(
  recoveryWords: string,
  vaultHeaderB64: string,
): Promise<WasmVaultSession> {
  await ensureDesktopWasm();
  return WasmVaultSession.unlockWithRecoveryWords(recoveryWords, b64ToBytes(vaultHeaderB64));
}

export async function formatSnippetWasm(content: string, lang: string, action?: string): Promise<string> {
  await ensureDesktopWasm();
  return wasmFormatRaw(content, lang, action ?? undefined);
}

export function detectSecretPatternFast(text: string): string | null {
  if (initialized) {
    return wasmDetectRaw(text) ?? null;
  }
  // Lightweight fallback before WASM initializes; mirrors `mynote_core::vault::detect_secret_pattern`
  if (text.includes("-----BEGIN ") && text.includes("PRIVATE KEY-----")) return "pem_private_key";
  if (/\b(AKIA|ASIA)[0-9A-Z]{16}\b/.test(text)) return "aws_access_key";
  if (/\bgh[pousr]_[A-Za-z0-9]{20,}\b/.test(text)) return "github_token";
  if (/\bsk-(?:live|test|proj)-[A-Za-z0-9_-]{16,}\b/.test(text)) return "api_secret_key";
  if (/\bxox[baprs]-[A-Za-z0-9-]{16,}\b/.test(text)) return "slack_token";
  return null;
}
