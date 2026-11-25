import initPwaWasm, { WasmSyncEngine, WasmVaultSession, initSync } from "./pkg-pwa/mynote_wasm.js";

export { WasmSyncEngine, WasmVaultSession };
export type { DecryptedBlockPayload } from "./pkg-pwa/mynote_wasm.js";

let initPromise: Promise<void> | null = null;
let initialized = false;

export function initPwaWasmSync(bytes: BufferSource): void {
  if (initialized) return;
  initSync({ module: bytes });
  initialized = true;
}

export async function ensurePwaWasm(): Promise<void> {
  if (initialized) return;
  if (!initPromise) {
    initPromise = initPwaWasm()
      .then(() => {
        initialized = true;
      })
      .catch((err) => {
        initPromise = null;
        throw err;
      });
  }
  await initPromise;
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
    // plain string
  }
  return { code: "WASM_ERROR", message: raw };
}
