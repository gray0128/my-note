// S-Plugin-1: Dedicated `'self'` Web Worker executing zero-import Core WASM 3-Export ABI.
// Zero VKEK, zero DOM access, zero network calls inside WASM (`imports.length === 0`).

const WASM_PAGE_BYTES = 65536;
const DEFAULT_MAX_PAGES = 256; // 16 MiB
const EXPECTED_ABI_VERSION = 1;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

let cachedModule = null;
let cachedInstance = null;

function readUleb128(bytes, offset) {
  let val = 0;
  let shift = 0;
  let pos = offset;
  while (pos < bytes.length) {
    const b = bytes[pos++];
    val |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) {
      return { val: val >>> 0, next: pos };
    }
    shift += 7;
    if (shift > 35) throw new Error("malformed LEB128");
  }
  throw new Error("truncated LEB128");
}

function encodeUleb128(val) {
  const out = [];
  let v = val >>> 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v !== 0) b |= 0x80;
    out.push(b);
  } while (v !== 0);
  return out;
}

/**
 * Inspects Core WASM Section 5 (Memory) BEFORE compilation:
 * - Rejects multi-memory (`count > 1`) and initial memory > `maxPages` (`16 MiB`);
 * - Rewrites unbounded `(memory min)` or `max > maxPages` to `(memory min maxPages)`
 *   so V8 and JavaScriptCore natively deny `memory.grow` past 16 MiB inside the VM.
 */
function enforceSection5MemoryCap(rawBytes, maxPages = DEFAULT_MAX_PAGES) {
  const bytes = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
  if (
    bytes.length < 8 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d
  ) {
    throw { code: "PLUGIN_INVALID_MANIFEST", detail: "invalid WASM magic header" };
  }

  const outChunks = [bytes.subarray(0, 8)];
  let pos = 8;
  while (pos < bytes.length) {
    const secStart = pos;
    const secId = bytes[pos++];
    const { val: secLen, next: payloadStart } = readUleb128(bytes, pos);
    const secEnd = payloadStart + secLen;
    if (secEnd > bytes.length) {
      throw { code: "PLUGIN_INVALID_MANIFEST", detail: "truncated WASM section" };
    }

    if (secId !== 5) {
      outChunks.push(bytes.subarray(secStart, secEnd));
      pos = secEnd;
      continue;
    }

    let p = payloadStart;
    const { val: memCount, next: afterCount } = readUleb128(bytes, p);
    p = afterCount;
    if (memCount > 1) {
      throw {
        code: "PLUGIN_INVALID_MANIFEST",
        detail: `multi-memory rejected: count=${memCount} > 1`,
      };
    }

    const newSecPayload = [...encodeUleb128(memCount)];
    for (let i = 0; i < memCount; i++) {
      const flags = bytes[p++];
      if ((flags & ~0x01) !== 0) {
        throw {
          code: "PLUGIN_INVALID_MANIFEST",
          detail: `unsupported memory flags 0x${flags.toString(16)} (threads/memory64 forbidden)`,
        };
      }
      const { val: minPages, next: afterMin } = readUleb128(bytes, p);
      p = afterMin;
      if (minPages > maxPages) {
        throw {
          code: "PLUGIN_RESOURCE_EXCEEDED",
          detail: `initial memory ${minPages} pages exceeds ${maxPages} pages (16 MiB)`,
        };
      }
      let effectiveMax = maxPages;
      if ((flags & 0x01) !== 0) {
        const { val: declMax, next: afterMax } = readUleb128(bytes, p);
        p = afterMax;
        effectiveMax = Math.min(declMax, maxPages);
      }
      newSecPayload.push(0x01, ...encodeUleb128(minPages), ...encodeUleb128(effectiveMax));
    }

    outChunks.push(
      new Uint8Array([5, ...encodeUleb128(newSecPayload.length), ...newSecPayload]),
    );
    pos = secEnd;
  }

  let total = 0;
  for (const c of outChunks) total += c.length;
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of outChunks) {
    merged.set(c, off);
    off += c.length;
  }
  return merged;
}

async function compileZeroImportModule(rawBytes, clampMemory = true, maxPages = DEFAULT_MAX_PAGES) {
  const bytes = clampMemory
    ? enforceSection5MemoryCap(rawBytes, maxPages)
    : new Uint8Array(rawBytes);

  let mod;
  try {
    mod = await WebAssembly.compile(bytes);
  } catch (err) {
    throw { code: "PLUGIN_INVALID_MANIFEST", detail: `WebAssembly.compile failed: ${String(err)}` };
  }

  const imports = WebAssembly.Module.imports(mod);
  if (imports.length !== 0) {
    const desc = imports.slice(0, 8).map((i) => `${i.module}::${i.name}`).join(", ");
    throw {
      code: "PLUGIN_INVALID_MANIFEST",
      detail: `INV-PLUGIN-ZERO-IMPORT violated: ${imports.length} import(s) [${desc}]`,
    };
  }
  return mod;
}

function invokeOnInstance(instance, reqBytes, maxBytes = DEFAULT_MAX_PAGES * WASM_PAGE_BYTES) {
  const exp = instance.exports;
  if (
    !(exp.memory instanceof WebAssembly.Memory) ||
    typeof exp.mynote_abi_version !== "function" ||
    typeof exp.mynote_alloc !== "function" ||
    typeof exp.mynote_invoke !== "function"
  ) {
    throw { code: "PLUGIN_INVALID_MANIFEST", detail: "missing required 3-Export ABI symbols" };
  }

  const abi = exp.mynote_abi_version() >>> 0;
  if (abi !== EXPECTED_ABI_VERSION) {
    throw { code: "PLUGIN_INVALID_MANIFEST", detail: `ABI version mismatch: ${abi}` };
  }

  const reqLen = reqBytes.byteLength >>> 0;
  let reqPtr = 0;
  let packed = 0n;
  try {
    reqPtr = exp.mynote_alloc(reqLen) >>> 0;
    if (reqLen > 0 && reqPtr === 0) {
      throw { code: "PLUGIN_RESOURCE_EXCEEDED", detail: "mynote_alloc returned 0 (OOM)" };
    }
    if (reqLen > 0) {
      new Uint8Array(exp.memory.buffer, reqPtr, reqLen).set(reqBytes);
    }
    packed = exp.mynote_invoke(reqPtr, reqLen);
  } catch (err) {
    if (err && err.code) throw err;
    const msg = String(err);
    if (err instanceof WebAssembly.RuntimeError || msg.includes("unreachable") || msg.includes("memory")) {
      throw { code: "PLUGIN_RESOURCE_EXCEEDED", detail: `WASM trap / OOM bound: ${msg}` };
    }
    throw { code: "PLUGIN_EXECUTION_FAILED", detail: msg };
  }

  if (exp.memory.buffer.byteLength > maxBytes) {
    throw {
      code: "PLUGIN_RESOURCE_EXCEEDED",
      detail: `linear memory ${exp.memory.buffer.byteLength} B exceeded ${maxBytes} B`,
    };
  }

  const bigPacked = typeof packed === "bigint" ? packed : BigInt(packed);
  const respPtr = Number((bigPacked >> 32n) & 0xffffffffn);
  const respLen = Number(bigPacked & 0xffffffffn);
  if (respPtr + respLen > exp.memory.buffer.byteLength) {
    throw { code: "PLUGIN_EXECUTION_FAILED", detail: "response slice out of bounds" };
  }

  const respSlice = new Uint8Array(exp.memory.buffer, respPtr, respLen).slice();
  if (typeof exp.mynote_dealloc === "function") {
    if (reqLen > 0) exp.mynote_dealloc(reqPtr, reqLen);
    if (respLen > 0) exp.mynote_dealloc(respPtr, respLen);
  }

  return {
    responseJson: textDecoder.decode(respSlice),
    memoryBytes: exp.memory.buffer.byteLength,
  };
}

self.onmessage = async (ev) => {
  const { id, cmd, wasmBytes, requestJson, clampMemory = true } = ev.data;
  try {
    if (cmd === "compile_cache") {
      cachedModule = await compileZeroImportModule(wasmBytes, clampMemory);
      cachedInstance = await WebAssembly.instantiate(cachedModule, {});
      self.postMessage({ id, ok: true, cached: true });
      return;
    }
    if (cmd === "invoke_cold") {
      const mod = await compileZeroImportModule(wasmBytes, clampMemory);
      const inst = await WebAssembly.instantiate(mod, {});
      const reqBytes = textEncoder.encode(requestJson);
      const maxBytes = clampMemory
        ? DEFAULT_MAX_PAGES * WASM_PAGE_BYTES
        : Number.MAX_SAFE_INTEGER;
      const res = invokeOnInstance(inst, reqBytes, maxBytes);
      self.postMessage({ id, ok: true, ...res });
      return;
    }
    if (cmd === "invoke_cached_fresh_instance") {
      if (!cachedModule) throw { code: "PLUGIN_EXECUTION_FAILED", detail: "module not cached" };
      const inst = await WebAssembly.instantiate(cachedModule, {});
      const reqBytes = textEncoder.encode(requestJson);
      const res = invokeOnInstance(inst, reqBytes);
      self.postMessage({ id, ok: true, ...res });
      return;
    }
    if (cmd === "invoke_cached_reused_instance") {
      if (!cachedInstance) throw { code: "PLUGIN_EXECUTION_FAILED", detail: "instance not cached" };
      const reqBytes = textEncoder.encode(requestJson);
      const res = invokeOnInstance(cachedInstance, reqBytes);
      self.postMessage({ id, ok: true, ...res });
      return;
    }
    throw { code: "PLUGIN_EXECUTION_FAILED", detail: `unknown worker cmd: ${cmd}` };
  } catch (err) {
    const error =
      err && typeof err === "object" && err.code
        ? { code: err.code, detail: String(err.detail || "") }
        : { code: "PLUGIN_EXECUTION_FAILED", detail: String(err) };
    self.postMessage({ id, ok: false, error });
  }
};
