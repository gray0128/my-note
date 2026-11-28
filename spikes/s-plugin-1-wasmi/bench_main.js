// Main-page harness for S-Plugin-1 `'self'` Web Worker benchmark & security gates.
const cspViolations = [];
window.addEventListener("securitypolicyviolation", (e) => {
  cspViolations.push(`${e.violatedDirective}: ${e.blockedURI}`);
});

class BoundedPluginWorkerClient {
  constructor(workerUrl = "/plugin_worker.js") {
    this.workerUrl = workerUrl;
    this.worker = new Worker(this.workerUrl);
    this.nextId = 1;
    this.pending = new Map();
    this._bindWorker(this.worker);
  }

  _bindWorker(w) {
    w.onmessage = (ev) => {
      const msg = ev.data;
      const entry = this.pending.get(msg.id);
      if (!entry) return;
      this.pending.delete(msg.id);
      clearTimeout(entry.timer);
      if (msg.ok) {
        entry.resolve(msg);
      } else {
        entry.reject(msg.error);
      }
    };
    w.onerror = (err) => {
      for (const [, entry] of this.pending) {
        clearTimeout(entry.timer);
        entry.reject({ code: "PLUGIN_EXECUTION_FAILED", detail: String(err.message || err) });
      }
      this.pending.clear();
    };
  }

  call(payload, timeoutMs = 2000) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.worker.terminate();
        this.worker = new Worker(this.workerUrl);
        this._bindWorker(this.worker);
        reject({
          code: "PLUGIN_RESOURCE_EXCEEDED",
          detail: `worker.terminate() hard timeout after ${timeoutMs} ms`,
          terminated: true,
        });
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.worker.postMessage({ id, ...payload });
    });
  }

  dispose() {
    this.worker.terminate();
  }
}

async function fetchWasm(name) {
  const res = await fetch(`/fixtures/${name}`, { redirect: "manual" });
  if (res.status !== 200) throw new Error(`failed to fetch ${name}: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

function summarizeMs(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  const p50 =
    n % 2 === 1 ? sorted[(n - 1) / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
  const p95Idx = Math.min(n - 1, Math.max(0, Math.ceil(n * 0.95) - 1));
  const mean = sorted.reduce((a, b) => a + b, 0) / n;
  return {
    runs: n,
    minMs: sorted[0],
    p50Ms: p50,
    p95Ms: sorted[p95Idx],
    maxMs: sorted[n - 1],
    meanMs: mean,
  };
}

function build16kJsonRequest() {
  const parts = [];
  for (let i = 179; i >= 0; i--) {
    const pad = String(i).padStart(3, "0");
    parts.push(
      `"key_${pad}":{"seq":${i},"active":${i % 2 === 0},"tag":"block_item_${pad}","ratio":${i % 17}.${(i * 7) % 100}}`,
    );
  }
  const messy = `{"zeta":[1,2,3],${parts.join(",")},"alpha":"first"}`;
  return JSON.stringify({
    slot: "transform",
    action: "json_canonicalize",
    content: messy,
  });
}

async function runSuite(runs = 100) {
  const [guestWasm, evilImportWasm, infiniteLoopWasm, oomGrowBombWasm, oomInitBombWasm] =
    await Promise.all([
      fetchWasm("guest_calc.wasm"),
      fetchWasm("evil_import.wasm"),
      fetchWasm("infinite_loop.wasm"),
      fetchWasm("oom_grow_bomb.wasm"),
      fetchWasm("oom_init_bomb.wasm"),
    ]);

  const client = new BoundedPluginWorkerClient();
  try {
    // 1. INV-PLUGIN-ZERO-IMPORT: non-empty import rejected before instantiation
    let evilRejected = null;
    try {
      await client.call({ cmd: "invoke_cold", wasmBytes: evilImportWasm, requestJson: "{}" }, 1000);
    } catch (e) {
      evilRejected = e;
    }

    // 2. INV-PLUGIN-RESOURCE-BOUND (OOM > 16 MiB grow bomb with Section-5 clamping vs unguarded control)
    let oomGrowClampedRejected = null;
    try {
      await client.call(
        { cmd: "invoke_cold", wasmBytes: oomGrowBombWasm, requestJson: "{}", clampMemory: true },
        1000,
      );
    } catch (e) {
      oomGrowClampedRejected = e;
    }

    // Positive control proving why Section-5 clamping is essential in Browser Workers:
    const unguardedRes = await client.call(
      { cmd: "invoke_cold", wasmBytes: oomGrowBombWasm, requestJson: "{}", clampMemory: false },
      1000,
    );

    let oomInitRejected = null;
    try {
      await client.call(
        { cmd: "invoke_cold", wasmBytes: oomInitBombWasm, requestJson: "{}", clampMemory: true },
        1000,
      );
    } catch (e) {
      oomInitRejected = e;
    }

    // 3. INV-PLUGIN-RESOURCE-BOUND (Infinite loop -> hard `worker.terminate()` at 60 ms + auto-respawn)
    let infiniteLoopTerminated = null;
    const tLoop0 = performance.now();
    try {
      await client.call(
        { cmd: "invoke_cold", wasmBytes: infiniteLoopWasm, requestJson: "{}" },
        60,
      );
    } catch (e) {
      infiniteLoopTerminated = { ...e, elapsedMs: performance.now() - tLoop0 };
    }

    // 4. Verify immediate clean recovery on respawned worker + cache `guest_calc.wasm`
    const mathReq = JSON.stringify({
      slot: "inspector",
      action: "eval_lines",
      content:
        "unit_price = 19.99 * 3\ntax = round(unit_price * 8) / 100\nshipping = sqrt(144) + 2^3\ntotal = unit_price + tax + shipping\nmargin_pct = round((total - 45) / total * 1000) / 10",
    });
    const json16kReq = build16kJsonRequest();

    await client.call({ cmd: "compile_cache", wasmBytes: guestWasm }, 2000);
    const sanity = await client.call(
      { cmd: "invoke_cached_fresh_instance", requestJson: mathReq },
      2000,
    );
    const parsedSanity = JSON.parse(sanity.responseJson);

    // Warmup (5 runs)
    for (let i = 0; i < 5; i++) {
      await client.call({ cmd: "invoke_cold", wasmBytes: guestWasm, requestJson: mathReq }, 2000);
      await client.call({ cmd: "invoke_cached_fresh_instance", requestJson: mathReq }, 2000);
      await client.call({ cmd: "invoke_cached_reused_instance", requestJson: mathReq }, 2000);
    }

    // 5. Cold roundtrip (postMessage + Section-5 cap + WebAssembly.compile + instantiate + invoke)
    const coldMathSamples = [];
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      const out = await client.call(
        { cmd: "invoke_cold", wasmBytes: guestWasm, requestJson: mathReq },
        2000,
      );
      coldMathSamples.push(performance.now() - t0);
      if (!out.responseJson.includes('"84.77"')) throw new Error("bad math output");
    }

    // 6. Warm roundtrip (cached Module, fresh instance per call)
    const warmFreshMathSamples = [];
    let freshMathMem = 0;
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      const out = await client.call(
        { cmd: "invoke_cached_fresh_instance", requestJson: mathReq },
        2000,
      );
      warmFreshMathSamples.push(performance.now() - t0);
      freshMathMem = out.memoryBytes;
      if (!out.responseJson.includes('"84.77"')) throw new Error("bad math output");
    }

    const warmFreshJsonSamples = [];
    let freshJsonMem = 0;
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      const out = await client.call(
        { cmd: "invoke_cached_fresh_instance", requestJson: json16kReq },
        2000,
      );
      warmFreshJsonSamples.push(performance.now() - t0);
      freshJsonMem = out.memoryBytes;
      if (!out.responseJson.includes('\\"alpha\\": \\"first\\"')) {
        throw new Error("bad json output");
      }
    }

    // 7. Warm roundtrip (cached Module + reused Instance — verify constant memoryBytes)
    const baselineReused = await client.call(
      { cmd: "invoke_cached_reused_instance", requestJson: mathReq },
      2000,
    );
    const warmReusedMathSamples = [];
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      const out = await client.call(
        { cmd: "invoke_cached_reused_instance", requestJson: mathReq },
        2000,
      );
      warmReusedMathSamples.push(performance.now() - t0);
      if (out.memoryBytes !== baselineReused.memoryBytes) {
        throw new Error(`memory leak in reused worker instance: ${out.memoryBytes}`);
      }
    }

    const baselineReusedJson = await client.call(
      { cmd: "invoke_cached_reused_instance", requestJson: json16kReq },
      2000,
    );
    const warmReusedJsonSamples = [];
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      const out = await client.call(
        { cmd: "invoke_cached_reused_instance", requestJson: json16kReq },
        2000,
      );
      warmReusedJsonSamples.push(performance.now() - t0);
      if (out.memoryBytes !== baselineReusedJson.memoryBytes) {
        throw new Error(`memory leak in reused json instance: ${out.memoryBytes}`);
      }
    }

    // 8. High-resolution amortized serial roundtrips (20 sequential calls per batch x 25 batches = 500 calls)
    //    Overcomes Chromium 0.1 ms and WebKit 1.0 ms Spectre `performance.now()` coarsening.
    const batchSize = 20;
    const batches = 25;
    const amortMathUs = [];
    const amortJsonUs = [];
    for (let b = 0; b < batches; b++) {
      const tm0 = performance.now();
      for (let k = 0; k < batchSize; k++) {
        await client.call({ cmd: "invoke_cached_fresh_instance", requestJson: mathReq }, 2000);
      }
      amortMathUs.push(((performance.now() - tm0) * 1000.0) / batchSize);

      const tj0 = performance.now();
      for (let k = 0; k < batchSize; k++) {
        await client.call({ cmd: "invoke_cached_fresh_instance", requestJson: json16kReq }, 2000);
      }
      amortJsonUs.push(((performance.now() - tj0) * 1000.0) / batchSize);
    }

    return {
      guestWasmBytes: guestWasm.byteLength,
      cspViolations,
      gates: {
        evilRejected,
        oomGrowClampedRejected,
        unguardedOomControlMemoryBytes: unguardedRes.memoryBytes,
        oomInitRejected,
        infiniteLoopTerminated,
        postTerminateSanity: parsedSanity,
      },
      benchmarks: {
        coldRoundtripMath: summarizeMs(coldMathSamples),
        warmFreshInstanceMath: {
          latency: summarizeMs(warmFreshMathSamples),
          amortizedBatch20Us: summarizeMs(amortMathUs),
          memoryBytes: freshMathMem,
        },
        warmFreshInstanceJson16k: {
          latency: summarizeMs(warmFreshJsonSamples),
          amortizedBatch20Us: summarizeMs(amortJsonUs),
          memoryBytes: freshJsonMem,
        },
        warmReusedInstanceMath: {
          latency: summarizeMs(warmReusedMathSamples),
          memoryBytes: baselineReused.memoryBytes,
        },
        warmReusedInstanceJson16k: {
          latency: summarizeMs(warmReusedJsonSamples),
          memoryBytes: baselineReusedJson.memoryBytes,
        },
      },
    };
  } finally {
    client.dispose();
  }
}

window.__sPlugin1 = { runSuite };
window.__sPlugin1Ready = true;
document.getElementById("status").textContent = "ready";
