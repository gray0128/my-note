import { describe, it, expect, beforeEach, vi } from "vitest";
import { MyNoteApp } from "../src/app";
import { MobilePwaApp } from "../src/pwa/pwaApp";
import type { LocalApiClient } from "../src/api";
import type {
  BlockDto,
  BlockHistoryContentDto,
  BlockHistoryEntryDto,
  BootstrapResponse,
  BufferDto,
  LocalWsFrame,
  SyncStatusDto,
  TrashItemDto,
} from "../src/types";

function makeMockApi() {
  const buffers: BufferDto[] = [{ id: "01BUF000000000000000000001", name: "scratch", position: "a0", updated_at_ms: 1000 }];
  let blocks: BlockDto[] = [
    {
      id: "01BLK000000000000000000001",
      buffer_id: buffers[0].id,
      position: "a0",
      lang: "json",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01OP0000000000000000000001"],
      display_op_id: "01OP0000000000000000000001",
      has_conflict: false,
      content: '{"a":1}',
      versions: [
        {
          op_id: "01OP0000000000000000000001",
          hlc: "000000000001000-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01KEY000000000000000000001",
          content: '{"a":1}',
        },
      ],
      updated_at_ms: 1000,
    },
    {
      id: "01BLK000000000000000000002",
      buffer_id: buffers[0].id,
      position: "b0",
      lang: "text",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01OP0000000000000000000002", "01OP0000000000000000000003"],
      display_op_id: "01OP0000000000000000000003",
      has_conflict: true,
      content: "version from omarchy",
      versions: [
        {
          op_id: "01OP0000000000000000000003",
          hlc: "000000000002000-00000-dev_linux00000001",
          device_id: "dev_linux00000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01KEY000000000000000000002",
          content: "version from omarchy",
        },
        {
          op_id: "01OP0000000000000000000002",
          hlc: "000000000001500-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: false,
          is_locked: false,
          key_id: "01KEY000000000000000000002",
          content: "version from macos",
        },
      ],
      updated_at_ms: 2000,
    },
  ];
  let trash: TrashItemDto[] = [];
  let wsListener: ((frame: LocalWsFrame) => void) | null = null;
  let seq = 10;

  const status: SyncStatusDto = {
    sync_state: "synced",
    epoch: "00000000-0000-4000-8000-000000000001",
    last_seq: 10,
    pending_ops: 0,
    blocked_ops: 0,
    clock_skew_ms: 0,
    key_self_check: { ok: true, last_run_ms: 1000, blocks_missing_key: 0 },
    trash: { count: 0, pending_confirm_count: 0, next_shred_ms: null },
    recovery_drill_due: false,
    last_recovery_drill_ms: 1000,
    last_local_backup_ms: 1000,
  };

  const api: LocalApiClient = {
    async bootstrap(): Promise<BootstrapResponse> {
      return {
        buffers: [...buffers],
        initial_buffer_id: buffers[0].id,
        blocks: [...blocks],
        sync_status: { ...status },
        vault_header: null,
        trash_count: trash.length,
        device_id: "dev_mac0000000001",
        last_hlc: null,
      };
    },
    async listBlocks(bufferId) {
      return blocks.filter((b) => b.buffer_id === bufferId);
    },
    async createBlock(input) {
      seq++;
      const created: BlockDto = {
        id: `01BLK0000000000000000000${seq}`,
        buffer_id: input.buffer_id,
        position: `c${seq}`,
        lang: input.lang,
        is_locked: false,
        has_unlocked_concurrent_version: false,
        public_hint: null,
        head_op_ids: [`01OP00000000000000000000${seq}`],
        display_op_id: `01OP00000000000000000000${seq}`,
        has_conflict: false,
        content: input.content ?? null,
        versions: [
          {
            op_id: `01OP00000000000000000000${seq}`,
            hlc: `00000000000${seq}00-00000-dev_mac0000000001`,
            device_id: "dev_mac0000000001",
            actor: "human",
            is_display: true,
            is_locked: false,
            key_id: "01KEYNEW",
            content: input.content ?? null,
          },
        ],
        updated_at_ms: 3000 + seq,
      };
      blocks.push(created);
      return created;
    },
    async patchBlock(id, input) {
      const idx = blocks.findIndex((b) => b.id === id);
      const cur = blocks[idx];
      const nextContent = input.content !== undefined ? input.content : cur.content;
      const nextPos = input.before_id ? "00" : input.after_id ? "z9" : cur.position;
      seq++;
      const updated: BlockDto = {
        ...cur,
        lang: input.lang ?? cur.lang,
        position: nextPos,
        content: nextContent,
        has_conflict: input.content !== undefined ? false : cur.has_conflict,
        head_op_ids: input.content !== undefined ? [`01OP_MERGED_${seq}`] : cur.head_op_ids,
        display_op_id: input.content !== undefined ? `01OP_MERGED_${seq}` : cur.display_op_id,
        versions:
          input.content !== undefined
            ? [{ ...cur.versions[0], op_id: `01OP_MERGED_${seq}`, is_display: true, content: nextContent }]
            : cur.versions,
      };
      blocks[idx] = updated;
      return updated;
    },
    async resolveBlock(id, input) {
      const cur = blocks.find((b) => b.id === id)!;
      const picked = cur.versions.find((v) => v.op_id === input.keep_op_id)?.content ?? input.content ?? "";
      return this.patchBlock(id, { expected_heads: input.expected_heads, content: picked });
    },
    async deleteBlock(id) {
      const blk = blocks.find((b) => b.id === id)!;
      blocks = blocks.filter((b) => b.id !== id);
      trash.push({
        id: blk.id,
        buffer_id: blk.buffer_id,
        buffer_name: "scratch",
        is_locked: false,
        preview: blk.content,
        deleted_at_ms: 4000,
        deleted_by_device: "dev_mac0000000001",
        actor: "human",
        shred_not_before_ms: null,
        shred_state: "unscheduled",
      });
      return { in_trash: true, shred_state: "unscheduled", shred_not_before_ms: null };
    },
    async createBuffer(input) {
      const b: BufferDto = { id: `01BUF_${input.name}`, name: input.name, position: "z0", updated_at_ms: 4000 };
      buffers.push(b);
      return b;
    },
    async renameBuffer(id, name) {
      const b = buffers.find((x) => x.id === id)!;
      b.name = name;
      return b;
    },
    async deleteBuffer(id) {
      return buffers.find((x) => x.id === id)!;
    },
    async listTrash() {
      return [...trash];
    },
    async restoreTrash(id) {
      const item = trash.find((t) => t.id === id)!;
      trash = trash.filter((t) => t.id !== id);
      const restored: BlockDto = {
        id: item.id,
        buffer_id: item.buffer_id,
        position: "a0",
        lang: "json",
        is_locked: false,
        has_unlocked_concurrent_version: false,
        public_hint: null,
        head_op_ids: ["01OP_RESTORED"],
        display_op_id: "01OP_RESTORED",
        has_conflict: false,
        content: item.preview ?? "",
        versions: [
          {
            op_id: "01OP_RESTORED",
            hlc: "000000000009000-00000-dev_mac0000000001",
            device_id: "dev_mac0000000001",
            actor: "human",
            is_display: true,
            is_locked: false,
            key_id: "01KEY000000000000000000001",
            content: item.preview ?? "",
          },
        ],
        updated_at_ms: 5000,
      };
      blocks.push(restored);
      return restored;
    },
    async formatSnippet(input) {
      return { formatted: JSON.stringify(JSON.parse(input.content), null, 2) };
    },
    async syncNow() {
      return { ...status };
    },
    connectWs(onFrame) {
      wsListener = onFrame;
      return () => {
        wsListener = null;
      };
    },
  };

  return {
    api,
    pushWs(frame: LocalWsFrame) {
      wsListener?.(frame);
    },
  };
}

describe("M1 Embedded Desktop Web UI (Candidate A CM6)", () => {
  let root: HTMLElement;

  beforeEach(() => {
    document.body.innerHTML = `<div id="app" class="app-shell"></div>`;
    root = document.getElementById("app")!;
  });

  it("supports create, language switch, Layer 1 format, dual-leaf conflict merge, trash & restore, and live WS updates", async () => {
    const { api, pushWs } = makeMockApi();
    const app = new MyNoteApp(root, api);
    await app.start();

    // 1. Initial render: 2 blocks, second block has conflict panel with 2 leaf cards
    expect(root.querySelectorAll(".block-card").length).toBe(2);
    expect(root.querySelectorAll(".conflict-panel").length).toBe(1);
    expect(root.querySelectorAll(".leaf-card").length).toBe(2);

    // 2. Format block 1 JSON via header button
    const firstCard = root.querySelector<HTMLElement>('[data-block-id="01BLK000000000000000000001"]')!;
    const formatBtn = [...firstCard.querySelectorAll("button")].find((b) => b.textContent === "Format")!;
    formatBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(app.stream.getBlockDraftContent("01BLK000000000000000000001")).toBe('{\n  "a": 1\n}');

    // 3. Change language on block 1
    const langSel = firstCard.querySelector<HTMLSelectElement>(".lang-select")!;
    langSel.value = "yaml";
    langSel.dispatchEvent(new Event("change"));
    await new Promise((r) => setTimeout(r, 20));
    expect(app.stream.getBlocks().find((b) => b.id === "01BLK000000000000000000001")?.lang).toBe("yaml");

    // 4. Resolve dual-leaf conflict on block 2 by clicking "Keep this version" on Mac version -> converges to 1 leaf
    const conflictCard = root.querySelector<HTMLElement>('[data-block-id="01BLK000000000000000000002"]')!;
    const keepBtns = [...conflictCard.querySelectorAll<HTMLButtonElement>(".leaf-card button")];
    expect(keepBtns.length).toBe(2);
    keepBtns[1].click();
    await new Promise((r) => setTimeout(r, 20));
    const resolved = app.stream.getBlocks().find((b) => b.id === "01BLK000000000000000000002")!;
    expect(resolved.has_conflict).toBe(false);
    expect(resolved.head_op_ids.length).toBe(1);
    expect(resolved.content).toBe("version from macos");
    expect(root.querySelectorAll(".conflict-panel").length).toBe(0);

    // 5. Create new block via "+ New Block"
    const newBtn = [...root.querySelectorAll("button")].find((b) => b.textContent === "+ New Block")!;
    newBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(root.querySelectorAll(".block-card").length).toBe(3);

    // 6. Move block 1 to recycle bin & restore from Trash drawer
    const card1Again = root.querySelector<HTMLElement>('[data-block-id="01BLK000000000000000000001"]')!;
    const trashBtn = [...card1Again.querySelectorAll("button")].find((b) => b.textContent === "Trash")!;
    trashBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(root.querySelectorAll(".block-card").length).toBe(2);

    const openTrash = [...root.querySelectorAll("button")].find((b) => b.textContent?.startsWith("Trash ("))!;
    openTrash.click();
    await new Promise((r) => setTimeout(r, 20));
    const restoreBtn = root.querySelector<HTMLButtonElement>(".trash-item button")!;
    expect(restoreBtn.textContent).toBe("Restore");
    restoreBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(root.querySelectorAll(".block-card").length).toBe(3);

    // 7. Live WebSocket blocks_changed & alert banner push
    pushWs({
      type: "blocks_changed",
      upserted: [
        {
          id: "01BLK_CLI_PUSHED_000000009",
          buffer_id: "01BUF000000000000000000001",
          position: "zz",
          lang: "sql",
          is_locked: false,
          has_unlocked_concurrent_version: false,
          public_hint: null,
          head_op_ids: ["01OP_CLI"],
          display_op_id: "01OP_CLI",
          has_conflict: false,
          content: "SELECT 1;",
          versions: [
            {
              op_id: "01OP_CLI",
              hlc: "000000000009999-00000-dev_mac0000000001",
              device_id: "dev_mac0000000001",
              actor: "agent:claude-code",
              is_display: true,
              is_locked: false,
              key_id: "01KEY_CLI",
              content: "SELECT 1;",
            },
          ],
          updated_at_ms: 9999,
        },
      ],
      deleted_ids: [],
    });
    expect(root.querySelector('[data-block-id="01BLK_CLI_PUSHED_000000009"]')).not.toBeNull();
    expect(app.stream.findAcrossBlocks("SELECT 1").length).toBe(1);

    pushWs({ type: "alert", code: "RECOVERY_DRILL_DUE", details: {} });
    expect(root.querySelector('[data-code="RECOVERY_DRILL_DUE"]')).not.toBeNull();

    app.destroy();
  });

  it("preserves original baseHeads on concurrent WS update (triggers HEAD_MISMATCH, zero silent overwrite) and keeps draft intact", async () => {
    const { api, pushWs } = makeMockApi();
    const { LocalApiError } = await import("../src/api");
    const seenExpectedHeads: string[][] = [];
    const origPatch = api.patchBlock.bind(api);
    let currentServerHead = "01OP0000000000000000000001";
    api.patchBlock = async (id, input, opts) => {
      if (input.expected_heads) seenExpectedHeads.push([...input.expected_heads]);
      if (input.content !== undefined && input.expected_heads) {
        const exp = [...input.expected_heads].sort().join(",");
        if (exp !== currentServerHead) {
          throw new LocalApiError(409, { code: "HEAD_MISMATCH", message: "heads changed" });
        }
      }
      const res = await origPatch(id, input, opts);
      currentServerHead = res.head_op_ids.join(",");
      return res;
    };

    const app = new MyNoteApp(root, api);
    await app.start();

    const blkId = "01BLK000000000000000000001";
    // Simulate user editing block 1 in CM6 (making it dirty while baseHeads = [01OP...0001])
    const mounted = (app.stream as unknown as { mounted: Map<string, { view: import("@codemirror/view").EditorView }> }).mounted.get(blkId)!;
    mounted.view.dispatch({ changes: { from: 0, to: mounted.view.state.doc.length, insert: '{"a": 999}' } });

    // Concurrent remote edit arrives on server + over WS before save fires, advancing server head to 01OP_REMOTE_2
    currentServerHead = "01OP_REMOTE_2";
    const remoteUpdated = {
      ...app.stream.getBlocks().find((b) => b.id === blkId)!,
      head_op_ids: ["01OP_REMOTE_2"],
      display_op_id: "01OP_REMOTE_2",
      content: '{"remote": true}',
    };
    const origList = api.listBlocks.bind(api);
    api.listBlocks = async (bufId) => (await origList(bufId)).map((b) => (b.id === blkId ? remoteUpdated : b));
    pushWs({ type: "blocks_changed", upserted: [remoteUpdated], deleted_ids: [] });

    // Flush dirty block -> MUST send original baseHeads ["01OP...0001"], NOT ["01OP_REMOTE_2"]!
    await app.stream.flushDirtyBlock(blkId, { fastSync: true });
    expect(seenExpectedHeads[0]).toEqual(["01OP0000000000000000000001"]);
    // Draft MUST be preserved in CM6 (never wiped!) and mismatch banner shown
    expect(app.stream.getBlockDraftContent(blkId)).toBe('{"a": 999}');
    expect(root.querySelector(".mismatch-panel")).not.toBeNull();

    // User clicks "Save My Draft Over Latest" -> sends explicit merge with latest server head
    const mergeBtn = [...root.querySelectorAll<HTMLButtonElement>(".mismatch-panel button")].find(
      (b) => b.textContent === "Save My Draft Over Latest",
    )!;
    mergeBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(seenExpectedHeads[1]).toEqual(["01OP_REMOTE_2"]);
    expect(app.stream.getBlockDraftContent(blkId)).toBe('{"a": 999}');
    expect(root.querySelector(".mismatch-panel")).toBeNull();

    app.destroy();
  });

  it("serializes in-flight saves so keystrokes typed during PATCH are preserved and saved in a follow-up request", async () => {
    const { api } = makeMockApi();
    const savedContents: string[] = [];
    let releaseFirstPatch!: () => void;
    const origPatch = api.patchBlock.bind(api);
    let callCount = 0;
    api.patchBlock = async (id, input, opts) => {
      callCount++;
      if (input.content !== undefined) savedContents.push(input.content);
      if (callCount === 1) {
        await new Promise<void>((resolve) => {
          releaseFirstPatch = resolve;
        });
      }
      return origPatch(id, input, opts);
    };

    const app = new MyNoteApp(root, api);
    await app.start();

    const blkId = "01BLK000000000000000000001";
    const mounted = (app.stream as unknown as { mounted: Map<string, { view: import("@codemirror/view").EditorView }> }).mounted.get(blkId)!;
    mounted.view.dispatch({ changes: { from: 0, to: mounted.view.state.doc.length, insert: "draft-1" } });

    const firstFlush = app.stream.flushDirtyBlock(blkId, { fastSync: true });
    // While first PATCH is still in flight, user types more characters!
    mounted.view.dispatch({ changes: { from: 7, to: 7, insert: "-more" } });
    releaseFirstPatch();
    await firstFlush;
    await new Promise((r) => setTimeout(r, 20));

    expect(savedContents).toEqual(["draft-1", "draft-1-more"]);
    expect(app.stream.getBlockDraftContent(blkId)).toBe("draft-1-more");
    expect(app.stream.hasDirtyBlocks()).toBe(false);

    app.destroy();
  });

  it("renders unreadable Tier 1 blocks as read-only diagnostic cards and disables Keep on null conflict leaves", async () => {
    const { api, pushWs } = makeMockApi();
    const app = new MyNoteApp(root, api);
    await app.start();

    pushWs({
      type: "blocks_changed",
      upserted: [
        {
          id: "01BLK_UNREADABLE_000000001",
          buffer_id: "01BUF000000000000000000001",
          position: "d0",
          lang: "text",
          is_locked: false,
          has_unlocked_concurrent_version: false,
          public_hint: null,
          head_op_ids: ["01OP_U1", "01OP_U2"],
          display_op_id: "01OP_U1",
          has_conflict: true,
          content: null,
          versions: [
            {
              op_id: "01OP_U1",
              hlc: "000000000005000-00000-dev_remote00001",
              device_id: "dev_remote00001",
              actor: "human",
              is_display: true,
              is_locked: false,
              key_id: "01KEY_MISSING",
              content: null,
            },
            {
              op_id: "01OP_U2",
              hlc: "000000000004000-00000-dev_mac0000000001",
              device_id: "dev_mac0000000001",
              actor: "human",
              is_display: false,
              is_locked: false,
              key_id: "01KEY_OK",
              content: "readable sibling",
            },
          ],
          updated_at_ms: 5000,
        },
      ],
      deleted_ids: [],
    });

    const card = root.querySelector<HTMLElement>('[data-block-id="01BLK_UNREADABLE_000000001"]')!;
    expect(card.querySelector(".unreadable-card")).not.toBeNull();
    expect(card.querySelector(".block-editor-host")).toBeNull();
    expect([...card.querySelectorAll("button")].some((b) => b.textContent === "Format")).toBe(false);
    const keepBtns = [...card.querySelectorAll<HTMLButtonElement>(".leaf-card button")];
    expect(keepBtns[0].disabled).toBe(true);
    expect(keepBtns[1].disabled).toBe(false);

    app.destroy();
  });

  it("flushes dirty edits on buffer switch, keeps Find focus, avoids double Ctrl+Enter, formats dirty blocks, and reconciles DOM incrementally", async () => {
    const { api, pushWs } = makeMockApi();
    let createCalls = 0;
    const savedBeforeSwitch: string[] = [];
    const origCreate = api.createBlock.bind(api);
    const origPatch = api.patchBlock.bind(api);
    api.createBlock = async (input) => {
      createCalls++;
      return origCreate(input);
    };
    api.patchBlock = async (id, input, opts) => {
      if (input.content !== undefined) savedBeforeSwitch.push(input.content);
      return origPatch(id, input, opts);
    };

    const app = new MyNoteApp(root, api);
    await app.start();

    // 1. Format dirty block updates CM6 cleanly and clears dirty
    const blk1 = "01BLK000000000000000000001";
    const m1 = (app.stream as unknown as { mounted: Map<string, { view: import("@codemirror/view").EditorView }> }).mounted.get(blk1)!;
    m1.view.dispatch({ changes: { from: 0, to: m1.view.state.doc.length, insert: '{"z":2}' } });
    const card1 = root.querySelector<HTMLElement>(`[data-block-id="${blk1}"]`)!;
    const fmtBtn = [...card1.querySelectorAll("button")].find((b) => b.textContent === "Format")!;
    fmtBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(app.stream.getBlockDraftContent(blk1)).toBe('{\n  "z": 2\n}');
    expect(app.stream.hasDirtyBlocks()).toBe(false);

    // 2. Keep version on dirty conflict block displays kept version cleanly
    const blk2 = "01BLK000000000000000000002";
    const m2 = (app.stream as unknown as { mounted: Map<string, { view: import("@codemirror/view").EditorView }> }).mounted.get(blk2)!;
    m2.view.dispatch({ changes: { from: 0, to: m2.view.state.doc.length, insert: "abandoned local typing" } });
    const keepBtns = [...root.querySelectorAll<HTMLButtonElement>(`[data-block-id="${blk2}"] .leaf-card button`)];
    keepBtns[1].click();
    await new Promise((r) => setTimeout(r, 20));
    expect(app.stream.getBlockDraftContent(blk2)).toBe("version from macos");

    // 3. Find bar typing MUST NOT steal focus from findInputEl
    const findBtn = [...root.querySelectorAll("button")].find((b) => b.textContent === "Find")!;
    findBtn.click();
    const findInput = root.querySelector<HTMLInputElement>(".find-bar input")!;
    expect(document.activeElement).toBe(findInput);
    findInput.value = "macos";
    findInput.dispatchEvent(new Event("input"));
    expect(document.activeElement).toBe(findInput);
    expect(root.querySelector(".find-bar .kbd")?.textContent).toBe("1 matches");

    // 4. Incremental DOM reconciliation: inserting a remote block via WS MUST preserve card1 DOM node & CM6 view instance
    const card1Before = root.querySelector(`[data-block-id="${blk1}"]`);
    pushWs({
      type: "blocks_changed",
      upserted: [
        {
          id: "01BLK_EXTRA_00000000000001",
          buffer_id: "01BUF000000000000000000001",
          position: "zz",
          lang: "text",
          is_locked: false,
          has_unlocked_concurrent_version: false,
          public_hint: null,
          head_op_ids: ["01OP_EXTRA"],
          display_op_id: "01OP_EXTRA",
          has_conflict: false,
          content: "remote added",
          versions: [],
          updated_at_ms: 8000,
        },
      ],
      deleted_ids: [],
    });
    expect(root.querySelector(`[data-block-id="${blk1}"]`)).toBe(card1Before);

    // 5. Ctrl/Cmd+Enter inside focused CM6 creates exactly 1 block (not 2)
    app.stream.focusBlock(blk1, 0);
    const cmContent = card1.querySelector<HTMLElement>(".cm-content")!;
    cmContent.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", ctrlKey: true, bubbles: true, cancelable: true }));
    await new Promise((r) => setTimeout(r, 20));
    expect(createCalls).toBe(1);

    // 6. Buffer switch flushes dirty edits before switching
    m1.view.dispatch({ changes: { from: 0, to: m1.view.state.doc.length, insert: '{"flushed":true}' } });
    const secondBuf = await api.createBuffer({ name: "work" });
    pushWs({ type: "buffers_changed", upserted: [secondBuf], deleted_ids: [] });
    const workTab = [...root.querySelectorAll<HTMLButtonElement>(".buf-tab")].find((b) => b.textContent === "work")!;
    workTab.click();
    await new Promise((r) => setTimeout(r, 30));
    expect(savedBeforeSwitch).toContain('{"flushed":true}');

    app.destroy();
  });

  it("M2 Vault & SEC-03: init Vault, lock block, format unlocked Tier 2 strictly in WASM (zero /v1/local/format), wipe on visibilitychange hidden, and two-step Trash confirm", async () => {
    const fsMod = (await import(/* @vite-ignore */ "node:" + "fs")) as { readFileSync(p: string): Uint8Array };
    const wasmBytes = fsMod.readFileSync("src/wasm/pkg/mynote_wasm_bg.wasm");
    const { bytesToB64, initDesktopWasmSync } = await import("../src/wasm/desktop");
    initDesktopWasmSync(new Uint8Array(wasmBytes));

    const { api, pushWs } = makeMockApi();
    const blk1 = "01J00000000000000000000001";
    let formatHttpCalls = 0;
    const patchPayloads: unknown[] = [];
    let storedHeader: { gen: number; blob_b64: string; updated_at_ms: number } | null = null;
    const recoveryPkB64 = bytesToB64(new Uint8Array(32).fill(7));
    const preparedNonces = new Map<string, string>();
    let committedNonce: string | null = null;
    const lockedState = new Map<string, BlockDto>();
    const validBlock: BlockDto = {
      id: blk1,
      buffer_id: "01BUF000000000000000000001",
      position: "a5",
      lang: "json",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01J00000000000000000000011"],
      display_op_id: "01J00000000000000000000011",
      has_conflict: false,
      content: '{"a":1}',
      versions: [
        {
          op_id: "01J00000000000000000000011",
          hlc: "000000000001000-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01J00000000000000000000021",
          content: '{"a":1}',
        },
      ],
      updated_at_ms: 1000,
    };
    lockedState.set(blk1, validBlock);

    const origBootstrap = api.bootstrap.bind(api);
    api.bootstrap = async () => {
      const b = await origBootstrap();
      return {
        ...b,
        blocks: [validBlock, ...b.blocks],
        vault_header: storedHeader,
        recovery_pk_b64: recoveryPkB64,
      };
    };
    api.putVaultHeader = async (gen, blob_b64) => {
      storedHeader = { gen, blob_b64, updated_at_ms: Date.now() };
      return storedHeader;
    };
    api.lockBlock = async (id, input) => {
      const cur = lockedState.get(id)!;
      const locked: BlockDto = {
        ...cur,
        is_locked: true,
        public_hint: input.public_hint ?? null,
        head_op_ids: [input.op_id],
        display_op_id: input.op_id,
        content: null,
        versions: [
          {
            op_id: input.op_id,
            hlc: "000000000009000-00000-dev_mac0000000001",
            device_id: "dev_mac0000000001",
            actor: "human",
            is_display: true,
            is_locked: true,
            key_id: input.key_id,
            content: null,
            mnb1_b64: input.mnb1_b64,
            mnw1_b64: input.mnw1_b64,
          },
        ],
      };
      lockedState.set(id, locked);
      return locked;
    };
    const origListBlocks = api.listBlocks.bind(api);
    api.listBlocks = async (bufId) => [lockedState.get(blk1)!, ...(await origListBlocks(bufId))];
    const origPatch = api.patchBlock.bind(api);
    api.patchBlock = async (id, input, opts) => {
      patchPayloads.push(input);
      const locked = lockedState.get(id);
      if (locked && input.mnb1_b64 && input.op_id && input.key_id) {
        const next: BlockDto = {
          ...locked,
          head_op_ids: [input.op_id],
          display_op_id: input.op_id,
          content: null,
          versions: [
            {
              ...locked.versions[0],
              op_id: input.op_id,
              key_id: input.key_id,
              mnb1_b64: input.mnb1_b64,
            },
          ],
        };
        lockedState.set(id, next);
        return next;
      }
      return origPatch(id, input, opts);
    };
    api.formatSnippet = async (input) => {
      formatHttpCalls++;
      return { formatted: input.content };
    };
    api.listBlockedOps = async () => [];
    api.prepareTrashAction = async (input) => {
      const nonce = `nonce_${input.action}_123`;
      preparedNonces.set(nonce, input.action);
      return {
        confirm_nonce: nonce,
        expires_in_ms: 60_000,
        summary: {
          action: input.action,
          block_count: input.block_ids?.length ?? 1,
          key_count: 1,
          grace_ms: input.grace_ms ?? 86_400_000,
          earliest_not_before_ms: Date.now() + 86_400_000,
        },
      };
    };
    api.commitTrashAction = async (input) => {
      committedNonce = input.confirm_nonce;
      return { ok: true };
    };

    const app = new MyNoteApp(root, api);
    await app.start();
    void pushWs;

    // 1. Setup Vault via modal
    const vaultBtn = root.querySelector<HTMLButtonElement>('[data-testid="vault-btn"]')!;
    expect(vaultBtn.textContent).toBe("Setup Vault");
    vaultBtn.click();
    const p1 = root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-input"]')!;
    const p2 = root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-confirm"]')!;
    p1.value = "correct horse battery staple";
    p2.value = "correct horse battery staple";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 150));
    expect(app.isVaultUnlocked()).toBe(true);
    expect(storedHeader).not.toBeNull();

    // 2. Lock block into Tier 2 Vault
    const card1 = root.querySelector<HTMLElement>(`[data-block-id="${blk1}"]`)!;
    const lockBtn = [...card1.querySelectorAll("button")].find((b) => b.textContent === "🔒 Lock")!;
    lockBtn.click();
    const hintInput = root.querySelector<HTMLInputElement>('[data-testid="lock-hint-input"]')!;
    hintInput.value = "API JSON secret";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 50));
    expect(app.stream.getBlocks().find((b) => b.id === blk1)?.is_locked).toBe(true);

    // 3. SEC-03: Format unlocked Tier 2 JSON block -> ZERO /v1/local/format HTTP calls, formatted in WASM, ciphertext-only PATCH!
    const card1Locked = root.querySelector<HTMLElement>(`[data-block-id="${blk1}"]`)!;
    const fmtBtn = [...card1Locked.querySelectorAll("button")].find((b) => b.textContent === "Format")!;
    fmtBtn.click();
    await new Promise((r) => setTimeout(r, 50));
    expect(formatHttpCalls).toBe(0);
    expect(app.stream.getBlockDraftContent(blk1)).toBe('{\n  "a": 1\n}');
    expect(JSON.stringify(patchPayloads)).not.toContain('"a": 1');
    expect(JSON.stringify(patchPayloads)).toContain("mnb1_b64");

    // 4. SEC-03: Trigger visibilitychange -> hidden => Vault immediately zeroizes & scrubs plaintext from DOM!
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    document.dispatchEvent(new Event("visibilitychange"));
    expect(app.isVaultUnlocked()).toBe(false);
    expect(root.textContent).not.toContain('"a": 1');
    expect(root.querySelector(`[data-block-id="${blk1}"] .locked-card`)).not.toBeNull();
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });

    // 5. Unlock Vault again -> plaintext restored in RAM from MNB1 + MNW1!
    vaultBtn.click();
    const unlockInput = root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-input"]')!;
    unlockInput.value = "correct horse battery staple";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 150));
    expect(app.isVaultUnlocked()).toBe(true);
    expect(app.stream.getBlockDraftContent(blk1)).toBe('{\n  "a": 1\n}');

    // 6. Trash two-step confirmation modal (prepare -> confirm -> commit with confirm_nonce)
    const card2 = root.querySelector<HTMLElement>('[data-block-id="01BLK000000000000000000002"]')!;
    const trashBtn = [...card2.querySelectorAll("button")].find((b) => b.textContent === "Trash")!;
    trashBtn.click();
    await new Promise((r) => setTimeout(r, 30));
    const openTrash = [...root.querySelectorAll("button")].find((b) => b.textContent?.startsWith("Trash ("))!;
    openTrash.click();
    await new Promise((r) => setTimeout(r, 30));
    const expediteBtn = [...root.querySelectorAll<HTMLButtonElement>(".trash-item button")].find(
      (b) => b.textContent === "Expedite",
    )!;
    expediteBtn.click();
    await new Promise((r) => setTimeout(r, 30));
    const commitBtn = root.querySelector<HTMLButtonElement>('[data-testid="trash-confirm-commit-btn"]')!;
    expect(commitBtn).not.toBeNull();
    commitBtn.click();
    await new Promise((r) => setTimeout(r, 30));
    expect(committedNonce).toBe("nonce_expedite_123");

    app.destroy();
  });

  it("PR #38 regressions: C4 mid-PATCH Vault lock never queues empty draft, H18 mid-format lock never leaks plaintext, H17 concurrent Tier 1 leaf fetch, and Shift+L lock shortcut", async () => {
    const fsMod = (await import(/* @vite-ignore */ "node:" + "fs")) as { readFileSync(p: string): Uint8Array };
    const wasmBytes = fsMod.readFileSync("src/wasm/pkg/mynote_wasm_bg.wasm");
    const { bytesToB64, initDesktopWasmSync } = await import("../src/wasm/desktop");
    initDesktopWasmSync(new Uint8Array(wasmBytes));

    const { api } = makeMockApi();
    const blk1 = "01JREG00000000000000000001";
    let storedHeader: { gen: number; blob_b64: string; updated_at_ms: number } | null = null;
    const recoveryPkB64 = bytesToB64(new Uint8Array(32).fill(9));
    let releasePatch!: () => void;
    let holdNextPatch = false;
    let patchCount = 0;
    const lockedMap = new Map<string, BlockDto>();

    const initialBlk: BlockDto = {
      id: blk1,
      buffer_id: "01BUF000000000000000000001",
      position: "a1",
      lang: "json",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01JREG00000000000000000011"],
      display_op_id: "01JREG00000000000000000011",
      has_conflict: false,
      content: '{"secret":"v1"}',
      versions: [
        {
          op_id: "01JREG00000000000000000011",
          hlc: "000000000001000-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01JREG00000000000000000021",
          content: '{"secret":"v1"}',
        },
      ],
      updated_at_ms: 1000,
    };
    lockedMap.set(blk1, initialBlk);

    const origBootstrap = api.bootstrap.bind(api);
    api.bootstrap = async () => {
      const b = await origBootstrap();
      return { ...b, blocks: [initialBlk, ...b.blocks], vault_header: storedHeader, recovery_pk_b64: recoveryPkB64 };
    };
    api.putVaultHeader = async (gen, blob_b64) => {
      storedHeader = { gen, blob_b64, updated_at_ms: Date.now() };
      return storedHeader;
    };
    api.listBlockedOps = async () => [];
    api.getTier1LeafPlaintext = async (blockId, opId) => ({
      block_id: blockId,
      op_id: opId,
      content: "CONCURRENT_TIER1_LEAF_SECRET",
    });
    api.lockBlock = async (id, input) => {
      const cur = lockedMap.get(id)!;
      const locked: BlockDto = {
        ...cur,
        is_locked: true,
        has_unlocked_concurrent_version: true,
        has_conflict: true,
        public_hint: input.public_hint ?? null,
        head_op_ids: [input.op_id, "01JREG00000000000000000099"],
        display_op_id: input.op_id,
        content: null,
        versions: [
          {
            op_id: input.op_id,
            hlc: "000000000009000-00000-dev_mac0000000001",
            device_id: "dev_mac0000000001",
            actor: "human",
            is_display: true,
            is_locked: true,
            key_id: input.key_id,
            content: null,
            mnb1_b64: input.mnb1_b64,
            mnw1_b64: input.mnw1_b64,
          },
          {
            op_id: "01JREG00000000000000000099",
            hlc: "000000000008000-00000-dev_other000001",
            device_id: "dev_other000001",
            actor: "human",
            is_display: false,
            is_locked: false,
            key_id: "01JREG00000000000000000021",
            content: null,
          },
        ],
      };
      lockedMap.set(id, locked);
      return locked;
    };
    const origPatch = api.patchBlock.bind(api);
    api.patchBlock = async (id, input, opts) => {
      patchCount++;
      if (holdNextPatch) {
        holdNextPatch = false;
        await new Promise<void>((res) => {
          releasePatch = res;
        });
      }
      const cur = lockedMap.get(id);
      if (cur && input.mnb1_b64 && input.op_id && input.key_id) {
        const next: BlockDto = {
          ...cur,
          has_conflict: false,
          head_op_ids: [input.op_id],
          display_op_id: input.op_id,
          versions: [
            {
              ...cur.versions[0],
              op_id: input.op_id,
              key_id: input.key_id,
              mnb1_b64: input.mnb1_b64,
            },
          ],
        };
        lockedMap.set(id, next);
        return next;
      }
      return origPatch(id, input, opts);
    };

    const app = new MyNoteApp(root, api);
    await app.start();

    // 1. Setup Vault
    root.querySelector<HTMLButtonElement>('[data-testid="vault-btn"]')!.click();
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-input"]')!.value = "regression-vault-pass";
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-confirm"]')!.value = "regression-vault-pass";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 150));
    expect(app.isVaultUnlocked()).toBe(true);

    // 2. Cmd/Ctrl+Shift+L on active Tier 1 block opens Lock Block modal (NOT lang selector!)
    app.stream.focusBlock(blk1, 0);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "L", ctrlKey: true, shiftKey: true, cancelable: true }));
    expect(root.querySelector('[data-testid="lock-hint-input"]')).not.toBeNull();
    root.querySelector<HTMLInputElement>('[data-testid="lock-hint-input"]')!.value = "C4 Hint";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 60));

    // H17: Unlock Vault again -> concurrent Tier 1 leaf plaintext is fetched on demand into RAM, then scrubbed on lock!
    app.lockVaultNow({ skipFlush: true, silent: true });
    expect(root.textContent).not.toContain("CONCURRENT_TIER1_LEAF_SECRET");
    root.querySelector<HTMLButtonElement>('[data-testid="vault-btn"]')!.click();
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-input"]')!.value = "regression-vault-pass";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 160));
    expect(root.textContent).toContain("CONCURRENT_TIER1_LEAF_SECRET");

    // 3. C4: Edit unlocked Tier 2 block, start PATCH, immediately lock Vault while PATCH is in flight!
    // When PATCH resolves after lock, dirty map MUST stay empty (NEVER store "" over the saved content!).
    const mounted = (app.stream as unknown as { mounted: Map<string, { view: import("@codemirror/view").EditorView }> }).mounted.get(blk1)!;
    mounted.view.dispatch({ changes: { from: 0, to: mounted.view.state.doc.length, insert: '{"secret":"v2-saved"}' } });
    holdNextPatch = true;
    const inflight = app.stream.flushDirtyBlock(blk1, { fastSync: true, isMerge: true });
    // Lock Vault while PATCH is still awaiting!
    app.lockVaultNow({ skipFlush: true, silent: true });
    releasePatch();
    await inflight;
    await new Promise((r) => setTimeout(r, 30));

    expect(app.stream.hasDirtyBlocks()).toBe(false);
    const patchesAfterLock = patchCount;
    // Re-unlock Vault -> MUST restore '{"secret":"v2-saved"}' and NOT trigger any empty-string PATCH!
    root.querySelector<HTMLButtonElement>('[data-testid="vault-btn"]')!.click();
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-input"]')!.value = "regression-vault-pass";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 160));
    expect(app.stream.getBlockDraftContent(blk1)).toBe('{"secret":"v2-saved"}');
    expect(patchCount).toBe(patchesAfterLock);

    // 4. H18: If page becomes hidden BEFORE unlock resolves, Vault MUST stay locked with zero plaintext in DOM!
    app.lockVaultNow({ skipFlush: true, silent: true });
    root.querySelector<HTMLButtonElement>('[data-testid="vault-btn"]')!.click();
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-input"]')!.value = "regression-vault-pass";
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 160));
    expect(app.isVaultUnlocked()).toBe(false);
    expect(root.textContent).not.toContain("v2-saved");
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });

    app.destroy();
  });

  it("M3 Desktop Markdown dual-mode: Source/Preview/Split, Cmd/Ctrl+E toggle, interactive task checkbox atomic patch, Copy Rich Dual-Format, and lang switch reset", async () => {
    const { api } = makeMockApi();
    const mdBlkId = "01M3MD00000000000000000001";
    const mdInitial = "# Sprint Tasks\n\n- [ ] write docs\n- [x] ship core\n\n![beacon](https://evil.example/a.png)\n";
    const mdBlock: BlockDto = {
      id: mdBlkId,
      buffer_id: "01BUF000000000000000000001",
      position: "a0",
      lang: "markdown",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01M3OP_MD_1"],
      display_op_id: "01M3OP_MD_1",
      has_conflict: false,
      content: mdInitial,
      versions: [
        {
          op_id: "01M3OP_MD_1",
          hlc: "000000000001000-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01M3KEY_MD_1",
          content: mdInitial,
        },
      ],
      updated_at_ms: 1000,
    };

    const patchCalls: Array<{ id: string; content?: string; expected_heads?: string[]; lang?: string }> = [];
    const origBootstrap = api.bootstrap.bind(api);
    api.bootstrap = async () => {
      const b = await origBootstrap();
      return { ...b, blocks: [mdBlock] };
    };
    api.listBlocks = async () => [mdBlock];
    api.patchBlock = async (id, input) => {
      patchCalls.push({ id, content: input.content, expected_heads: input.expected_heads, lang: input.lang });
      if (input.content !== undefined) {
        mdBlock.content = input.content;
        mdBlock.head_op_ids = [`01M3OP_MD_${patchCalls.length + 1}`];
        mdBlock.display_op_id = mdBlock.head_op_ids[0];
        mdBlock.versions[0].op_id = mdBlock.head_op_ids[0];
        mdBlock.versions[0].content = input.content;
      }
      if (input.lang !== undefined) {
        mdBlock.lang = input.lang;
      }
      return { ...mdBlock, head_op_ids: [...mdBlock.head_op_ids], versions: [{ ...mdBlock.versions[0] }] };
    };

    const clipboardWrite = vi.fn().mockResolvedValue(undefined);
    const clipboardWriteText = vi.fn().mockResolvedValue(undefined);
    class FakeClipboardItem {
      constructor(public readonly items: Record<string, Blob>) {}
    }
    vi.stubGlobal("ClipboardItem", FakeClipboardItem);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { write: clipboardWrite, writeText: clipboardWriteText },
    });

    const app = new MyNoteApp(root, api);
    await app.start();

    const card = root.querySelector<HTMLElement>(`[data-block-id="${mdBlkId}"]`)!;
    // Default mode is source with CM6 mounted
    expect(app.stream.getBlockViewMode(mdBlkId)).toBe("source");
    expect(card.querySelector(".cm-editor")).not.toBeNull();
    expect(card.querySelector(`[data-testid="mode-source-${mdBlkId}"]`)?.getAttribute("aria-pressed")).toBe("true");

    // Switch to Preview via header button -> unmounts CM6, renders .md-preview, shows Copy Rich, blocks external img
    card.querySelector<HTMLButtonElement>(`[data-testid="mode-preview-${mdBlkId}"]`)!.click();
    expect(app.stream.getBlockViewMode(mdBlkId)).toBe("preview");
    expect(card.querySelector(".cm-editor")).toBeNull();
    expect(card.querySelector(".block-preview-host .md-preview h1")?.textContent).toBe("Sprint Tasks");
    expect(card.querySelectorAll(".block-preview-host img").length).toBe(0);
    expect(card.querySelector(".block-preview-host .md-blocked-img")).not.toBeNull();

    // Interactive task checkbox click atomically writes updated Markdown via patchBlock with expected_heads
    const boxes = card.querySelectorAll<HTMLInputElement>('.block-preview-host input[type="checkbox"]');
    expect(boxes.length).toBe(2);
    expect(boxes[0].disabled).toBe(false);
    boxes[0].checked = true;
    boxes[0].dispatchEvent(new Event("change"));
    await new Promise((r) => setTimeout(r, 30));
    expect(patchCalls.length).toBe(1);
    expect(patchCalls[0].expected_heads).toEqual(["01M3OP_MD_1"]);
    expect(patchCalls[0].content).toContain("- [x] write docs");
    expect(patchCalls[0].content).toContain("- [x] ship core");

    // Copy Rich invokes Dual-Format ClipboardItem (text/html + text/plain)
    const copyRichBtn = card.querySelector<HTMLButtonElement>(`[data-testid="copy-rich-${mdBlkId}"]`)!;
    expect(copyRichBtn).not.toBeNull();
    copyRichBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(clipboardWrite).toHaveBeenCalledTimes(1);
    const copiedItem = (clipboardWrite.mock.calls[0][0] as FakeClipboardItem[])[0];
    expect(Object.keys(copiedItem.items)).toEqual(["text/html", "text/plain"]);

    // Cmd/Ctrl+E toggles Preview -> Source -> Preview
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "e", ctrlKey: true, cancelable: true }));
    expect(app.stream.getBlockViewMode(mdBlkId)).toBe("source");
    expect(card.querySelector(".cm-editor")).not.toBeNull();
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "e", ctrlKey: true, cancelable: true }));
    expect(app.stream.getBlockViewMode(mdBlkId)).toBe("preview");
    expect(card.querySelector(".cm-editor")).toBeNull();

    // Split mode mounts BOTH CM6 and live .md-preview, debouncing edits into preview
    card.querySelector<HTMLButtonElement>(`[data-testid="mode-split-${mdBlkId}"]`)!.click();
    expect(app.stream.getBlockViewMode(mdBlkId)).toBe("split");
    expect(card.querySelector(".block-split-body")).not.toBeNull();
    expect(card.querySelector(".cm-editor")).not.toBeNull();
    expect(card.querySelector(".block-preview-host .md-preview")).not.toBeNull();

    const mounted = (app.stream as unknown as { mounted: Map<string, { view: import("@codemirror/view").EditorView }> }).mounted.get(mdBlkId)!;
    mounted.view.dispatch({ changes: { from: 0, to: mounted.view.state.doc.length, insert: "## Live Split Updated" } });
    await new Promise((r) => setTimeout(r, 200));
    expect(card.querySelector(".block-preview-host .md-preview h2")?.textContent).toBe("Live Split Updated");

    // Switching language away from markdown resets cleanly to source & mounts CM6
    const langSel = card.querySelector<HTMLSelectElement>(".lang-select")!;
    langSel.value = "yaml";
    langSel.dispatchEvent(new Event("change"));
    await new Promise((r) => setTimeout(r, 30));
    expect(app.stream.getBlockViewMode(mdBlkId)).toBe("source");
    expect(card.querySelector(".block-split-body")).toBeNull();
    expect(card.querySelector(".block-preview-host .md-preview")).toBeNull();
    expect(card.querySelector(".cm-editor")).not.toBeNull();

    vi.unstubAllGlobals();
    app.destroy();
  });

  it("M3 Desktop Mermaid Split/Preview lazy Pele rendering, last-valid-frame preservation, and Tier 1 formatSnippet block_id forwarding", async () => {
    const { api } = makeMockApi();
    const mmdId = "01M3MMD0000000000000000001";
    const mmdBlock: BlockDto = {
      id: mmdId,
      buffer_id: "01BUF000000000000000000001",
      position: "a0",
      lang: "mermaid",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01M3OP_MMD_1"],
      display_op_id: "01M3OP_MMD_1",
      has_conflict: false,
      content: "flowchart LR\n  A[Alpha] --> B[Beta]",
      versions: [
        {
          op_id: "01M3OP_MMD_1",
          hlc: "000000000001000-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01M3KEY_MMD_1",
          content: "flowchart LR\n  A[Alpha] --> B[Beta]",
        },
      ],
      updated_at_ms: 1000,
    };

    const formatInputs: Array<{ content: string; lang: string; block_id?: string }> = [];
    const origBootstrap = api.bootstrap.bind(api);
    api.bootstrap = async () => {
      const b = await origBootstrap();
      return { ...b, blocks: [mmdBlock, b.blocks[0]] };
    };
    api.formatSnippet = async (input) => {
      formatInputs.push(input);
      return { formatted: input.content };
    };

    const app = new MyNoteApp(root, api);
    await app.start();

    // Format unlocked Tier 1 JSON block -> forwards block_id to /v1/local/format
    const jsonCard = root.querySelector<HTMLElement>('[data-block-id="01BLK000000000000000000001"]')!;
    const fmtBtn = [...jsonCard.querySelectorAll("button")].find((b) => b.textContent === "Format")!;
    fmtBtn.click();
    await new Promise((r) => setTimeout(r, 30));
    expect(formatInputs.length).toBe(1);
    expect(formatInputs[0].block_id).toBe("01BLK000000000000000000001");

    // Mermaid Split mode: lazy Pele renders pure SVG with zero inline style
    const card = root.querySelector<HTMLElement>(`[data-block-id="${mmdId}"]`)!;
    card.querySelector<HTMLButtonElement>(`[data-testid="mode-split-${mmdId}"]`)!.click();
    await new Promise((r) => setTimeout(r, 80));

    const svgBefore = card.querySelector(".diagram-viewport svg");
    expect(svgBefore).not.toBeNull();
    expect(svgBefore?.getAttribute("style")).toBeNull();
    expect(card.querySelector(".diagram-viewport")?.textContent).toContain("Alpha");

    // Introduce invalid syntax mid-edit -> preserves last valid SVG and displays syntax hint
    const mounted = (app.stream as unknown as { mounted: Map<string, { view: import("@codemirror/view").EditorView }> }).mounted.get(mmdId)!;
    mounted.view.dispatch({
      changes: { from: 0, to: mounted.view.state.doc.length, insert: "flowchart LR\n  A --> --> ??? BROKEN %%%" },
    });
    await new Promise((r) => setTimeout(r, 240));

    const hint = card.querySelector<HTMLElement>(".diagram-syntax-hint")!;
    expect(hint.hidden).toBe(false);
    expect(hint.textContent).toContain("Diagram syntax error");
    expect(card.querySelector(".diagram-viewport svg")).toBe(svgBefore);
    expect(card.querySelector(".diagram-viewport")?.textContent).toContain("Alpha");

    app.destroy();
  });

  it("M3 Desktop History Drawer & SEC-03: agent badge, shredded badge, line diff, revert, undo actor batch, and Vault lock wiping Preview & History DOM", async () => {
    const fsMod = (await import(/* @vite-ignore */ "node:" + "fs")) as { readFileSync(p: string): Uint8Array };
    const wasmBytes = fsMod.readFileSync("src/wasm/pkg/mynote_wasm_bg.wasm");
    const { bytesToB64, initDesktopWasmSync } = await import("../src/wasm/desktop");
    initDesktopWasmSync(new Uint8Array(wasmBytes));

    const { api } = makeMockApi();
    const t1Id = "01BLK000000000000000000001";
    const t2Id = "01JH5T20000000000000000001";
    let storedHeader: { gen: number; blob_b64: string; updated_at_ms: number } | null = null;
    const recoveryPkB64 = bytesToB64(new Uint8Array(32).fill(5));

    const t2Block: BlockDto = {
      id: t2Id,
      buffer_id: "01BUF000000000000000000001",
      position: "a5",
      lang: "markdown",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01JH5T20000000000000000011"],
      display_op_id: "01JH5T20000000000000000011",
      has_conflict: false,
      content: "# Secret Note\n\nTOP_SECRET_MARKDOWN_TOKEN",
      versions: [
        {
          op_id: "01JH5T20000000000000000011",
          hlc: "000000000001000-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01JH5T20000000000000000021",
          content: "# Secret Note\n\nTOP_SECRET_MARKDOWN_TOKEN",
        },
      ],
      updated_at_ms: 1000,
    };

    const t1History: BlockHistoryEntryDto[] = [
      {
        op_id: "01OP_AGENT_2",
        op_type: "UPDATE",
        hlc: "000000000003000-00000-dev_mac0000000001",
        device_id: "dev_mac0000000001",
        actor: "agent:claude-code",
        content_available: true,
        has_content: true,
        is_locked: false,
        shredded: false,
        key_id: "01KEY_1",
        created_at_ms: 1700000003000,
      },
      {
        op_id: "01OP_HUMAN_1",
        op_type: "UPDATE",
        hlc: "000000000002000-00000-dev_mac0000000001",
        device_id: "dev_mac0000000001",
        actor: "human",
        content_available: true,
        has_content: true,
        is_locked: false,
        shredded: false,
        key_id: "01KEY_1",
        created_at_ms: 1700000002000,
      },
      {
        op_id: "01OP_SHRED_0",
        op_type: "CREATE",
        hlc: "000000000001000-00000-dev_mac0000000001",
        device_id: "dev_mac0000000001",
        actor: "human",
        content_available: false,
        has_content: true,
        is_locked: false,
        shredded: true,
        key_id: "01KEY_OLD",
        created_at_ms: 1700000001000,
      },
    ];

    const revertCalls: Array<{ id: string; input: Record<string, unknown> }> = [];
    let lockedT2Snapshot: BlockDto = t2Block;
    let t2HistContent: BlockHistoryContentDto | null = null;

    const origBootstrap = api.bootstrap.bind(api);
    api.bootstrap = async () => {
      const b = await origBootstrap();
      b.blocks[0].content = "line1\nagent-changed";
      b.blocks[0].head_op_ids = ["01OP_AGENT_2"];
      b.blocks[0].display_op_id = "01OP_AGENT_2";
      return {
        ...b,
        blocks: [b.blocks[0], lockedT2Snapshot],
        vault_header: storedHeader,
        recovery_pk_b64: recoveryPkB64,
      };
    };
    api.putVaultHeader = async (gen, blob_b64) => {
      storedHeader = { gen, blob_b64, updated_at_ms: Date.now() };
      return storedHeader;
    };
    api.listBlockedOps = async () => [];
    api.lockBlock = async (_id, input) => {
      lockedT2Snapshot = {
        ...t2Block,
        is_locked: true,
        public_hint: input.public_hint ?? null,
        head_op_ids: [input.op_id],
        display_op_id: input.op_id,
        content: null,
        versions: [
          {
            op_id: input.op_id,
            hlc: "000000000009000-00000-dev_mac0000000001",
            device_id: "dev_mac0000000001",
            actor: "human",
            is_display: true,
            is_locked: true,
            key_id: input.key_id,
            content: null,
            mnb1_b64: input.mnb1_b64,
            mnw1_b64: input.mnw1_b64,
          },
        ],
      };
      t2HistContent = {
        block_id: t2Id,
        op_id: input.op_id,
        op_type: "LOCK",
        hlc: "000000000009000-00000-dev_mac0000000001",
        device_id: "dev_mac0000000001",
        actor: "human",
        created_at_ms: 1700000009000,
        is_locked: true,
        key_id: input.key_id,
        lang: "markdown",
        content: null,
        mnb1_b64: input.mnb1_b64,
        mnw1_b64: input.mnw1_b64,
      };
      return lockedT2Snapshot;
    };
    api.getBlockHistory = async (id) => {
      if (id === t2Id && t2HistContent) {
        return [
          {
            op_id: t2HistContent.op_id,
            op_type: "LOCK",
            hlc: t2HistContent.hlc,
            device_id: t2HistContent.device_id,
            actor: "human",
            content_available: true,
            has_content: true,
            is_locked: true,
            shredded: false,
            key_id: t2HistContent.key_id,
            created_at_ms: t2HistContent.created_at_ms,
          },
        ];
      }
      return t1History;
    };
    api.getBlockHistoryOp = async (id, opId) => {
      if (id === t2Id && t2HistContent) {
        return t2HistContent;
      }
      return {
        block_id: id,
        op_id: opId,
        op_type: "UPDATE",
        hlc: "000000000002000-00000-dev_mac0000000001",
        device_id: "dev_mac0000000001",
        actor: "human",
        created_at_ms: 1700000002000,
        is_locked: false,
        key_id: "01KEY_1",
        lang: "json",
        content: "line1\nhuman-original",
        mnb1_b64: null,
        mnw1_b64: null,
      };
    };
    api.revertBlock = async (id, input) => {
      revertCalls.push({ id, input: { ...input } });
      const cur = app.stream.getBlocks().find((b) => b.id === id)!;
      return {
        ...cur,
        head_op_ids: [`01OP_REVERT_${revertCalls.length}`],
        display_op_id: `01OP_REVERT_${revertCalls.length}`,
        content: "line1\nhuman-original",
        versions: [
          {
            ...cur.versions[0],
            op_id: `01OP_REVERT_${revertCalls.length}`,
            actor: "human",
            content: "line1\nhuman-original",
          },
        ],
      };
    };

    const app = new MyNoteApp(root, api);
    await app.start();

    // 1. Open History Drawer on Tier 1 block
    root.querySelector<HTMLButtonElement>(`[data-testid="history-btn-${t1Id}"]`)!.click();
    await new Promise((r) => setTimeout(r, 30));

    const drawer = root.querySelector<HTMLElement>('[data-testid="history-drawer"]')!;
    expect(drawer.classList.contains("hidden")).toBe(false);
    expect(drawer.textContent).toContain("agent:claude-code");
    expect(drawer.querySelector('[data-testid="history-undo-actor-btn"]')?.textContent).toBe("Undo agent:claude-code batch");
    expect(drawer.querySelector('[data-testid="history-shredded-badge"]')?.textContent).toBe("Shredded / Unavailable");
    expect(drawer.querySelector<HTMLButtonElement>('[data-testid="history-select-01OP_SHRED_0"]')?.disabled).toBe(true);

    // 2. Inspect prior human version -> line diff renders - human-original and + agent-changed
    drawer.querySelector<HTMLButtonElement>('[data-testid="history-select-01OP_HUMAN_1"]')!.click();
    await new Promise((r) => setTimeout(r, 30));
    const diffView = drawer.querySelector<HTMLElement>('[data-testid="history-diff-view"]')!;
    expect(diffView).not.toBeNull();
    expect(diffView.querySelector(".diff-del")?.textContent).toContain("human-original");
    expect(diffView.querySelector(".diff-add")?.textContent).toContain("agent-changed");

    // 3. One-click Revert calls revertBlock({ to_op_id, expected_heads }) and updates block
    drawer.querySelector<HTMLButtonElement>('[data-testid="history-revert-btn"]')!.click();
    await new Promise((r) => setTimeout(r, 30));
    expect(revertCalls.length).toBe(1);
    expect(revertCalls[0].input.to_op_id).toBe("01OP_HUMAN_1");
    expect(revertCalls[0].input.expected_heads).toEqual(["01OP_AGENT_2"]);
    expect(app.stream.getBlockDraftContent(t1Id)).toBe("line1\nhuman-original");

    // 4. Undo actor batch button calls revertBlock({ undo_actor: "agent:claude-code", expected_heads })
    drawer.querySelector<HTMLButtonElement>('[data-testid="history-undo-actor-btn"]')!.click();
    await new Promise((r) => setTimeout(r, 30));
    expect(revertCalls.length).toBe(2);
    expect(revertCalls[1].input.undo_actor).toBe("agent:claude-code");

    // 5. SEC-03: Setup Vault, lock Markdown block into Tier 2, open Preview AND open Tier 2 History Drawer, then lockVaultNow()
    root.querySelector<HTMLButtonElement>('[data-testid="vault-btn"]')!.click();
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-input"]')!.value = "m3-vault-passphrase";
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-confirm"]')!.value = "m3-vault-passphrase";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 150));
    expect(app.isVaultUnlocked()).toBe(true);

    const t2Card = root.querySelector<HTMLElement>(`[data-block-id="${t2Id}"]`)!;
    const lockBtn = [...t2Card.querySelectorAll("button")].find((b) => b.textContent === "🔒 Lock")!;
    lockBtn.click();
    root.querySelector<HTMLInputElement>('[data-testid="lock-hint-input"]')!.value = "Secret MD";
    root.querySelector<HTMLFormElement>(".dialog-form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 60));

    // Switch locked Markdown block to Preview mode -> renders secret heading in .block-preview-host
    const t2LockedCard = root.querySelector<HTMLElement>(`[data-block-id="${t2Id}"]`)!;
    t2LockedCard.querySelector<HTMLButtonElement>(`[data-testid="mode-preview-${t2Id}"]`)!.click();
    expect(t2LockedCard.querySelector(".block-preview-host .md-preview")?.textContent).toContain("TOP_SECRET_MARKDOWN_TOKEN");

    // Open Tier 2 History Drawer & decrypt historical version strictly in browser WASM RAM
    t2LockedCard.querySelector<HTMLButtonElement>(`[data-testid="history-btn-${t2Id}"]`)!.click();
    await new Promise((r) => setTimeout(r, 40));
    const t2SelectBtn = drawer.querySelector<HTMLButtonElement>(`[data-testid="history-select-${t2HistContent!.op_id}"]`)!;
    t2SelectBtn.click();
    await new Promise((r) => setTimeout(r, 40));
    expect(drawer.classList.contains("hidden")).toBe(false);
    expect(drawer.textContent).toContain("TOP_SECRET_MARKDOWN_TOKEN");

    // Lock Vault -> MUST immediately wipe locked Preview DOM AND close & clear History Drawer!
    app.lockVaultNow();
    expect(app.isVaultUnlocked()).toBe(false);
    expect(drawer.classList.contains("hidden")).toBe(true);
    expect(drawer.textContent).not.toContain("TOP_SECRET_MARKDOWN_TOKEN");
    expect(root.textContent).not.toContain("TOP_SECRET_MARKDOWN_TOKEN");
    expect(root.querySelector(`[data-block-id="${t2Id}"] .block-preview-host`)).toBeNull();
    expect(root.querySelector(`[data-block-id="${t2Id}"] .locked-card`)).not.toBeNull();

    app.destroy();
  });

  it("M3 Mobile Read-Only PWA: Markdown & Mermaid default to Preview, toggle to Source, disabled checkboxes, external img blocked, and SEC-08 wipe on hide", async () => {
    const pwaRoot = document.createElement("div");
    pwaRoot.className = "pwa-shell";
    document.body.appendChild(pwaRoot);

    const pwa = new MobilePwaApp(pwaRoot);
    const internals = pwa as unknown as {
      creds: { device_id: string; device_token: string; sync_url: string; smks: Array<{ smk_kid: string; smk_b64: string }> };
      buffers: Array<{ id: string; name: string; position: string; state: string; updated_at_ms: number }>;
      blocks: Array<{
        id: string;
        buffer_id: string;
        position: string;
        lang: string;
        public_hint: string | null;
        state: string;
        is_locked: boolean;
        has_unlocked_concurrent_version: boolean;
        display_op_id: string | null;
        updated_at_ms: number;
        versions: Array<{
          op_id: string;
          hlc: string;
          device_id: string;
          actor: string;
          is_display: boolean;
          is_locked: boolean;
          key_id: string | null;
          content: string | null;
          mnb1_b64: string | null;
          mnw1_b64: string | null;
          body_state: string;
        }>;
      }>;
      activeBufferId: string;
      vaultSession: { isLocked(): boolean; lockAndZeroize(): void; free(): void } | null;
      unlockedPlaintext: Map<string, Map<string, string>>;
      render(): void;
    };

    const mdId = "01PWA_MD_1";
    const mmdId = "01PWA_MMD_1";
    const lockedMdId = "01PWA_T2_MD_1";
    internals.creds = {
      device_id: "dev_iphone000001",
      device_token: "tok",
      sync_url: "https://sync.example.com",
      smks: [],
    };
    internals.buffers = [{ id: "01BUF1", name: "mobile", position: "a0", state: "active", updated_at_ms: 1000 }];
    internals.activeBufferId = "01BUF1";
    internals.blocks = [
      {
        id: mdId,
        buffer_id: "01BUF1",
        position: "a0",
        lang: "markdown",
        public_hint: null,
        state: "active",
        is_locked: false,
        has_unlocked_concurrent_version: false,
        display_op_id: "01OP_MD",
        updated_at_ms: 1000,
        versions: [
          {
            op_id: "01OP_MD",
            hlc: "000000000001000-00000-dev_mac",
            device_id: "dev_mac",
            actor: "human",
            is_display: true,
            is_locked: false,
            key_id: "01K1",
            content: "# Mobile Read\n\n- [ ] readonly task\n- [x] done task\n\n![track](https://evil.example/track.gif)\n",
            mnb1_b64: null,
            mnw1_b64: null,
            body_state: "ok",
          },
        ],
      },
      {
        id: mmdId,
        buffer_id: "01BUF1",
        position: "b0",
        lang: "mermaid",
        public_hint: null,
        state: "active",
        is_locked: false,
        has_unlocked_concurrent_version: false,
        display_op_id: "01OP_MMD",
        updated_at_ms: 1000,
        versions: [
          {
            op_id: "01OP_MMD",
            hlc: "000000000002000-00000-dev_mac",
            device_id: "dev_mac",
            actor: "human",
            is_display: true,
            is_locked: false,
            key_id: "01K2",
            content: "flowchart LR\n  Phone[iPhone] --> Safe[SVG]",
            mnb1_b64: null,
            mnw1_b64: null,
            body_state: "ok",
          },
        ],
      },
      {
        id: lockedMdId,
        buffer_id: "01BUF1",
        position: "c0",
        lang: "markdown",
        public_hint: "Vault MD",
        state: "active",
        is_locked: true,
        has_unlocked_concurrent_version: false,
        display_op_id: "01OP_T2",
        updated_at_ms: 1000,
        versions: [
          {
            op_id: "01OP_T2",
            hlc: "000000000003000-00000-dev_mac",
            device_id: "dev_mac",
            actor: "human",
            is_display: true,
            is_locked: true,
            key_id: "01K3",
            content: null,
            mnb1_b64: "AAA",
            mnw1_b64: "BBB",
            body_state: "locked",
          },
        ],
      },
    ];
    let fakeLocked = false;
    internals.vaultSession = {
      isLocked: () => fakeLocked,
      lockAndZeroize: () => {
        fakeLocked = true;
      },
      free: () => {},
    };
    internals.unlockedPlaintext.set(lockedMdId, new Map([["01OP_T2", "# Vault Secret\n\nPWA_TIER2_SECRET_BODY"]]));
    internals.render();
    await new Promise((r) => setTimeout(r, 80));

    // Markdown & Mermaid default to Preview mode
    const mdCard = pwaRoot.querySelector<HTMLElement>(`[data-block-id="${mdId}"]`)!;
    expect(mdCard.dataset.viewMode).toBe("preview");
    expect(mdCard.querySelector(".md-preview h1")?.textContent).toBe("Mobile Read");
    expect(mdCard.querySelectorAll("img").length).toBe(0);
    expect(mdCard.querySelectorAll("textarea, [contenteditable]").length).toBe(0);
    expect(mdCard.querySelector(`[data-testid="pwa-copy-rich-${mdId}"]`)).not.toBeNull();
    const pwaBoxes = Array.from(mdCard.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'));
    expect(pwaBoxes.length).toBe(2);
    expect(pwaBoxes.every((cb) => cb.disabled)).toBe(true);

    const mmdCard = pwaRoot.querySelector<HTMLElement>(`[data-block-id="${mmdId}"]`)!;
    expect(mmdCard.dataset.viewMode).toBe("preview");
    const pwaSvg = mmdCard.querySelector(".diagram-viewport svg");
    expect(pwaSvg).not.toBeNull();
    expect(pwaSvg?.getAttribute("style")).toBeNull();
    expect(mmdCard.querySelector(".diagram-viewport")?.textContent).toContain("iPhone");

    // Toggle Markdown block from Preview -> Source -> Preview
    const toggleBtn = mdCard.querySelector<HTMLButtonElement>(`[data-testid="pwa-toggle-mode-${mdId}"]`)!;
    expect(toggleBtn.textContent).toBe("Source");
    toggleBtn.click();
    const mdCardSource = pwaRoot.querySelector<HTMLElement>(`[data-block-id="${mdId}"]`)!;
    expect(mdCardSource.dataset.viewMode).toBe("source");
    expect(mdCardSource.querySelector(".ro-pre")?.textContent).toContain("# Mobile Read");
    expect(mdCardSource.querySelector<HTMLButtonElement>(`[data-testid="pwa-toggle-mode-${mdId}"]`)?.textContent).toBe("Preview");

    // SEC-08: Unlocked Tier 2 Markdown preview is wiped immediately on visibilitychange: hidden
    expect(pwaRoot.textContent).toContain("PWA_TIER2_SECRET_BODY");
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    document.dispatchEvent(new Event("visibilitychange"));
    expect(pwaRoot.textContent).not.toContain("PWA_TIER2_SECRET_BODY");
    expect(pwaRoot.querySelector(`[data-block-id="${lockedMdId}"] .ro-locked-body`)).not.toBeNull();
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });

    pwa.destroy();
    pwaRoot.remove();
  });
});
