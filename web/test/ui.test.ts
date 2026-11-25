import { describe, it, expect, beforeEach } from "vitest";
import { MyNoteApp } from "../src/app";
import type { LocalApiClient } from "../src/api";
import type { BlockDto, BootstrapResponse, BufferDto, LocalWsFrame, SyncStatusDto, TrashItemDto } from "../src/types";

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
        content: input.content,
        versions: [
          {
            op_id: `01OP00000000000000000000${seq}`,
            hlc: `00000000000${seq}00-00000-dev_mac0000000001`,
            device_id: "dev_mac0000000001",
            actor: "human",
            is_display: true,
            is_locked: false,
            key_id: "01KEYNEW",
            content: input.content,
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
});
