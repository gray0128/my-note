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
});
