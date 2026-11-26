import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { MyNoteApp } from "../src/app";
import { MobilePwaApp } from "../src/pwa/pwaApp";
import { bytesToB64 } from "../src/wasm/desktop";
import {
  getLocale,
  LOCALE_STORAGE_KEY,
  setLocale,
  subscribeLocale,
  toggleLocale,
} from "../src/i18n";
import {
  getResolvedTheme,
  getThemePreference,
  initTheme,
  setThemePreference,
  subscribeTheme,
  THEME_COLOR_DARK,
  THEME_COLOR_LIGHT,
  THEME_STORAGE_KEY,
} from "../src/theme";
import type { LocalApiClient } from "../src/api";
import type { BlockDto, BootstrapResponse, BufferDto, SyncStatusDto } from "../src/types";

const FORBIDDEN_EMOJIS = ["🔒", "🔓", "⚡", "⚠", "🖼"];

function createMemoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear() {
      map.clear();
    },
    getItem(key: string) {
      return map.has(key) ? map.get(key)! : null;
    },
    key(index: number) {
      return [...map.keys()][index] ?? null;
    },
    removeItem(key: string) {
      map.delete(key);
    },
    setItem(key: string, value: string) {
      map.set(key, String(value));
    },
  };
}

function ensureTestLocalStorage(): Storage {
  const existing = window.localStorage;
  if (
    existing &&
    typeof existing.getItem === "function" &&
    typeof existing.setItem === "function" &&
    typeof existing.removeItem === "function" &&
    typeof existing.clear === "function"
  ) {
    existing.clear();
    return existing;
  }
  const mem = createMemoryStorage();
  Object.defineProperty(window, "localStorage", { value: mem, configurable: true });
  Object.defineProperty(globalThis, "localStorage", { value: mem, configurable: true });
  return mem;
}

function installFakeMatchMedia(initialDark: boolean) {
  let darkMatches = initialDark;
  const listeners = new Set<() => void>();
  const mql = {
    media: "(prefers-color-scheme: dark)",
    get matches() {
      return darkMatches;
    },
    onchange: null,
    addEventListener: (_type: string, fn: () => void) => {
      listeners.add(fn);
    },
    removeEventListener: (_type: string, fn: () => void) => {
      listeners.delete(fn);
    },
    addListener: (fn: () => void) => {
      listeners.add(fn);
    },
    removeListener: (fn: () => void) => {
      listeners.delete(fn);
    },
    dispatchEvent: () => true,
  } as unknown as MediaQueryList;

  vi.stubGlobal(
    "matchMedia",
    vi.fn((query: string) => {
      if (query === "(prefers-color-scheme: dark)") return mql;
      return {
        media: query,
        matches: false,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => true,
      } as unknown as MediaQueryList;
    }),
  );

  return {
    setDark(next: boolean) {
      darkMatches = next;
      for (const fn of [...listeners]) fn();
    },
  };
}

function makeSimpleDesktopApi(vaultHeader: { gen: number; blob_b64: string; updated_at_ms: number } | null = null) {
  const buf: BufferDto = { id: "01BUF_THEME_1", name: "scratch", position: "a0", updated_at_ms: 1000 };
  const blocks: BlockDto[] = [
    {
      id: "01BLK_THEME_MD_1",
      buffer_id: buf.id,
      position: "a0",
      lang: "markdown",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01OP_T1"],
      display_op_id: "01OP_T1",
      has_conflict: false,
      content: "# Hello\n\n![img](https://evil.example/a.png)\n",
      versions: [
        {
          op_id: "01OP_T1",
          hlc: "000000000001000-00000-dev_mac0000000001",
          device_id: "dev_mac0000000001",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01KEY_T1",
          content: "# Hello\n\n![img](https://evil.example/a.png)\n",
        },
      ],
      updated_at_ms: 1000,
    },
    {
      id: "01BLK_THEME_CONFLICT_2",
      buffer_id: buf.id,
      position: "b0",
      lang: "text",
      is_locked: false,
      has_unlocked_concurrent_version: false,
      public_hint: null,
      head_op_ids: ["01OP_C1", "01OP_C2"],
      display_op_id: "01OP_C1",
      has_conflict: true,
      content: "alpha",
      versions: [
        {
          op_id: "01OP_C1",
          hlc: "000000000002000-00000-dev_a",
          device_id: "dev_a",
          actor: "human",
          is_display: true,
          is_locked: false,
          key_id: "01KEY_C",
          content: "alpha",
        },
        {
          op_id: "01OP_C2",
          hlc: "000000000001900-00000-dev_b",
          device_id: "dev_b",
          actor: "human",
          is_display: false,
          is_locked: false,
          key_id: "01KEY_C",
          content: "beta",
        },
      ],
      updated_at_ms: 2000,
    },
  ];
  let storedHeader = vaultHeader;
  const status: SyncStatusDto = {
    sync_state: "synced",
    epoch: "00000000-0000-4000-8000-000000000001",
    last_seq: 1,
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
        buffers: [buf],
        initial_buffer_id: buf.id,
        blocks: [...blocks],
        sync_status: { ...status },
        vault_header: storedHeader,
        recovery_pk_b64: bytesToB64(new Uint8Array(32).fill(7)),
        trash_count: 0,
        device_id: "dev_mac0000000001",
        last_hlc: null,
      };
    },
    async listBlocks() {
      return [...blocks];
    },
    async createBlock() {
      throw new Error("not used");
    },
    async patchBlock(id, input) {
      const cur = blocks.find((b) => b.id === id)!;
      return { ...cur, content: input.content ?? cur.content };
    },
    async resolveBlock(id) {
      return blocks.find((b) => b.id === id)!;
    },
    async deleteBlock() {
      return { in_trash: true, shred_state: "unscheduled", shred_not_before_ms: null };
    },
    async createBuffer(input) {
      return { id: `01BUF_${input.name}`, name: input.name, position: "z0", updated_at_ms: 2000 };
    },
    async renameBuffer(id, name) {
      return { id, name, position: "a0", updated_at_ms: 2000 };
    },
    async deleteBuffer(id) {
      return { id, name: "deleted", position: "a0", updated_at_ms: 2000 };
    },
    async listTrash() {
      return [];
    },
    async restoreTrash() {
      return blocks[0];
    },
    async formatSnippet(input) {
      return { formatted: input.content };
    },
    async syncNow() {
      return { ...status };
    },
    async putVaultHeader(gen, blob_b64) {
      storedHeader = { gen, blob_b64, updated_at_ms: Date.now() };
      return storedHeader;
    },
    async listBlockedOps() {
      return [];
    },
    connectWs() {
      return () => {};
    },
  };
  return { api };
}

describe("Theme controller, Bilingual i18n, CSP & Emoji Hygiene", () => {
  beforeEach(() => {
    ensureTestLocalStorage();
    document.head.innerHTML =
      '<meta name="color-scheme" content="light dark" /><meta name="theme-color" content="#171614" />';
    document.body.innerHTML = '<div id="app" class="app-shell"></div>';
    document.documentElement.dataset.theme = "auto";
    document.documentElement.lang = "en";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    window.localStorage?.clear?.();
  });

  it("manages 3-state theme persistence, meta/data-theme sync, OS change immunity, and cross-tab storage sync", () => {
    const mm = installFakeMatchMedia(false);
    const snap0 = initTheme();
    expect(snap0.preference).toBe("system");
    expect(snap0.resolved).toBe("light");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute("content")).toBe(
      "light dark",
    );
    expect(document.documentElement.dataset.theme).toBe("auto");
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute("content")).toBe(
      THEME_COLOR_LIGHT,
    );

    const seen: string[] = [];
    const unsub = subscribeTheme((s) => seen.push(`${s.preference}:${s.resolved}:${s.systemTheme}`));

    // Pin Dark
    setThemePreference("dark");
    expect(getThemePreference()).toBe("dark");
    expect(getResolvedTheme()).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute("content")).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute("content")).toBe(
      THEME_COLOR_DARK,
    );

    // OS switches to dark and back to light: stored "dark" override MUST NEVER be removed!
    mm.setDark(true);
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(getThemePreference()).toBe("dark");
    mm.setDark(false);
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(getThemePreference()).toBe("dark");
    expect(getResolvedTheme()).toBe("dark");

    // Pin Light
    setThemePreference("light");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute("content")).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute("content")).toBe(
      THEME_COLOR_LIGHT,
    );

    // Return to System -> removes localStorage key and restores "light dark" / "auto"
    setThemePreference("system");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute("content")).toBe(
      "light dark",
    );
    expect(document.documentElement.dataset.theme).toBe("auto");

    // OS changes to dark while in System -> resolved flips to dark and theme-color updates
    mm.setDark(true);
    expect(getResolvedTheme()).toBe("dark");
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute("content")).toBe(
      THEME_COLOR_DARK,
    );

    // Cross-tab storage sync
    localStorage.setItem(THEME_STORAGE_KEY, "light");
    window.dispatchEvent(
      new StorageEvent("storage", {
        key: THEME_STORAGE_KEY,
        newValue: "light",
      }),
    );
    expect(getThemePreference()).toBe("light");
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute("content")).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(seen.at(-1)).toBe("light:light:dark");

    unsub();
  });

  it("handles i18n locale persistence, toggleLocale, <html lang> sync, and cross-tab storage sync", () => {
    expect(getLocale()).toBe("en");
    const observed: string[] = [];
    const unsub = subscribeLocale((loc) => observed.push(loc));

    setLocale("zh-CN");
    expect(getLocale()).toBe("zh-CN");
    expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
    expect(document.documentElement.lang).toBe("zh-CN");

    toggleLocale();
    expect(getLocale()).toBe("en");
    expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("en");
    expect(document.documentElement.lang).toBe("en");

    // Cross-tab storage sync
    localStorage.setItem(LOCALE_STORAGE_KEY, "zh-CN");
    window.dispatchEvent(
      new StorageEvent("storage", {
        key: LOCALE_STORAGE_KEY,
        newValue: "zh-CN",
      }),
    );
    expect(getLocale()).toBe("zh-CN");
    expect(document.documentElement.lang).toBe("zh-CN");
    expect(observed).toEqual(["zh-CN", "en", "zh-CN"]);

    unsub();
  });

  it("Desktop: switches Theme & Language live in place without remounting CM6, losing unsaved drafts, or locking Vault RAM", async () => {
    const mm = installFakeMatchMedia(false);
    const fsMod = (await import(/* @vite-ignore */ "node:" + "fs")) as {
      readFileSync(p: string): Uint8Array;
    };
    const wasmBytes = fsMod.readFileSync("src/wasm/pkg/mynote_wasm_bg.wasm");
    const { initDesktopWasmSync } = await import("../src/wasm/desktop");
    initDesktopWasmSync(new Uint8Array(wasmBytes));

    const { api } = makeSimpleDesktopApi();
    const root = document.getElementById("app")!;
    const app = new MyNoteApp(root, api);
    await app.start();

    // Initialize & unlock Vault in WASM RAM
    root.querySelector<HTMLButtonElement>('[data-testid="vault-btn"]')!.click();
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-input"]')!.value =
      "theme-i18n-test-pass";
    root.querySelector<HTMLInputElement>('[data-testid="vault-passphrase-confirm"]')!.value =
      "theme-i18n-test-pass";
    root
      .querySelector<HTMLFormElement>(".dialog-form")!
      .dispatchEvent(new Event("submit", { cancelable: true }));
    await new Promise((r) => setTimeout(r, 150));
    expect(app.isVaultUnlocked()).toBe(true);

    // Type an unsaved draft into block 1 and capture the mounted .cm-editor DOM node
    const blkId = "01BLK_THEME_MD_1";
    const cardBefore = root.querySelector<HTMLElement>(`[data-block-id="${blkId}"]`)!;
    const cmEditorBefore = cardBefore.querySelector(".cm-editor")!;
    expect(cmEditorBefore).not.toBeNull();
    const mounted = (
      app.stream as unknown as {
        mounted: Map<string, { view: import("@codemirror/view").EditorView }>;
      }
    ).mounted.get(blkId)!;
    mounted.view.dispatch({
      changes: { from: 0, to: mounted.view.state.doc.length, insert: "# Unsaved Draft 123" },
    });

    // Switch Language to zh-CN via topbar switch
    root.querySelector<HTMLButtonElement>('[data-testid="lang-opt-zh-CN"]')!.click();
    expect(document.documentElement.lang).toBe("zh-CN");
    expect(root.querySelector('[data-testid="new-block-btn"]')?.textContent).toBe("新建块");
    expect(root.querySelector('[data-testid="find-btn"]')?.textContent).toBe("查找");
    expect(root.querySelector('[data-testid="trash-btn"]')?.textContent).toBe("回收站 (0)");
    expect(root.querySelector('[data-testid="theme-opt-system"]')?.textContent).toBe("跟随系统（浅色）");
    expect(root.querySelector('[data-testid="theme-opt-dark"]')?.textContent).toBe("深色");
    expect(cardBefore.querySelector(`[data-testid="mode-source-${blkId}"]`)?.textContent).toBe("源码");

    // Verify ZERO CM6 remount, draft intact, Vault still unlocked!
    expect(cardBefore.querySelector(".cm-editor")).toBe(cmEditorBefore);
    expect(app.stream.getBlockDraftContent(blkId)).toBe("# Unsaved Draft 123");
    expect(app.isVaultUnlocked()).toBe(true);

    // Switch OS preference to dark -> System menu option updates live to 跟随系统（深色）
    mm.setDark(true);
    expect(root.querySelector('[data-testid="theme-opt-system"]')?.textContent).toBe("跟随系统（深色）");

    // Open Theme popover menu and pick Dark
    const themeTrigger = root.querySelector<HTMLButtonElement>('[data-testid="theme-trigger"]')!;
    themeTrigger.click();
    expect(themeTrigger.getAttribute("aria-expanded")).toBe("true");
    root.querySelector<HTMLButtonElement>('[data-testid="theme-opt-dark"]')!.click();
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(themeTrigger.getAttribute("aria-expanded")).toBe("false");

    // Switch Language back to EN
    root.querySelector<HTMLButtonElement>('[data-testid="lang-opt-en"]')!.click();
    expect(document.documentElement.lang).toBe("en");
    expect(root.querySelector('[data-testid="new-block-btn"]')?.textContent).toBe("New Block");
    expect(root.querySelector('[data-testid="theme-opt-system"]')?.textContent).toBe("System (Dark)");
    expect(cardBefore.querySelector(".cm-editor")).toBe(cmEditorBefore);
    expect(app.stream.getBlockDraftContent(blkId)).toBe("# Unsaved Draft 123");
    expect(app.isVaultUnlocked()).toBe(true);

    // Zero inline style on custom UI chrome & SVG icons, zero forbidden emojis
    const chromeNodes = [
      ...root.querySelectorAll(".topbar *, .find-bar *, .block-header *, .conflict-panel *, .drawer *, svg.icon"),
    ];
    for (const el of chromeNodes) {
      expect(el.getAttribute("style"), `Unexpected inline style on <${el.tagName}>`).toBeNull();
    }
    const text = root.textContent ?? "";
    for (const emoji of FORBIDDEN_EMOJIS) {
      expect(text, `Forbidden emoji ${emoji} found in Desktop DOM`).not.toContain(emoji);
    }

    app.destroy();
  });

  it("Mobile PWA: exposes Theme & Language controls in both Onboarding and Paired states, preserves Vault RAM across locale switch, and enforces SEC-08 hide wipe", async () => {
    installFakeMatchMedia(false);
    const pwaRoot = document.createElement("div");
    pwaRoot.className = "pwa-shell";
    document.body.appendChild(pwaRoot);

    const pwa = new MobilePwaApp(pwaRoot);
    const internals = pwa as unknown as {
      creds: {
        device_id: string;
        device_token: string;
        sync_url: string;
        smks: Array<{ smk_kid: string; smk_b64: string }>;
      } | null;
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
      activeBufferId: string | null;
      vaultSession: { isLocked(): boolean; lockAndZeroize(): void; free(): void } | null;
      unlockedPlaintext: Map<string, Map<string, string>>;
      render(): void;
    };

    // 1. Onboarding state has Theme + Language controls and translates cleanly
    internals.render();
    const themeAnchorBefore = pwaRoot.querySelector(".popover-anchor");
    const langSwitchBefore = pwaRoot.querySelector('[data-testid="pwa-lang-switch"]');
    expect(pwaRoot.querySelector('[data-testid="pwa-theme-trigger"]')).not.toBeNull();
    expect(langSwitchBefore).not.toBeNull();
    expect(pwaRoot.querySelector(".onboard-title")?.textContent).toBe("Pair Read-Only Mobile Device");

    let headerControlsDetached = false;
    const headerObserver = new MutationObserver((muts) => {
      for (const m of muts) {
        for (const removed of m.removedNodes) {
          if (removed === themeAnchorBefore || removed === langSwitchBefore || (removed instanceof Element && (removed.contains(themeAnchorBefore) || removed.contains(langSwitchBefore)))) {
            headerControlsDetached = true;
          }
        }
      }
    });
    headerObserver.observe(pwaRoot.querySelector(".pwa-header")!, { childList: true, subtree: true });

    pwaRoot.querySelector<HTMLButtonElement>('[data-testid="pwa-lang-opt-zh-CN"]')!.click();
    expect(pwaRoot.querySelector(".onboard-title")?.textContent).toBe("配对只读移动设备");
    expect(pwaRoot.querySelector(".ro-pill")?.textContent).toBe("只读");
    // Flush microtasks so MutationObserver callback runs
    await Promise.resolve();
    expect(headerControlsDetached).toBe(false);
    expect(pwaRoot.querySelector(".popover-anchor")).toBe(themeAnchorBefore);
    headerObserver.disconnect();

    // 2. Paired state with unlocked Tier 2 Vault in RAM
    let locked = false;
    internals.creds = {
      device_id: "dev_iphone01",
      device_token: "tok",
      sync_url: "https://sync.example.com",
      smks: [],
    };
    internals.buffers = [{ id: "01BUF_M", name: "mobile", position: "a0", state: "active", updated_at_ms: 1000 }];
    internals.activeBufferId = "01BUF_M";
    internals.blocks = [
      {
        id: "01BLK_PWA_T2",
        buffer_id: "01BUF_M",
        position: "a0",
        lang: "text",
        public_hint: "Prod Key",
        state: "active",
        is_locked: true,
        has_unlocked_concurrent_version: false,
        display_op_id: "01OP_1",
        updated_at_ms: 1000,
        versions: [
          {
            op_id: "01OP_1",
            hlc: "000000000001000-00000-dev_mac",
            device_id: "dev_mac",
            actor: "human",
            is_display: true,
            is_locked: true,
            key_id: "01KEY_1",
            content: null,
            mnb1_b64: "AAA",
            mnw1_b64: "BBB",
            body_state: "locked",
          },
        ],
      },
    ];
    internals.vaultSession = {
      isLocked: () => locked,
      lockAndZeroize: () => {
        locked = true;
      },
      free: () => {},
    };
    internals.unlockedPlaintext.set("01BLK_PWA_T2", new Map([["01OP_1", "PWA_RAM_SECRET_VALUE"]]));
    internals.render();

    expect(pwaRoot.textContent).toContain("PWA_RAM_SECRET_VALUE");
    expect(pwaRoot.querySelector('[data-testid="pwa-vault-lock-btn"]')?.textContent).toBe("锁定");

    // Switch back to EN -> Vault RAM secret stays intact!
    pwaRoot.querySelector<HTMLButtonElement>('[data-testid="pwa-lang-opt-en"]')!.click();
    expect(pwaRoot.textContent).toContain("PWA_RAM_SECRET_VALUE");
    expect(pwaRoot.querySelector('[data-testid="pwa-vault-lock-btn"]')?.textContent).toBe("Lock");
    expect(pwaRoot.querySelector(".ro-pill")?.textContent).toBe("READ-ONLY");

    // Theme switching works in PWA too
    pwaRoot.querySelector<HTMLButtonElement>('[data-testid="pwa-theme-opt-dark"]')!.click();
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");

    // Zero inline style & zero forbidden emojis in PWA DOM
    for (const el of pwaRoot.querySelectorAll("*")) {
      expect(el.getAttribute("style"), `Unexpected inline style on PWA <${el.tagName}>`).toBeNull();
    }
    const pwaText = pwaRoot.textContent ?? "";
    for (const emoji of FORBIDDEN_EMOJIS) {
      expect(pwaText, `Forbidden emoji ${emoji} found in PWA DOM`).not.toContain(emoji);
    }

    // SEC-08: visibilitychange: hidden still wipes immediately
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    document.dispatchEvent(new Event("visibilitychange"));
    expect(pwaRoot.textContent).not.toContain("PWA_RAM_SECRET_VALUE");
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });

    pwa.destroy();
    pwaRoot.remove();
  });

  it("enforces strict CSP-safe HTML & /theme-init.js bootstrap contract", async () => {
    const fsMod = (await import(/* @vite-ignore */ "node:" + "fs")) as {
      readFileSync(p: string, enc: string): string;
    };
    const desktopHtml = fsMod.readFileSync("index.html", "utf8");
    const pwaHtml = fsMod.readFileSync("pwa.html", "utf8");
    const swJs = fsMod.readFileSync("public-pwa/sw.js", "utf8");
    const desktopInit = fsMod.readFileSync("public/theme-init.js", "utf8");
    const pwaInit = fsMod.readFileSync("public-pwa/theme-init.js", "utf8");

    for (const html of [desktopHtml, pwaHtml]) {
      expect(html).toContain('<meta name="color-scheme" content="light dark" />');
      expect(html).toContain('<meta name="theme-color" content="#171614" />');
      expect(html).toContain('<script src="/theme-init.js"></script>');
      expect(html).toContain('data-theme="auto"');
      // ZERO inline <script> bodies
      const scriptTags = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
      expect(scriptTags.length).toBeGreaterThanOrEqual(2);
      for (const [, attrs, body] of scriptTags) {
        expect(attrs).toMatch(/\bsrc=/i);
        expect(body.trim()).toBe("");
      }
    }

    expect(swJs).toContain("mynote-pwa-shell-v4");
    expect(swJs).toContain('"/theme-init.js"');
    expect(desktopInit).toBe(pwaInit);

    // Execute bootstrap script against stored theme & locale
    localStorage.setItem(THEME_STORAGE_KEY, "dark");
    localStorage.setItem(LOCALE_STORAGE_KEY, "zh-CN");
    new Function(desktopInit)();
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.lang).toBe("zh-CN");
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute("content")).toBe("dark");
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute("content")).toBe("#171614");
  });

  it("refinement pass invariants: GFM CM6 highlight tags, Find decorations + Prev, Conflict badge, ⌘P quick switcher, localized History/Trash, and PWA cli-chip", async () => {
    installFakeMatchMedia(false);
    const { markdown, markdownLanguage } = await import("@codemirror/lang-markdown");
    const { highlightTree } = await import("@lezer/highlight");
    const { myNoteHighlightStyle } = await import("../src/cmTheme");
    const { formatDeviceName, formatOpTypeLabel, formatActorLabel, formatShredStateLabel } = await import(
      "../src/i18n"
    );

    // 1. GFM Markdown in CM6: [x] MUST NOT be styled as underlined hyperlink, inline `localhost` MUST be styled
    const sampleMd = "- [x] Local SQLite WAL on `localhost` (`0600`)\n\n[docs](https://example.com)\n";
    const mdSupport = markdown({ base: markdownLanguage });
    const tree = mdSupport.language.parser.parse(sampleMd);
    const spans: Array<{ text: string; classes: string }> = [];
    highlightTree(tree, myNoteHighlightStyle, (from, to, classes) => {
      spans.push({ text: sampleMd.slice(from, to), classes });
    });
    const checkboxSpan = spans.find((s) => s.text === "[x]");
    const urlSpan = spans.find((s) => s.text === "https://example.com");
    const inlineCodeSpan = spans.find((s) => s.text.includes("localhost"));
    expect(checkboxSpan).toBeDefined();
    expect(inlineCodeSpan).toBeDefined();
    expect(checkboxSpan?.classes).not.toBe(urlSpan?.classes);

    // 1b. Markdown fenced mermaid & typescript blocks receive real syntax highlighting (not monochrome inline-code style)
    const { loadLangExtension } = await import("../src/langs");
    const { EditorState } = await import("@codemirror/state");
    const { syntaxTree } = await import("@codemirror/language");
    const { highlightCodeSnippet } = await import("../src/render/highlight");
    const mdExt = await loadLangExtension("markdown");
    const fencedSample = "```mermaid\nflowchart LR\n  A --> B\n```\n";
    const st = EditorState.create({ doc: fencedSample, extensions: [mdExt] });
    const fencedSpans: Array<{ text: string; classes: string }> = [];
    highlightTree(syntaxTree(st), myNoteHighlightStyle, (from, to, classes) => {
      fencedSpans.push({ text: fencedSample.slice(from, to), classes });
    });
    expect(fencedSpans.some((s) => s.text === "flowchart")).toBe(true);
    const tsTokens = await highlightCodeSnippet("const ok: boolean = true;", "ts");
    expect(tsTokens?.some((tok) => tok.text === "const" && tok.cls === "tok-kw")).toBe(true);
    expect(tsTokens?.some((tok) => tok.text === "boolean" && tok.cls === "tok-type")).toBe(true);

    // 2. Human-friendly device & enum localization
    expect(formatDeviceName("dev_macmini0001")).toBe("macmini");
    expect(formatDeviceName("dev_omarchy0001")).toBe("omarchy");
    setLocale("zh-CN");
    expect(formatOpTypeLabel("UPDATE")).toBe("编辑");
    expect(formatOpTypeLabel("CREATE")).toBe("创建");
    expect(formatActorLabel("human")).toBe("手动");
    expect(formatShredStateLabel("scheduled")).toBe("已排期");
    setLocale("en");

    // 3. Desktop UI: Conflict badge, Find highlights + Prev button, ⌘P quick switcher, quiet sync pill
    const { api } = makeSimpleDesktopApi();
    const root = document.getElementById("app")!;
    const app = new MyNoteApp(root, api);
    await app.start();

    // Sync pill when synced is whisper-quiet with single dot (NO check-circle svg + dot combo)
    const syncPill = root.querySelector<HTMLButtonElement>('[data-testid="sync-pill"]')!;
    expect(syncPill.classList.contains("is-quiet")).toBe(true);
    expect(syncPill.querySelector(".sync-dot")).not.toBeNull();
    expect(syncPill.querySelector("svg")).toBeNull();

    // Conflict block renders unmistakable inline conflict badge in header
    const conflictBadge = root.querySelector('[data-testid="conflict-badge-01BLK_THEME_CONFLICT_2"]');
    expect(conflictBadge).not.toBeNull();
    expect(conflictBadge?.classList.contains("hidden")).toBe(false);
    expect(conflictBadge?.textContent).toContain("Conflict");

    // Find bar has Prev + Next buttons and highlights matches in unfocused CM6 via .cm-find-match-active
    root.querySelector<HTMLButtonElement>('[data-testid="find-btn"]')!.click();
    expect(root.querySelector('[data-testid="find-prev-btn"]')).not.toBeNull();
    const findInput = root.querySelector<HTMLInputElement>(".find-bar input")!;
    findInput.value = "alpha";
    findInput.dispatchEvent(new Event("input"));
    expect(root.querySelector(".cm-find-match-active")?.textContent).toBe("alpha");

    // Buffers ⌘P modal opens with top filter input focused, active checkmark (no duplicate "Current"), tabular count, inline create, and keyboard hints
    root.querySelector<HTMLButtonElement>('[data-testid="buffers-btn"]')!.click();
    const filterInput = root.querySelector<HTMLInputElement>('[data-testid="buffer-filter-input"]')!;
    expect(document.activeElement).toBe(filterInput);
    expect(root.querySelector(".modal-row.is-current")).not.toBeNull();
    expect(root.querySelector(".modal-current-pill")).toBeNull();
    expect(root.querySelector(".modal-row-count")?.textContent).toBe("2 blocks");
    expect(root.querySelector(".modal-hints")).not.toBeNull();

    // Typing a new buffer name reveals inline Create option without a separate empty-state primary button
    filterInput.value = "ops-notes";
    filterInput.dispatchEvent(new Event("input"));
    const createRow = root.querySelector<HTMLElement>('[data-testid="buffer-create-inline-row"]');
    expect(createRow?.textContent).toContain('Create "ops-notes"');

    // Find bar lives inside .workspace-main so side drawers remain full-height
    expect(root.querySelector(".workspace-main > .find-bar")).not.toBeNull();

    // Conflict panel uses inline word diff & keeps Commit Merged Text secondary (non-primary) until user edits
    const conflictCard = root.querySelector<HTMLElement>('[data-block-id="01BLK_THEME_CONFLICT_2"]')!;
    const commitBtn = conflictCard.querySelector(".conflict-commit-btn");
    expect(commitBtn?.classList.contains("btn")).toBe(true);
    expect(commitBtn?.classList.contains("btn-primary")).toBe(false);
    expect(conflictCard.querySelector(".conflict-diff-shown")?.textContent).toBe("alpha");
    expect(conflictCard.querySelector(".conflict-diff-other")?.textContent).toBe("beta");

    app.destroy();

    // 4. PWA Onboarding: wrapped .cli-chip with atomic flags, promoted Scan QR when input empty, disabled Pair Device until code entered
    const pwaRoot = document.createElement("div");
    pwaRoot.className = "pwa-shell";
    document.body.appendChild(pwaRoot);
    const pwa = new MobilePwaApp(pwaRoot);
    (pwa as unknown as { render(): void }).render();
    expect(pwaRoot.querySelector(".cli-chip")?.textContent).toBe("mynote device add --name iPhone --scope read");
    expect(pwaRoot.querySelectorAll(".cli-chip .cli-nowrap").length).toBe(3);
    expect(pwaRoot.textContent).not.toContain("Zero-Plaintext IDB");
    expect(pwaRoot.textContent).not.toContain("(Camera)");
    expect(pwaRoot.querySelector(".pwa-footer")?.classList.contains("hidden")).toBe(true);
    const qrBtn = pwaRoot.querySelector<HTMLButtonElement>('[data-testid="pwa-scan-qr-btn"]')!;
    const pairBtn = pwaRoot.querySelector<HTMLButtonElement>('[data-testid="pwa-pair-submit"]')!;
    const pairInput = pwaRoot.querySelector<HTMLInputElement>('[data-testid="pwa-pair-input"]')!;
    expect(pairBtn.disabled).toBe(true);
    expect(qrBtn.classList.contains("btn-primary")).toBe(true);
    pairInput.value = "mynote-pair:v1:abc";
    pairInput.dispatchEvent(new Event("input"));
    expect(pairBtn.disabled).toBe(false);
    expect(pairBtn.classList.contains("btn-primary")).toBe(true);
    expect(qrBtn.classList.contains("btn-primary")).toBe(false);
    pwa.destroy();
    pwaRoot.remove();
  });
});
