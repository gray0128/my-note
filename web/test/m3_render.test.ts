import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import xssVectors from "../../tests/fixtures/xss_vectors.json";
import {
  renderSafeMarkdown,
  mountMarkdownPreview,
  toggleMarkdownTaskCheckbox,
  copyDualFormat,
  tableToTsv,
  tableToMarkdown,
} from "../src/render/markdown";
import {
  peleDiagramRenderer,
  resolveSvgForStandaloneExport,
  svgToPngBlob,
  copyDiagramPng,
  attachSvgViewBoxPanZoom,
  mountDiagramWidget,
  type DiagramRenderer,
} from "../src/render/diagram";
import { computeLineDiff } from "../src/render/diff";

function assertDomTreeCleanOfXss(root: Element): void {
  const forbiddenTags = new Set([
    "script",
    "iframe",
    "object",
    "embed",
    "form",
    "foreignobject",
    "style",
    "img",
  ]);
  const elements = [root, ...Array.from(root.querySelectorAll("*"))];
  for (const el of elements) {
    const tag = el.localName.toLowerCase();
    expect(forbiddenTags.has(tag), `Forbidden tag <${tag}> found in DOM`).toBe(false);
    if (tag === "input") {
      expect(el.getAttribute("type")?.toLowerCase()).toBe("checkbox");
    }
    for (const attr of Array.from(el.attributes)) {
      const name = attr.name.toLowerCase();
      expect(name.startsWith("on"), `Forbidden event handler ${name}`).toBe(false);
      expect(name, "Forbidden inline style attribute").not.toBe("style");
      if (name === "href" || name === "src" || name === "xlink:href") {
        expect(attr.value).not.toMatch(/^\s*(?:javascript|vbscript|data):/i);
        expect(attr.value).not.toMatch(/^\/\//);
      }
    }
  }
}

function assertSvgTreeSafe(svgMarkup: string): SVGSVGElement {
  const doc = new DOMParser().parseFromString(svgMarkup, "image/svg+xml");
  const root = doc.documentElement as unknown as SVGSVGElement;
  expect(root.localName.toLowerCase()).toBe("svg");

  const forbiddenTags = new Set([
    "foreignobject",
    "script",
    "style",
    "iframe",
    "object",
    "embed",
    "image",
    "link",
    "meta",
    "animate",
    "set",
  ]);

  const elements = [root, ...Array.from(root.querySelectorAll("*"))];
  for (const el of elements) {
    const tag = el.localName.toLowerCase();
    expect(forbiddenTags.has(tag), `Forbidden SVG tag <${tag}>`).toBe(false);
    for (const attr of Array.from(el.attributes)) {
      const name = attr.name.toLowerCase();
      expect(name, "Inline style attribute violates style-src 'self'").not.toBe("style");
      expect(name.startsWith("on"), `Forbidden event attr ${name}`).toBe(false);
      expect(name, `Forbidden href attr ${name}`).not.toBe("href");
      expect(name, `Forbidden xlink:href attr ${name}`).not.toBe("xlink:href");
      expect(attr.value).not.toMatch(/javascript:|vbscript:|url\s*\(/i);
    }
  }

  return root;
}

describe("SEC-06 XSS and external image exfiltration protection", () => {
  let host: HTMLDivElement;

  beforeEach(() => {
    host = document.createElement("div");
    document.body.appendChild(host);
  });

  afterEach(() => {
    host.remove();
  });

  it("loads comprehensive fixture vectors from tests/fixtures/xss_vectors.json", () => {
    expect(xssVectors.markdown_xss.length).toBeGreaterThanOrEqual(15);
    expect(xssVectors.external_images.length).toBeGreaterThanOrEqual(5);
    expect(xssVectors.mermaid_xss.length).toBeGreaterThanOrEqual(5);
  });

  it("blocks every markdown_xss vector in renderSafeMarkdown and mountMarkdownPreview", () => {
    for (const vector of xssVectors.markdown_xss) {
      const result = renderSafeMarkdown(vector);
      expect(result.html).not.toMatch(/<script\b/i);
      expect(result.html).not.toMatch(/<iframe\b/i);
      expect(result.html).not.toMatch(/<object\b/i);
      expect(result.html).not.toMatch(/<embed\b/i);
      expect(result.html).not.toMatch(/<form\b/i);
      expect(result.html).not.toMatch(/<foreignObject\b/i);
      expect(result.html).not.toMatch(/<style\b/i);
      expect(result.html).not.toMatch(/<img\b/i);

      const preview = mountMarkdownPreview(host, vector, { readOnly: true });
      assertDomTreeCleanOfXss(host);
      preview.destroy();
    }
  });

  it("blocks every external_images exfiltration vector with zero <img> tags", () => {
    for (const vector of xssVectors.external_images) {
      const result = renderSafeMarkdown(vector);
      expect(result.html).not.toMatch(/<img\b/i);

      const preview = mountMarkdownPreview(host, vector, { readOnly: true });
      assertDomTreeCleanOfXss(host);
      expect(host.querySelectorAll("img").length).toBe(0);
      preview.destroy();
    }

    const mdImg = renderSafeMarkdown("![secret](https://evil.example/beacon?s=1)");
    expect(mdImg.html).toContain("md-blocked-img");
    expect(mdImg.html).toContain('rel="noopener noreferrer"');
    expect(mdImg.html).toContain('target="_blank"');
    expect(mdImg.html).not.toMatch(/<img\b/i);

    const jsImg = renderSafeMarkdown("![bad](javascript:alert(1))");
    expect(jsImg.html).toContain("md-blocked-img");
    expect(jsImg.html).not.toMatch(/<a\b/i);
    expect(jsImg.html).not.toMatch(/<img\b/i);

    const links = renderSafeMarkdown(
      "[ok](https://example.com/x) [mail](mailto:test@example.com) [frag](#sec) [bad](javascript:alert(1))",
    );
    expect(links.html).toContain('href="https://example.com/x"');
    expect(links.html).toContain('href="mailto:test@example.com"');
    expect(links.html).toContain('href="#sec"');
    expect(links.html).not.toContain("javascript:");
  });

  it("sanitizes or safely rejects every mermaid_xss vector with zero foreignObject/script/style", async () => {
    for (const vector of xssVectors.mermaid_xss) {
      let renderedSvg: string | null = null;
      try {
        const res = await peleDiagramRenderer.render(vector);
        renderedSvg = res.svg;
      } catch {
        // Rejection at parse time is safe for hostile Mermaid syntax (e.g. url() in style).
      }
      if (renderedSvg !== null) {
        assertSvgTreeSafe(renderedSvg);
      }
    }
  });
});

describe("toggleMarkdownTaskCheckbox and interactive task preview", () => {
  it("toggles checkboxes across nested and ordered lists while ignoring code fences", () => {
    const src = [
      "# Tasks",
      "- [ ] first",
      "  - [x] nested done",
      "```markdown",
      "- [ ] inside backtick fence",
      "- [x] also inside fence",
      "```",
      "~~~md",
      "- [ ] inside tilde fence",
      "~~~",
      "1. [ ] ordered item",
      "* [X] uppercase checked",
    ].join("\n");

    const toggle0 = toggleMarkdownTaskCheckbox(src, 0);
    expect(toggle0).toContain("- [x] first");
    expect(toggle0).toContain("- [ ] inside backtick fence");

    const toggle1 = toggleMarkdownTaskCheckbox(src, 1);
    expect(toggle1).toContain("  - [ ] nested done");

    const toggle2 = toggleMarkdownTaskCheckbox(src, 2);
    expect(toggle2).toContain("1. [x] ordered item");
    expect(toggle2).toContain("- [ ] inside backtick fence");
    expect(toggle2).toContain("- [ ] inside tilde fence");

    const toggle3 = toggleMarkdownTaskCheckbox(src, 3);
    expect(toggle3).toContain("* [ ] uppercase checked");

    expect(toggleMarkdownTaskCheckbox(src, 99)).toBe(src);
    expect(toggleMarkdownTaskCheckbox(src, -1)).toBe(src);
  });

  it("preserves CRLF line endings when toggling a checkbox", () => {
    const crlf = "- [ ] alpha\r\n- [x] beta\r\n";
    expect(toggleMarkdownTaskCheckbox(crlf, 0)).toBe("- [x] alpha\r\n- [x] beta\r\n");
  });

  it("enables interactive toggling in edit mode and locks checkboxes in readOnly mode", () => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    const md = "- [ ] one\n- [x] two\n";

    const ro = mountMarkdownPreview(host, md, { readOnly: true });
    const roBoxes = Array.from(host.querySelectorAll('input[type="checkbox"]')) as HTMLInputElement[];
    expect(roBoxes).toHaveLength(2);
    expect(roBoxes[0].disabled).toBe(true);
    expect(roBoxes[1].disabled).toBe(true);
    ro.destroy();

    const toggled: string[] = [];
    const rw = mountMarkdownPreview(host, md, {
      readOnly: false,
      onToggleTask: (next) => toggled.push(next),
    });
    const rwBoxes = Array.from(host.querySelectorAll('input[type="checkbox"]')) as HTMLInputElement[];
    expect(rwBoxes[0].disabled).toBe(false);
    rwBoxes[0].checked = true;
    rwBoxes[0].dispatchEvent(new Event("change"));
    expect(toggled).toEqual(["- [x] one\n- [x] two\n"]);

    rw.destroy();
    host.remove();
  });
});

describe("GFM tables, code copy, and Dual-Format clean copy payload", () => {
  let host: HTMLDivElement;

  beforeEach(() => {
    host = document.createElement("div");
    document.body.appendChild(host);
  });

  afterEach(() => {
    host.remove();
    vi.restoreAllMocks();
  });

  it("exports tables to TSV and Markdown preserving alignment, quotes, tabs, pipes, and CJK", () => {
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const hRow = document.createElement("tr");
    const h1 = document.createElement("th");
    h1.setAttribute("align", "left");
    h1.textContent = "名称";
    const h2 = document.createElement("th");
    h2.setAttribute("align", "center");
    h2.textContent = "Note | Info";
    const h3 = document.createElement("th");
    h3.setAttribute("align", "right");
    h3.textContent = "Score";
    hRow.append(h1, h2, h3);
    thead.appendChild(hRow);

    const tbody = document.createElement("tbody");
    const r1 = document.createElement("tr");
    const c1 = document.createElement("td");
    c1.textContent = "中文项目";
    const c2 = document.createElement("td");
    c2.textContent = 'He said "hi"\tnow';
    const c3 = document.createElement("td");
    c3.textContent = "98";
    r1.append(c1, c2, c3);
    tbody.appendChild(r1);
    table.append(thead, tbody);

    expect(tableToTsv(table)).toBe('名称\tNote | Info\tScore\n中文项目\t"He said ""hi""\tnow"\t98');
    expect(tableToMarkdown(table)).toBe(
      "| 名称 | Note \\| Info | Score |\n| :--- | :---: | ---: |\n| 中文项目 | He said \"hi\"\tnow | 98 |",
    );
  });

  it("provides clean semantic HTML and plain text in getCleanCopyPayload with zero UI chrome", () => {
    const md = [
      "# Weekly Plan",
      "",
      "| Task | Status |",
      "| :--- | ---: |",
      "| Ship M3 | Ready |",
      "",
      "```ts",
      "export const answer = 42;",
      "```",
    ].join("\n");

    const mounted = mountMarkdownPreview(host, md, { readOnly: true });
    expect(host.querySelector(".md-code-wrap .md-copy-code")).not.toBeNull();
    expect(host.querySelector(".md-table-wrap .md-copy-tsv")).not.toBeNull();
    expect(host.querySelector(".md-table-wrap .md-copy-md")).not.toBeNull();

    const payload = mounted.getCleanCopyPayload();
    expect(payload.html).toContain("<h1>Weekly Plan</h1>");
    expect(payload.html).toContain("<table>");
    expect(payload.html).toContain("<pre><code");
    expect(payload.html).not.toContain("Copy Code");
    expect(payload.html).not.toContain("Copy TSV");
    expect(payload.html).not.toContain("Copy MD");
    expect(payload.html).not.toContain("Copy PNG");
    expect(payload.text).toContain("Weekly Plan");
    expect(payload.text).toContain("Ship M3\tReady");
    expect(payload.text).toContain("export const answer = 42;");
    expect(payload.text).not.toContain("Copy Code");
    expect(payload.text).not.toContain("Copy TSV");

    mounted.destroy();
  });

  it("copies raw code without backticks, keeps button enabled, and announces repeat copies via role=status", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    const md = "```rust\nfn main() {}\n```\n";
    const feedback: Array<{ msg: string; isError?: boolean }> = [];
    const mounted = mountMarkdownPreview(host, md, {
      readOnly: true,
      onCopyFeedback: (msg, isError) => feedback.push({ msg, isError }),
    });

    const btn = host.querySelector(".md-copy-code") as HTMLButtonElement;
    const tip = btn.nextElementSibling as HTMLSpanElement;
    expect(btn.type).toBe("button");
    expect(tip.getAttribute("role")).toBe("status");

    btn.click();
    await new Promise((r) => setTimeout(r, 30));
    expect(writeText).toHaveBeenCalledWith("fn main() {}");
    expect(btn.disabled).toBe(false);
    expect(btn.hasAttribute("data-copied")).toBe(true);
    const firstMsg = tip.textContent ?? "";
    expect(firstMsg.trim()).toBe("Copied");

    btn.click();
    await new Promise((r) => setTimeout(r, 30));
    const secondMsg = tip.textContent ?? "";
    expect(secondMsg).not.toBe(firstMsg);
    expect(secondMsg.trim()).toBe("Copied");
    expect(feedback).toHaveLength(2);

    mounted.destroy();
  });

  it("mounts embedded mermaid slots, copies table TSV/MD, and handles clipboard failure without disabling button", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    const md = [
      "| Col A | Col B |",
      "| :--- | ---: |",
      "| one | two |",
      "",
      "```mermaid",
      "flowchart LR",
      "  A[Start] --> B[End]",
      "```",
    ].join("\n");

    const mounted = mountMarkdownPreview(host, md, { readOnly: true });
    await new Promise((r) => setTimeout(r, 80));

    const svg = host.querySelector(".md-mermaid-slot svg");
    expect(svg).not.toBeNull();
    expect(svg?.getAttribute("style")).toBeNull();

    const tsvBtn = host.querySelector(".md-copy-tsv") as HTMLButtonElement;
    const mdBtn = host.querySelector(".md-copy-md") as HTMLButtonElement;
    tsvBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(writeText).toHaveBeenCalledWith("Col A\tCol B\none\ttwo");

    writeText.mockRejectedValueOnce(new Error("permission denied"));
    mdBtn.click();
    await new Promise((r) => setTimeout(r, 30));
    expect(mdBtn.disabled).toBe(false);
    expect(mdBtn.hasAttribute("data-failed")).toBe(true);
    expect((mdBtn.nextElementSibling as HTMLSpanElement).textContent?.trim()).toBe("Copy failed");

    const payload = mounted.getCleanCopyPayload();
    expect(payload.html).toContain("language-mermaid");
    expect(payload.html).not.toContain("Copy PNG");
    expect(payload.html).not.toContain("Copy TSV");

    mounted.destroy();
  });

  it("writes Dual-Format ClipboardItem when supported and falls back to writeText otherwise", async () => {
    const write = vi.fn().mockResolvedValue(undefined);
    const writeText = vi.fn().mockResolvedValue(undefined);
    class FakeClipboardItem {
      constructor(public readonly items: Record<string, Blob>) {}
    }
    vi.stubGlobal("ClipboardItem", FakeClipboardItem);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { write, writeText },
    });

    const ok1 = await copyDualFormat("<p>Hi</p>", "Hi");
    expect(ok1).toBe(true);
    expect(write).toHaveBeenCalledTimes(1);
    const firstArg = write.mock.calls[0][0] as FakeClipboardItem[];
    expect(Object.keys(firstArg[0].items)).toEqual(["text/html", "text/plain"]);

    write.mockRejectedValueOnce(new Error("html mime rejected"));
    const ok2 = await copyDualFormat("<p>Fallback</p>", "Fallback");
    expect(ok2).toBe(true);
    expect(writeText).toHaveBeenCalledWith("Fallback");
  });
});

describe("Pele SVG diagram rendering, export, pan/zoom, and last-valid-frame preservation", () => {
  let host: HTMLDivElement;

  beforeEach(() => {
    host = document.createElement("div");
    document.body.appendChild(host);
  });

  afterEach(() => {
    host.remove();
    vi.restoreAllMocks();
  });

  it("renders flowchart, sequenceDiagram, erDiagram, classDiagram, stateDiagram-v2 with zero style attrs and valid viewBox", async () => {
    const diagrams = [
      "flowchart LR\n  A[Start] --> B{Check}\n  style A fill:#f00,stroke:#333,stroke-width:2px",
      "sequenceDiagram\n  Alice->>Bob: Hello",
      "erDiagram\n  USER ||--o{ ORDER : places",
      "classDiagram\n  Animal <|-- Duck",
      "stateDiagram-v2\n  [*] --> Active",
    ];

    for (const src of diagrams) {
      const rendered = await peleDiagramRenderer.render(src);
      expect(rendered.width).toBeGreaterThan(0);
      expect(rendered.height).toBeGreaterThan(0);
      const svgEl = assertSvgTreeSafe(rendered.svg);
      const vb = svgEl.getAttribute("viewBox");
      expect(vb).toBeTruthy();
      expect(vb?.trim().split(/\s+/)).toHaveLength(4);
    }

    const styled = await peleDiagramRenderer.render(diagrams[0]);
    expect(styled.svg).toContain('fill="#f00"');
    expect(styled.svg).toContain('stroke="#333"');
    expect(styled.svg).toContain('stroke-width="2px"');
    expect(styled.svg).not.toMatch(/\sstyle=/i);
  });

  it("preserves last valid SVG frame when updated with broken Mermaid syntax", async () => {
    const widget = mountDiagramWidget(host, "flowchart LR\n  A[Alpha] --> B[Beta]");
    expect(await widget.ready).toBe(true);

    const viewport = host.querySelector(".diagram-viewport") as HTMLDivElement;
    const hint = host.querySelector(".diagram-syntax-hint") as HTMLDivElement;
    const initialSvg = viewport.querySelector("svg");
    expect(initialSvg).not.toBeNull();
    expect(hint.hidden).toBe(true);

    const badOk = await widget.update("flowchart LR\n  A --> --> ??? BROKEN %%%");
    expect(badOk).toBe(false);
    expect(hint.hidden).toBe(false);
    expect(hint.textContent).toContain("Diagram syntax error");
    expect(viewport.querySelector("svg")).toBe(initialSvg);
    expect(viewport.textContent).toContain("Alpha");

    const recoveredOk = await widget.update("sequenceDiagram\n  Alice->>Bob: Recovered");
    expect(recoveredOk).toBe(true);
    expect(hint.hidden).toBe(true);
    expect(viewport.textContent).toContain("Recovered");

    widget.destroy();
  });

  it("zooms and pans strictly via viewBox attribute with zero inline style mutations", async () => {
    const fakeRenderer: DiagramRenderer = {
      id: "stub",
      async render() {
        return {
          svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100" width="200" height="100"><rect x="10" y="10" width="50" height="30"/></svg>',
          width: 200,
          height: 100,
          type: "flowchart",
        };
      },
    };

    const widget = mountDiagramWidget(host, "flowchart LR\n  A-->B", { renderer: fakeRenderer });
    expect(await widget.ready).toBe(true);

    const viewport = host.querySelector(".diagram-viewport") as HTMLDivElement;
    const svg = viewport.querySelector("svg") as SVGSVGElement;
    expect(svg.getAttribute("viewBox")).toBe("0 0 200 100");

    const zoomInBtn = host.querySelector('button[aria-label="Zoom in"]') as HTMLButtonElement;
    const resetBtn = Array.from(host.querySelectorAll("button")).find(
      (b) => b.textContent === "Reset",
    ) as HTMLButtonElement;

    zoomInBtn.click();
    const zoomedVb = svg.getAttribute("viewBox") ?? "";
    expect(zoomedVb).not.toBe("0 0 200 100");
    expect(svg.getAttribute("style")).toBeNull();
    expect(viewport.getAttribute("style")).toBeNull();

    resetBtn.click();
    expect(svg.getAttribute("viewBox")).toBe("0 0 200 100");

    const ctrl = attachSvgViewBoxPanZoom(viewport, svg);
    ctrl.zoomOut();
    const outParts = (svg.getAttribute("viewBox") ?? "").split(/\s+/).map(Number);
    expect(outParts[2]).toBeGreaterThan(200);
    ctrl.reset();
    expect(svg.getAttribute("viewBox")).toBe("0 0 200 100");

    // Pointer drag pan mutates viewBox x/y with zero inline styles
    viewport.dispatchEvent(new PointerEvent("pointerdown", { pointerId: 1, clientX: 50, clientY: 50, button: 0, pointerType: "mouse" }));
    viewport.dispatchEvent(new PointerEvent("pointermove", { pointerId: 1, clientX: 70, clientY: 60, pointerType: "mouse" }));
    viewport.dispatchEvent(new PointerEvent("pointerup", { pointerId: 1, clientX: 70, clientY: 60, pointerType: "mouse" }));
    const draggedParts = (svg.getAttribute("viewBox") ?? "").split(/\s+/).map(Number);
    expect(draggedParts[0]).toBeLessThan(0);
    expect(draggedParts[1]).toBeLessThan(0);
    expect(svg.getAttribute("style")).toBeNull();
    expect(viewport.getAttribute("style")).toBeNull();

    // Two-finger pinch zoom mutates viewBox width with zero inline styles
    ctrl.reset();
    viewport.dispatchEvent(new PointerEvent("pointerdown", { pointerId: 10, clientX: 40, clientY: 50, pointerType: "touch" }));
    viewport.dispatchEvent(new PointerEvent("pointerdown", { pointerId: 11, clientX: 80, clientY: 50, pointerType: "touch" }));
    viewport.dispatchEvent(new PointerEvent("pointermove", { pointerId: 11, clientX: 120, clientY: 50, pointerType: "touch" }));
    viewport.dispatchEvent(new PointerEvent("pointerup", { pointerId: 10, clientX: 40, clientY: 50, pointerType: "touch" }));
    viewport.dispatchEvent(new PointerEvent("pointerup", { pointerId: 11, clientX: 120, clientY: 50, pointerType: "touch" }));
    const pinchedParts = (svg.getAttribute("viewBox") ?? "").split(/\s+/).map(Number);
    expect(pinchedParts[2]).toBeLessThan(200);
    expect(svg.getAttribute("style")).toBeNull();

    ctrl.destroy();
    widget.destroy();
  });

  it("resolves var(--_...) CSS tokens, adds background rect, and strips foreignObject in standalone export", async () => {
    const rendered = await peleDiagramRenderer.render("flowchart LR\n  A[Start] --> B[End]");
    const doc = new DOMParser().parseFromString(rendered.svg, "image/svg+xml");
    const svgEl = document.importNode(doc.documentElement, true) as unknown as SVGSVGElement;
    // Inject a hostile foreignObject directly to prove export strips it too.
    const fo = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
    fo.textContent = "bad";
    svgEl.appendChild(fo);
    host.appendChild(svgEl);

    const standalone = resolveSvgForStandaloneExport(svgEl, host);
    expect(standalone).not.toContain("var(--");
    expect(standalone).not.toMatch(/<foreignObject/i);
    expect(standalone).toContain('xmlns="http://www.w3.org/2000/svg"');

    const exportedDoc = new DOMParser().parseFromString(standalone, "image/svg+xml");
    const firstRect = exportedDoc.documentElement.firstElementChild;
    expect(firstRect?.localName.toLowerCase()).toBe("rect");
    expect(firstRect?.getAttribute("fill")).toMatch(/^#/);
  });

  it("rasterizes standalone SVG to 2x PNG blob and copies image/png ClipboardItem", async () => {
    const rendered = await peleDiagramRenderer.render("flowchart LR\n  A --> B");
    const doc = new DOMParser().parseFromString(rendered.svg, "image/svg+xml");
    const svgEl = document.importNode(doc.documentElement, true) as unknown as SVGSVGElement;
    host.appendChild(svgEl);

    let capturedSrc = "";
    class FakeImage {
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      set src(val: string) {
        capturedSrc = val;
        queueMicrotask(() => this.onload?.());
      }
    }
    vi.stubGlobal("Image", FakeImage);

    const drawImage = vi.fn();
    const fakePng = new Blob([new Uint8Array([137, 80, 78, 71])], { type: "image/png" });
    const origCreateElement = document.createElement.bind(document);
    let createdCanvasWidth = 0;
    let createdCanvasHeight = 0;

    vi.spyOn(document, "createElement").mockImplementation((tagName: string) => {
      const el = origCreateElement(tagName);
      if (tagName.toLowerCase() === "canvas") {
        const canvas = el as HTMLCanvasElement;
        canvas.getContext = (() => ({ drawImage })) as unknown as typeof canvas.getContext;
        canvas.toBlob = ((cb: BlobCallback) => {
          createdCanvasWidth = canvas.width;
          createdCanvasHeight = canvas.height;
          cb(fakePng);
        }) as unknown as typeof canvas.toBlob;
      }
      return el;
    });

    const blob = await svgToPngBlob(svgEl, 2, host);
    expect(blob.type).toBe("image/png");
    expect(blob.size).toBeGreaterThan(0);
    expect(capturedSrc.startsWith("data:image/svg+xml;charset=utf-8,")).toBe(true);
    expect(drawImage).toHaveBeenCalledTimes(1);
    expect(createdCanvasWidth).toBe(Math.ceil(rendered.width * 2));
    expect(createdCanvasHeight).toBe(Math.ceil(rendered.height * 2));

    const write = vi.fn().mockResolvedValue(undefined);
    class FakeClipboardItem {
      constructor(public readonly items: Record<string, Blob>) {}
    }
    vi.stubGlobal("ClipboardItem", FakeClipboardItem);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { write },
    });

    const copied = await copyDiagramPng(svgEl, host);
    expect(copied.size).toBe(fakePng.size);
    expect(write).toHaveBeenCalledTimes(1);
    const items = (write.mock.calls[0][0] as FakeClipboardItem[])[0].items;
    expect(items["image/png"]).toBe(fakePng);
  });
});

describe("computeLineDiff", () => {
  it("handles empty inputs and identical text", () => {
    expect(computeLineDiff("", "")).toEqual([]);
    expect(computeLineDiff("a\nb", "a\nb")).toEqual([
      { kind: "context", oldLine: 1, newLine: 1, text: "a" },
      { kind: "context", oldLine: 2, newLine: 2, text: "b" },
    ]);
  });

  it("computes additions, deletions, and modifications with accurate line numbers", () => {
    expect(computeLineDiff("", "x\ny")).toEqual([
      { kind: "add", oldLine: null, newLine: 1, text: "x" },
      { kind: "add", oldLine: null, newLine: 2, text: "y" },
    ]);

    expect(computeLineDiff("x\ny", "")).toEqual([
      { kind: "del", oldLine: 1, newLine: null, text: "x" },
      { kind: "del", oldLine: 2, newLine: null, text: "y" },
    ]);

    const diff = computeLineDiff("a\nb\nc\nd", "a\nb2\nc\ne\nd");
    expect(diff).toEqual([
      { kind: "context", oldLine: 1, newLine: 1, text: "a" },
      { kind: "del", oldLine: 2, newLine: null, text: "b" },
      { kind: "add", oldLine: null, newLine: 2, text: "b2" },
      { kind: "context", oldLine: 3, newLine: 3, text: "c" },
      { kind: "add", oldLine: null, newLine: 4, text: "e" },
      { kind: "context", oldLine: 4, newLine: 5, text: "d" },
    ]);
  });

  it("normalizes CRLF and safely handles large differing inputs > 2000 lines", () => {
    const crlfDiff = computeLineDiff("a\r\nb", "a\nc");
    expect(crlfDiff).toEqual([
      { kind: "context", oldLine: 1, newLine: 1, text: "a" },
      { kind: "del", oldLine: 2, newLine: null, text: "b" },
      { kind: "add", oldLine: null, newLine: 2, text: "c" },
    ]);

    const oldLines = ["head", ...Array.from({ length: 2100 }, (_, i) => `old-${i}`), "tail"];
    const newLines = ["head", ...Array.from({ length: 2100 }, (_, i) => `new-${i}`), "tail"];
    const bigDiff = computeLineDiff(oldLines.join("\n"), newLines.join("\n"));

    expect(bigDiff[0]).toEqual({ kind: "context", oldLine: 1, newLine: 1, text: "head" });
    expect(bigDiff[bigDiff.length - 1]).toEqual({
      kind: "context",
      oldLine: 2102,
      newLine: 2102,
      text: "tail",
    });

    const reconstructedOld = bigDiff.filter((d) => d.kind !== "add").map((d) => d.text);
    const reconstructedNew = bigDiff.filter((d) => d.kind !== "del").map((d) => d.text);
    expect(reconstructedOld).toEqual(oldLines);
    expect(reconstructedNew).toEqual(newLines);
  });
});
