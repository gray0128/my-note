import { createIcon } from "./icons";

export type ShortcutKeyToken =
  | { readonly kind: "mod" }
  | { readonly kind: "alt" }
  | { readonly kind: "shift" }
  | { readonly kind: "enter" }
  | { readonly kind: "up" }
  | { readonly kind: "down" }
  | { readonly kind: "esc" }
  | { readonly kind: "char"; readonly label: string };

export const SHORTCUT_NEW_BLOCK: readonly ShortcutKeyToken[] = [{ kind: "mod" }, { kind: "enter" }];
export const SHORTCUT_SWITCH_BLOCK_PAIR: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "alt" },
  { kind: "up" },
  { kind: "down" },
];
export const SHORTCUT_MOVE_UP: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "alt" },
  { kind: "shift" },
  { kind: "up" },
];
export const SHORTCUT_MOVE_DOWN: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "alt" },
  { kind: "shift" },
  { kind: "down" },
];
export const SHORTCUT_MOVE_BLOCK_PAIR: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "alt" },
  { kind: "shift" },
  { kind: "up" },
  { kind: "down" },
];
export const SHORTCUT_EDGE_ARROWS: readonly ShortcutKeyToken[] = [{ kind: "up" }, { kind: "down" }];
export const SHORTCUT_SWITCH_BUFFER: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "char", label: "P" },
];
export const SHORTCUT_FIND: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "char", label: "F" },
];
export const SHORTCUT_CLIPBOARD: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "char", label: "\\" },
];
export const SHORTCUT_HELP: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "char", label: "/" },
];
export const SHORTCUT_LANG: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "char", label: "L" },
];
export const SHORTCUT_MARKDOWN_MODE: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "char", label: "E" },
];
export const SHORTCUT_FORMAT: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "shift" },
  { kind: "char", label: "F" },
];
export const SHORTCUT_COPY_BLOCK: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "shift" },
  { kind: "char", label: "C" },
];
export const SHORTCUT_LOCK_VAULT: readonly ShortcutKeyToken[] = [
  { kind: "mod" },
  { kind: "shift" },
  { kind: "char", label: "L" },
];
export const SHORTCUT_ESC: readonly ShortcutKeyToken[] = [{ kind: "esc" }];

export function isMacPlatform(): boolean {
  if (typeof navigator === "undefined") return true;
  const uaData = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData;
  const platform = uaData?.platform ?? navigator.platform ?? navigator.userAgent ?? "";
  return /mac|iphone|ipad|ipod/i.test(platform);
}

function tokenTextLabel(token: ShortcutKeyToken, mac: boolean): string {
  switch (token.kind) {
    case "mod":
      return mac ? "⌘" : "Ctrl";
    case "alt":
      return mac ? "⌥" : "Alt";
    case "shift":
      return mac ? "⇧" : "Shift";
    case "enter":
      return mac ? "↵" : "Enter";
    case "up":
      return "↑";
    case "down":
      return "↓";
    case "esc":
      return "Esc";
    case "char":
      return token.label;
    default: {
      const _exhaustive: never = token;
      return _exhaustive;
    }
  }
}

export function formatShortcutTitle(tokens: readonly ShortcutKeyToken[]): string {
  const mac = isMacPlatform();
  const parts = tokens.map((tok) => tokenTextLabel(tok, mac));
  return mac ? parts.join("") : parts.join("+");
}

function buildKeycap(token: ShortcutKeyToken, mac: boolean): HTMLElement {
  const kbd = document.createElement("kbd");
  kbd.className = "kbd";
  switch (token.kind) {
    case "enter":
      kbd.classList.add("kbd-icon");
      kbd.appendChild(createIcon("corner-down-left", "kbd"));
      return kbd;
    case "up":
      kbd.classList.add("kbd-icon");
      kbd.appendChild(createIcon("arrow-up", "kbd"));
      return kbd;
    case "down":
      kbd.classList.add("kbd-icon");
      kbd.appendChild(createIcon("arrow-down", "kbd"));
      return kbd;
    case "mod":
    case "alt":
    case "shift":
      if (mac) kbd.classList.add("kbd-symbol");
      else kbd.classList.add("kbd-word");
      kbd.textContent = tokenTextLabel(token, mac);
      return kbd;
    case "esc":
      kbd.classList.add("kbd-word");
      kbd.textContent = "Esc";
      return kbd;
    case "char":
      kbd.textContent = token.label;
      return kbd;
    default: {
      const _exhaustive: never = token;
      return _exhaustive;
    }
  }
}

export function createShortcutHint(
  tokens: readonly ShortcutKeyToken[],
  extraClass = "",
): HTMLSpanElement {
  const mac = isMacPlatform();
  const group = document.createElement("span");
  group.className = extraClass ? `kbd-group ${extraClass}` : "kbd-group";
  group.setAttribute("aria-hidden", "true");
  for (const token of tokens) {
    group.appendChild(buildKeycap(token, mac));
  }
  return group;
}
