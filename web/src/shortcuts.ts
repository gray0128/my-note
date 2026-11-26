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
