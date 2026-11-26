import { getLocale, setLocale, subscribeLocale, t, type Locale } from "../i18n";
import { createIcon, type IconName } from "../icons";
import {
  getThemeSnapshot,
  initTheme,
  setThemePreference,
  subscribeTheme,
  type ThemePreference,
  type ThemeSnapshot,
} from "../theme";

export interface ThemeMenuHandle {
  readonly element: HTMLElement;
  refreshLocale(): void;
  destroy(): void;
}

export interface LocaleSwitchHandle {
  readonly element: HTMLElement;
  refreshLocale(): void;
  destroy(): void;
}

const THEME_OPTIONS: readonly { readonly value: ThemePreference; readonly icon: IconName }[] = [
  { value: "system", icon: "monitor" },
  { value: "light", icon: "sun" },
  { value: "dark", icon: "moon" },
];

function iconForPreference(pref: ThemePreference): IconName {
  switch (pref) {
    case "light":
      return "sun";
    case "dark":
      return "moon";
    case "system":
      return "monitor";
    default: {
      const _exhaustive: never = pref;
      return _exhaustive;
    }
  }
}

function labelForOption(pref: ThemePreference, snap: ThemeSnapshot): string {
  switch (pref) {
    case "system":
      return snap.systemTheme === "dark" ? t("theme.systemDark") : t("theme.systemLight");
    case "light":
      return t("theme.light");
    case "dark":
      return t("theme.dark");
    default: {
      const _exhaustive: never = pref;
      return _exhaustive;
    }
  }
}

export function createThemeMenu(opts: { idPrefix?: string } = {}): ThemeMenuHandle {
  const prefix = opts.idPrefix ?? "";
  const triggerId = `${prefix}theme-trigger`;
  const menuId = `${prefix}theme-menu`;

  let snapshot = initTheme();

  const anchor = document.createElement("div");
  anchor.className = "popover-anchor";

  const trigger = document.createElement("button");
  trigger.id = triggerId;
  trigger.type = "button";
  trigger.className = "btn btn-chrome theme-trigger";
  trigger.setAttribute("aria-haspopup", "menu");
  trigger.setAttribute("aria-expanded", "false");
  trigger.setAttribute("commandfor", menuId);
  trigger.setAttribute("command", "toggle-popover");
  trigger.dataset.testid = triggerId;

  const triggerIconSlot = document.createElement("span");
  triggerIconSlot.className = "theme-trigger-icon";
  const chevronIcon = createIcon("chevron-down", "xs", "theme-trigger-chevron");
  const triggerSrLabel = document.createElement("span");
  triggerSrLabel.className = "sr-only";
  trigger.append(triggerIconSlot, chevronIcon, triggerSrLabel);

  const menuEl = document.createElement("div");
  menuEl.id = menuId;
  menuEl.className = "theme-popover";
  menuEl.setAttribute("popover", "auto");
  menuEl.dataset.testid = menuId;

  const menuList = document.createElement("div");
  menuList.className = "menu-list";
  menuList.setAttribute("focusgroup", "menu nomemory");
  menuList.setAttribute("aria-labelledby", triggerId);

  const group = document.createElement("div");
  group.setAttribute("role", "group");

  const itemButtons = new Map<
    ThemePreference,
    { button: HTMLButtonElement; labelSpan: HTMLSpanElement }
  >();

  for (const opt of THEME_OPTIONS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "menu-item";
    btn.setAttribute("role", "menuitemradio");
    btn.setAttribute("aria-checked", "false");
    btn.dataset.themeOption = opt.value;
    btn.dataset.testid = `${prefix}theme-opt-${opt.value}`;

    const icon = createIcon(opt.icon, "sm", "menu-item-icon");
    const labelSpan = document.createElement("span");
    labelSpan.className = "menu-item-label";
    btn.append(icon, labelSpan);

    itemButtons.set(opt.value, { button: btn, labelSpan });
    group.appendChild(btn);
  }

  menuList.appendChild(group);
  menuEl.appendChild(menuList);
  // Keep popover directly after its trigger so browsers emit no implicit aria-details.
  anchor.append(trigger, menuEl);

  const supportsPopover =
    typeof HTMLElement !== "undefined" &&
    "popover" in HTMLElement.prototype &&
    typeof (menuEl as HTMLElement & { showPopover?: unknown }).showPopover === "function" &&
    typeof (menuEl as HTMLElement & { hidePopover?: unknown }).hidePopover === "function";
  const supportsInvoker =
    typeof HTMLButtonElement !== "undefined" && "commandForElement" in HTMLButtonElement.prototype;
  const supportsFocusGroup =
    typeof HTMLElement !== "undefined" && "focusGroup" in HTMLElement.prototype;

  if (!supportsPopover) {
    menuEl.classList.add("popover-fallback");
  }
  if (!supportsFocusGroup) {
    menuList.setAttribute("role", "menu");
  }

  let fallbackOpen = false;
  let enterOnOpen = false;
  let pointerTriggered = false;
  let itemPointerTriggered = false;

  const isMenuOpen = (): boolean => {
    if (supportsPopover) {
      try {
        return menuEl.matches(":popover-open");
      } catch {
        return trigger.getAttribute("aria-expanded") === "true";
      }
    }
    return fallbackOpen;
  };

  const focusCheckedOrFirst = (): void => {
    const items = [...itemButtons.values()].map((x) => x.button);
    const checked = items.find((b) => b.getAttribute("aria-checked") === "true");
    (checked ?? items[0])?.focus({ preventScroll: true });
  };

  const openMenu = (fromKeyboard: boolean): void => {
    enterOnOpen = fromKeyboard;
    if (supportsPopover) {
      if (!isMenuOpen()) {
        try {
          (
            menuEl as HTMLElement & { showPopover(opts?: { source?: HTMLElement }): void }
          ).showPopover({ source: trigger });
        } catch {
          (menuEl as HTMLElement & { showPopover(): void }).showPopover();
        }
        trigger.setAttribute("aria-expanded", "true");
      } else if (fromKeyboard) {
        focusCheckedOrFirst();
      }
    } else {
      fallbackOpen = true;
      menuEl.dataset.open = "true";
      menuEl.classList.add("is-open");
      trigger.setAttribute("aria-expanded", "true");
      if (fromKeyboard) {
        focusCheckedOrFirst();
      }
    }
  };

  const closeMenu = (restoreFocus: boolean): void => {
    if (supportsPopover) {
      if (isMenuOpen()) {
        (menuEl as HTMLElement & { hidePopover(): void }).hidePopover();
      }
      trigger.setAttribute("aria-expanded", "false");
    } else if (fallbackOpen) {
      fallbackOpen = false;
      delete menuEl.dataset.open;
      menuEl.classList.remove("is-open");
      trigger.setAttribute("aria-expanded", "false");
    }
    if (restoreFocus) {
      trigger.focus({ preventScroll: true });
    } else if (document.activeElement === trigger) {
      trigger.blur();
    }
  };

  const toggleMenuFallback = (fromKeyboard: boolean): void => {
    if (isMenuOpen()) {
      closeMenu(fromKeyboard);
    } else {
      openMenu(fromKeyboard);
    }
  };

  const syncVisuals = (): void => {
    triggerIconSlot.replaceChildren(createIcon(iconForPreference(snapshot.preference), "sm"));
    const label = t("theme.triggerLabel");
    triggerSrLabel.textContent = label;
    trigger.title = `${label}: ${labelForOption(snapshot.preference, snapshot)}`;
    group.setAttribute("aria-label", t("theme.groupLabel"));

    for (const [pref, entry] of itemButtons.entries()) {
      entry.button.setAttribute("aria-checked", String(snapshot.preference === pref));
      entry.labelSpan.textContent = labelForOption(pref, snapshot);
    }
  };

  syncVisuals();

  const onTriggerPointerDown = (): void => {
    pointerTriggered = true;
  };

  const onTriggerClick = (): void => {
    const fromKeyboard = !pointerTriggered;
    pointerTriggered = false;
    if (supportsPopover) {
      enterOnOpen = fromKeyboard;
      if (!supportsInvoker) {
        toggleMenuFallback(fromKeyboard);
      }
    } else {
      toggleMenuFallback(fromKeyboard);
    }
  };

  const onTriggerKeyDown = (ev: KeyboardEvent): void => {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      openMenu(true);
    } else if (ev.key === "Escape" && isMenuOpen()) {
      ev.preventDefault();
      closeMenu(true);
    }
  };

  const onMenuToggle = (ev: Event): void => {
    const newState = (ev as Event & { newState?: string }).newState;
    const opened = newState === "open";
    trigger.setAttribute("aria-expanded", String(opened));
    if (opened && enterOnOpen) {
      enterOnOpen = false;
      focusCheckedOrFirst();
    } else if (!opened) {
      enterOnOpen = false;
    }
  };

  const onMenuKeyDown = (ev: KeyboardEvent): void => {
    if (ev.key === "Escape") {
      ev.preventDefault();
      ev.stopPropagation();
      closeMenu(true);
      return;
    }
    if (ev.key === "Tab") {
      closeMenu(false);
      return;
    }
    if (!supportsFocusGroup && ["ArrowDown", "ArrowUp", "Home", "End"].includes(ev.key)) {
      const items = [...itemButtons.values()].map((x) => x.button);
      const current = items.indexOf(document.activeElement as HTMLButtonElement);
      const nextIdx =
        ev.key === "Home"
          ? 0
          : ev.key === "End"
            ? items.length - 1
            : current < 0
              ? 0
              : (current + (ev.key === "ArrowUp" ? -1 : 1) + items.length) % items.length;
      ev.preventDefault();
      ev.stopPropagation();
      items[nextIdx]?.focus({ preventScroll: true });
    }
  };

  const onDocPointerDown = (ev: PointerEvent): void => {
    if (!fallbackOpen) return;
    if (ev.target instanceof Node && !anchor.contains(ev.target)) {
      closeMenu(false);
    }
  };

  const onDocFocusIn = (ev: FocusEvent): void => {
    if (!isMenuOpen()) return;
    if (ev.target instanceof Node && !anchor.contains(ev.target)) {
      closeMenu(false);
    }
  };

  trigger.addEventListener("pointerdown", onTriggerPointerDown);
  trigger.addEventListener("click", onTriggerClick);
  trigger.addEventListener("keydown", onTriggerKeyDown);
  menuEl.addEventListener("toggle", onMenuToggle);
  menuList.addEventListener("keydown", onMenuKeyDown);
  document.addEventListener("focusin", onDocFocusIn);
  if (!supportsPopover) {
    document.addEventListener("pointerdown", onDocPointerDown);
  }

  for (const [pref, entry] of itemButtons.entries()) {
    entry.button.addEventListener("pointerdown", () => {
      itemPointerTriggered = true;
    });
    entry.button.addEventListener("click", () => {
      const fromKeyboard = !itemPointerTriggered;
      itemPointerTriggered = false;
      snapshot = setThemePreference(pref);
      syncVisuals();
      closeMenu(fromKeyboard);
    });
  }

  const unsubTheme = subscribeTheme((nextSnap) => {
    snapshot = nextSnap;
    syncVisuals();
  });

  return {
    element: anchor,
    refreshLocale(): void {
      snapshot = getThemeSnapshot();
      syncVisuals();
    },
    destroy(): void {
      unsubTheme();
      trigger.removeEventListener("pointerdown", onTriggerPointerDown);
      trigger.removeEventListener("click", onTriggerClick);
      trigger.removeEventListener("keydown", onTriggerKeyDown);
      menuEl.removeEventListener("toggle", onMenuToggle);
      menuList.removeEventListener("keydown", onMenuKeyDown);
      document.removeEventListener("focusin", onDocFocusIn);
      if (!supportsPopover) {
        document.removeEventListener("pointerdown", onDocPointerDown);
      }
    },
  };
}

export function createLocaleSwitch(opts: { idPrefix?: string } = {}): LocaleSwitchHandle {
  const prefix = opts.idPrefix ?? "";

  const group = document.createElement("div");
  group.className = "lang-seg";
  group.setAttribute("role", "group");
  group.dataset.testid = `${prefix}lang-switch`;

  const locales: readonly { readonly value: Locale; readonly label: string }[] = [
    { value: "zh-CN", label: "中文" },
    { value: "en", label: "EN" },
  ];

  const buttons = new Map<Locale, HTMLButtonElement>();
  for (const item of locales) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "lang-seg-btn";
    btn.textContent = item.label;
    btn.dataset.locale = item.value;
    btn.dataset.testid = `${prefix}lang-opt-${item.value}`;
    btn.addEventListener("click", () => {
      if (getLocale() !== item.value) {
        setLocale(item.value);
      }
    });
    buttons.set(item.value, btn);
    group.appendChild(btn);
  }

  const syncVisuals = (): void => {
    const active = getLocale();
    group.setAttribute("aria-label", t("lang.label"));
    for (const [loc, btn] of buttons.entries()) {
      btn.setAttribute("aria-pressed", String(loc === active));
    }
  };

  syncVisuals();
  const unsubLocale = subscribeLocale(() => {
    syncVisuals();
  });

  return {
    element: group,
    refreshLocale(): void {
      syncVisuals();
    },
    destroy(): void {
      unsubLocale();
    },
  };
}
