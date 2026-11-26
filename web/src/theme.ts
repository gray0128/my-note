export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

export interface ThemeSnapshot {
  readonly preference: ThemePreference;
  readonly systemTheme: ResolvedTheme;
  readonly resolved: ResolvedTheme;
}

export const THEME_STORAGE_KEY = "color-scheme";
export const THEME_COLOR_LIGHT = "#FAF8F4";
export const THEME_COLOR_DARK = "#171614";

type ThemeListener = (snapshot: ThemeSnapshot) => void;

const DARK_MEDIA_QUERY = "(prefers-color-scheme: dark)";

const listeners = new Set<ThemeListener>();
let memoryPreference: ThemePreference = "system";
let storageListenerBound = false;
let boundMql: MediaQueryList | null = null;

function parseStoredTheme(raw: unknown): ThemePreference {
  if (raw === "light" || raw === "dark") return raw;
  return "system";
}

function getSafeLocalStorage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    const store = window.localStorage;
    if (
      store &&
      typeof store.getItem === "function" &&
      typeof store.setItem === "function" &&
      typeof store.removeItem === "function"
    ) {
      return store;
    }
  } catch {
    // Storage access blocked
  }
  return null;
}

function readStoredPreference(): ThemePreference {
  const store = getSafeLocalStorage();
  if (!store) return memoryPreference;
  try {
    return parseStoredTheme(store.getItem(THEME_STORAGE_KEY));
  } catch {
    return memoryPreference;
  }
}

export function getSystemTheme(): ResolvedTheme {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return "light";
  }
  return window.matchMedia(DARK_MEDIA_QUERY).matches ? "dark" : "light";
}

export function getThemePreference(): ThemePreference {
  if (typeof window === "undefined") return "system";
  return readStoredPreference();
}

export function getResolvedTheme(): ResolvedTheme {
  const pref = getThemePreference();
  return pref === "system" ? getSystemTheme() : pref;
}

export function getThemeSnapshot(): ThemeSnapshot {
  const preference = getThemePreference();
  const systemTheme = getSystemTheme();
  const resolved: ResolvedTheme = preference === "system" ? systemTheme : preference;
  return { preference, systemTheme, resolved };
}

function upsertHeadMeta(name: string, content: string): void {
  if (typeof document === "undefined") return;
  let meta = document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`);
  if (!meta && document.head) {
    meta = document.createElement("meta");
    meta.name = name;
    document.head.appendChild(meta);
  }
  if (meta) {
    meta.setAttribute("content", content);
  }
}

function applyThemeToDocument(snapshot: ThemeSnapshot): void {
  if (typeof document === "undefined") return;
  const schemeContent = snapshot.preference === "system" ? "light dark" : snapshot.preference;
  const themeAttr = snapshot.preference === "system" ? "auto" : snapshot.preference;

  upsertHeadMeta("color-scheme", schemeContent);
  document.documentElement.dataset.theme = themeAttr;
  upsertHeadMeta("theme-color", snapshot.resolved === "dark" ? THEME_COLOR_DARK : THEME_COLOR_LIGHT);
}

function notifyListeners(snapshot: ThemeSnapshot): void {
  for (const fn of [...listeners]) {
    fn(snapshot);
  }
}

const onMediaChange = (): void => {
  // Never clear or modify an explicit stored override when the OS switches themes.
  const snapshot = getThemeSnapshot();
  applyThemeToDocument(snapshot);
  notifyListeners(snapshot);
};

const onWindowStorage = (ev: StorageEvent): void => {
  if (ev.key !== null && ev.key !== THEME_STORAGE_KEY) return;
  const snapshot = getThemeSnapshot();
  memoryPreference = snapshot.preference;
  applyThemeToDocument(snapshot);
  notifyListeners(snapshot);
};

function ensureGlobalListeners(): void {
  if (typeof window === "undefined") return;

  if (!storageListenerBound) {
    window.addEventListener("storage", onWindowStorage);
    storageListenerBound = true;
  }

  if (typeof window.matchMedia === "function") {
    const nextMql = window.matchMedia(DARK_MEDIA_QUERY);
    if (nextMql && nextMql !== boundMql) {
      if (boundMql) {
        if (typeof boundMql.removeEventListener === "function") {
          boundMql.removeEventListener("change", onMediaChange);
        } else if (typeof boundMql.removeListener === "function") {
          boundMql.removeListener(onMediaChange);
        }
      }
      boundMql = nextMql;
      if (typeof boundMql.addEventListener === "function") {
        boundMql.addEventListener("change", onMediaChange);
      } else if (typeof boundMql.addListener === "function") {
        boundMql.addListener(onMediaChange);
      }
    }
  }
}

export function initTheme(): ThemeSnapshot {
  ensureGlobalListeners();
  const snapshot = getThemeSnapshot();
  applyThemeToDocument(snapshot);
  return snapshot;
}

export function setThemePreference(preference: ThemePreference): ThemeSnapshot {
  ensureGlobalListeners();
  memoryPreference = preference;
  const store = getSafeLocalStorage();
  if (store) {
    try {
      if (preference === "system") {
        store.removeItem(THEME_STORAGE_KEY);
      } else {
        store.setItem(THEME_STORAGE_KEY, preference);
      }
    } catch {
      // Storage blocked: keep in-memory preference and still update document
    }
  }

  const systemTheme = getSystemTheme();
  const resolved: ResolvedTheme = preference === "system" ? systemTheme : preference;
  const snapshot: ThemeSnapshot = { preference, systemTheme, resolved };
  applyThemeToDocument(snapshot);
  notifyListeners(snapshot);
  return snapshot;
}

export function subscribeTheme(fn: ThemeListener): () => void {
  ensureGlobalListeners();
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}
