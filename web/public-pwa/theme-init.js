(() => {
  const docEl = document.documentElement;
  let storedTheme = null;
  let storedLocale = null;
  try {
    storedTheme = localStorage.getItem("color-scheme");
    storedLocale =
      localStorage.getItem("mynote.locale") ?? localStorage.getItem("mynote-locale");
  } catch {
    // Storage blocked: degrade gracefully to system defaults
  }

  const scheme =
    storedTheme === "light" || storedTheme === "dark" ? storedTheme : "light dark";
  const themeAttr =
    storedTheme === "light" || storedTheme === "dark" ? storedTheme : "auto";

  const csMeta = document.querySelector('meta[name="color-scheme"]');
  if (csMeta) csMeta.setAttribute("content", scheme);
  docEl.dataset.theme = themeAttr;

  const isDark =
    storedTheme === "dark" ||
    (storedTheme !== "light" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches);

  const tcMeta = document.querySelector('meta[name="theme-color"]');
  if (tcMeta) tcMeta.setAttribute("content", isDark ? "#171614" : "#FAF8F4");

  const locale =
    storedLocale === "zh-CN" || storedLocale === "en"
      ? storedLocale
      : typeof navigator !== "undefined" &&
          typeof navigator.language === "string" &&
          navigator.language.toLowerCase().startsWith("zh")
        ? "zh-CN"
        : "en";
  docEl.lang = locale;
})();
