// my-note Mobile Read-Only PWA Service Worker
// SEC-08 HARD INVARIANT: Cache ONLY static app shell assets (HTML/JS/CSS/WASM/icons).
// NEVER cache `/v1/*` API calls, snapshots, keys, or auth responses!

const CACHE_NAME = "mynote-pwa-shell-v2";
const SHELL_PATHS = ["/", "/manifest.webmanifest", "/icon.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_PATHS)));
});

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    void self.skipWaiting();
  }
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // NEVER intercept or cache API routes (`/v1/*`)
  if (url.pathname.startsWith("/v1/")) return;

  const isHashedAsset = url.pathname.startsWith("/assets/");
  const isShellPath =
    url.pathname === "/" ||
    url.pathname === "/index.html" ||
    url.pathname === "/manifest.webmanifest" ||
    url.pathname === "/icon.svg";
  if (!isHashedAsset && !isShellPath) return;

  event.respondWith(
    caches.match(req).then((cached) => {
      // Serve cached shell/assets deterministically; NEVER silently overwrite `/` in the active cache
      // (updates take effect only when a new Service Worker is explicitly activated by the user).
      if (cached) return cached;
      return fetch(req)
        .then((res) => {
          if (res.ok && res.type === "basic") {
            const copy = res.clone();
            void caches.open(CACHE_NAME).then((c) => c.put(req, copy));
          }
          return res;
        })
        .catch(
          () =>
            new Response("Offline — asset not cached", {
              status: 503,
              headers: { "content-type": "text/plain; charset=utf-8" },
            }),
        );
    }),
  );
});
