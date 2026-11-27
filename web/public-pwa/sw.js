// my-note Mobile PWA Service Worker
// SEC-08 HARD INVARIANT: Cache ONLY static app shell assets (HTML/JS/CSS/WASM/icons).
// NEVER cache `/v1/*` API calls, snapshots, keys, or auth responses!
// Android Web Share Target (`POST /clip-share`) stores shared payload transiently in
// `mynote-share-handoff`, which the main PWA page deletes immediately after consumption.

const CACHE_NAME = "mynote-pwa-shell-v5";
const SHARE_HANDOFF_CACHE = "mynote-share-handoff";
const SHARE_HANDOFF_URL = "/__share-handoff/latest";
const SHELL_PATHS = ["/", "/theme-init.js", "/manifest.webmanifest", "/icon.svg"];
const ALLOWED_SHARE_IMAGE_MIMES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

function normalizeMime(raw) {
  return String(raw || "").split(";")[0].trim().toLowerCase();
}

async function handleClipShareTarget(req) {
  try {
    const form = await req.formData();
    const file = form.get("image");
    const cache = await caches.open(SHARE_HANDOFF_CACHE);

    if (file && typeof file === "object" && typeof file.arrayBuffer === "function" && file.size > 0) {
      const mime = normalizeMime(file.type);
      if (!ALLOWED_SHARE_IMAGE_MIMES.has(mime)) {
        await cache.put(
          SHARE_HANDOFF_URL,
          new Response(JSON.stringify({ kind: "error", code: "DISALLOWED_MIME", mime: mime || "unknown" }), {
            headers: {
              "content-type": "application/json; charset=utf-8",
              "x-share-kind": "error",
            },
          }),
        );
        return Response.redirect("/?clip_share=1", 303);
      }
      const bytes = await file.arrayBuffer();
      await cache.put(
        SHARE_HANDOFF_URL,
        new Response(bytes, {
          headers: {
            "content-type": mime,
            "x-share-kind": "image",
            "x-share-filename": encodeURIComponent(String(file.name || "shared-image")),
          },
        }),
      );
      return Response.redirect("/?clip_share=1", 303);
    }

    const title = String(form.get("title") || "").trim();
    const text = String(form.get("text") || "").trim();
    const sharedUrl = String(form.get("url") || "").trim();
    const parts = [];
    if (title && !text.includes(title)) parts.push(title);
    if (text) parts.push(text);
    if (sharedUrl && !text.includes(sharedUrl)) parts.push(sharedUrl);
    const combined = parts.join("\n").trim();

    await cache.put(
      SHARE_HANDOFF_URL,
      new Response(JSON.stringify({ kind: "text", text: combined }), {
        headers: {
          "content-type": "application/json; charset=utf-8",
          "x-share-kind": "text",
        },
      }),
    );
    return Response.redirect("/?clip_share=1", 303);
  } catch {
    return Response.redirect("/?clip_share=1", 303);
  }
}

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
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Android Web Share Target transient handoff (strictly rejects non-bitmap images such as SVG)
  if (req.method === "POST" && url.pathname === "/clip-share") {
    event.respondWith(handleClipShareTarget(req));
    return;
  }

  if (req.method !== "GET") return;
  // NEVER intercept or cache API routes (`/v1/*`)
  if (url.pathname.startsWith("/v1/")) return;

  const isHashedAsset = url.pathname.startsWith("/assets/");
  const isShellPath =
    url.pathname === "/" ||
    url.pathname === "/index.html" ||
    url.pathname === "/theme-init.js" ||
    url.pathname === "/manifest.webmanifest" ||
    url.pathname === "/icon.svg";
  if (!isHashedAsset && !isShellPath) return;

  const cacheLookupKey = url.pathname === "/" && url.search ? "/" : req;

  event.respondWith(
    caches.match(cacheLookupKey).then((cached) => {
      // Serve cached shell/assets deterministically; NEVER silently overwrite `/` in the active cache
      // (updates take effect only when a new Service Worker is explicitly activated by the user).
      if (cached) return cached;
      return fetch(req)
        .then((res) => {
          if (res.ok && res.type === "basic" && !(url.pathname === "/" && url.search)) {
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
