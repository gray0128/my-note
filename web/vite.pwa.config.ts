import { defineConfig } from "vite";

export default defineConfig({
  base: "/",
  publicDir: "public-pwa",
  plugins: [
    {
      name: "rename-pwa-html-to-index",
      enforce: "post",
      generateBundle(_options, bundle) {
        const entry = bundle["pwa.html"];
        if (entry) {
          entry.fileName = "index.html";
          bundle["index.html"] = entry;
          delete bundle["pwa.html"];
        }
      },
    },
  ],
  build: {
    outDir: "dist-pwa",
    emptyOutDir: true,
    target: "es2022",
    sourcemap: false,
    rollupOptions: {
      input: "pwa.html",
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/pele")) return "pele";
          return undefined;
        },
      },
    },
  },
});
