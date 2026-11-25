import { defineConfig } from "vite";

export default defineConfig({
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/pele")) return "pele";
          if (id.includes("@replit/codemirror-vim")) return "cm-vim";
          const langMatch = id.match(/@codemirror\/lang-([a-z]+)/) ?? id.match(/@lezer\/(json|javascript|markdown|python|rust|html|css|xml|yaml)/);
          if (langMatch) return `lang-${langMatch[1]}`;
          if (id.includes("@codemirror/state") || id.includes("@codemirror/view") || id.includes("@codemirror/commands") || id.includes("@codemirror/language") || id.includes("@lezer/common") || id.includes("@lezer/highlight") || id.includes("@lezer/lr")) {
            return "cm-core";
          }
          return undefined;
        },
      },
    },
  },
  test: {
    environment: "happy-dom",
  },
});
