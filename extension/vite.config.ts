import { resolve } from "node:path";

import { defineConfig } from "vite";

export default defineConfig({
  build: {
    target: "chrome116",
    sourcemap: false,
    modulePreload: { polyfill: false },
    emptyOutDir: true,
    rollupOptions: {
      input: {
        sidepanel: resolve(import.meta.dirname, "sidepanel.html"),
        background: resolve(import.meta.dirname, "src/background/index.ts"),
      },
      output: {
        entryFileNames: "assets/[name].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});
