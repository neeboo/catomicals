import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";

// No Babel plugin: Vite/esbuild handles the TSX automatic JSX runtime
// (see tsconfig "jsx": "react-jsx"). Keeps the dependency graph free of the
// @babel/* subtree and js-tokens.
export default defineConfig({
  plugins: [tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  esbuild: {
    jsx: "automatic",
    jsxImportSource: "react",
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});
