import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In development, run xcp-api with packaging/dev/xcp.toml and open
// http://localhost:5173. The proxy keeps the browser's Host header
// (changeOrigin: false), so xcp-api's same-origin check sees matching
// Origin and Host values.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:2443", changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // No inline scripts or styles, so the strict CSP (script-src 'self') holds.
    assetsInlineLimit: 0,
  },
});
