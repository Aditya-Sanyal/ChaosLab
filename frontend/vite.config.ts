import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const apiProxyTarget =
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
    ?.VITE_API_TARGET ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": {
        target: apiProxyTarget,
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    exclude: ["e2e/**", "node_modules/**"],
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          const normId = id.replace(/\\/g, "/");
          if (normId.includes("node_modules/cytoscape")) {
            return "cytoscape";
          }
          if (
            normId.includes("node_modules/react") ||
            normId.includes("node_modules/react-dom") ||
            normId.includes("node_modules/@tanstack/react-query") ||
            normId.includes("node_modules/lucide-react")
          ) {
            return "vendor";
          }
          return undefined;
        },
      },
    },
  },
});
