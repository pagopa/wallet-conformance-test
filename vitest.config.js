import * as path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "#": path.resolve(import.meta.dirname, "./tests"),
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  test: {
    globalSetup: "./tests/global-setup.ts",
    hookTimeout: 120000,
    setupFiles: ["./tests/setup-tls.ts"],
  },
});
