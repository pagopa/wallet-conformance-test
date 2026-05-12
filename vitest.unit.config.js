import * as path from "node:path";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "#": path.resolve(import.meta.dirname, "./tests"),
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  test: {
    exclude: configDefaults.exclude,
    globalSetup: "./tests/global-setup.ts",
    include: ["**/*.unit.spec.ts"],
    setupFiles: ["./tests/setup-tls.ts"],
  },
});
