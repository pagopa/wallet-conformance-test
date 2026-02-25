import * as path from "node:path";

import { configDefaults, defineConfig } from "vitest/config";
import "./vitest.global.setup.mjs";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      "#": path.resolve(__dirname, "./tests")
    },
  },
  test: {
    exclude: configDefaults.exclude,
    include: ["**/*.unit.spec.ts"],
  },
});
