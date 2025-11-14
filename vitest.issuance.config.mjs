import * as path from "node:path";

import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    exclude: configDefaults.exclude,
    include: ["**/*.issuance.spec.ts"],
  },
});
