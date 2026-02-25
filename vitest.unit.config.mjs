import * as path from "node:path";
import * as tls from "node:tls"

import { configDefaults, defineConfig } from "vitest/config";

/**
 * Set the node certificates to the system ones
 */
tls.setDefaultCACertificates(tls.getCACertificates('system'))

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
