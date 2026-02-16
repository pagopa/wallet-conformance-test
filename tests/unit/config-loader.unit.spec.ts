import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { loadConfigWithHierarchy } from "@/logic/config-loader";

const DEFAULT_INI = "./config.ini";

function getPackageVersion(): string {
  const pkg = JSON.parse(readFileSync("./package.json", "utf-8")) as {
    version?: string;
  };
  return pkg.version ?? "0.0.0";
}

describe("loadConfigWithHierarchy – user_agent", () => {
  it("should always set user_agent to CEN-TC-Wallet-CLI/<version> from package.json", () => {
    const config = loadConfigWithHierarchy({}, DEFAULT_INI);
    expect(config.network.user_agent).toBe(
      `CEN-TC-Wallet-CLI/${getPackageVersion()}`,
    );
  });
});
