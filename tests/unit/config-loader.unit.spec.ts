import { describe, expect, it } from "vitest";

import {
  loadConfigWithHierarchy,
  readPackageVersion,
} from "@/logic/config-loader";

const DEFAULT_INI = "./config.example.ini";

describe("loadConfigWithHierarchy – user_agent", () => {
  it("should always set user_agent to CEN-TC-Wallet-CLI/<version> from package.json", () => {
    const config = loadConfigWithHierarchy({}, DEFAULT_INI);
    expect(config.network.user_agent).toBe(
      `CEN-TC-Wallet-CLI/${readPackageVersion()}`,
    );
  });
});
