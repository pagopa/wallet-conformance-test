import { describe, expect, it } from "vitest";

import { resolveCredentialScope } from "@/logic";

describe("resolveCredentialScope", () => {
  const configs = {
    dc_sd_jwt_mDL: { scope: "mDL" },
    dc_sd_jwt_pid: { scope: "pid" },
    no_scope: {},
  };

  it("returns the scope the issuer advertises for the configuration", () => {
    expect(resolveCredentialScope(["dc_sd_jwt_pid"], configs)).toBe("pid");
  });

  it("joins the scopes of several configurations with a space", () => {
    expect(
      resolveCredentialScope(["dc_sd_jwt_pid", "dc_sd_jwt_mDL"], configs),
    ).toBe("pid mDL");
  });

  it("returns undefined when no requested configuration has a scope", () => {
    expect(resolveCredentialScope(["no_scope"], configs)).toBeUndefined();
    expect(resolveCredentialScope(["unknown"], configs)).toBeUndefined();
    expect(
      resolveCredentialScope(["dc_sd_jwt_pid"], undefined),
    ).toBeUndefined();
  });
});
