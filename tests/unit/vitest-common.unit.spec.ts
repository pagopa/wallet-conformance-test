import { describe, expect, it } from "vitest";

import { buildIncludePattern } from "../../vitest.common.js";

describe("buildIncludePattern", () => {
  it("normalizes Windows paths before building the Vitest glob", () => {
    const includePattern = buildIncludePattern(
      "issuance",
      "D:\\a\\wallet-conformance-test\\wallet-conformance-test\\tests\\conformance\\issuance",
      false,
    );

    expect(includePattern).toBe(
      "D:/a/wallet-conformance-test/wallet-conformance-test/tests/conformance/issuance/**/*.issuance.spec.ts",
    );
  });

  it("keeps user-configured directories compatible with both ts and js tests", () => {
    const includePattern = buildIncludePattern(
      "presentation",
      "D:\\custom\\presentation-tests",
      true,
    );

    expect(includePattern).toBe(
      "D:/custom/presentation-tests/**/*.presentation.spec.{js,ts}",
    );
  });
});
