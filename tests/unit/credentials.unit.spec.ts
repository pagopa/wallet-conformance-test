import { ValidationError } from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import { loadCredentials } from "@/functions";

describe("Load Mocked Credentials", async () => {
  it("should load a mix of valid sd-jwt and mdoc credentials", async () => {
    try {
      const credentials = await loadCredentials(
        "tests/mocked-data/credentials",
        ["dc_sd_jwt_PersonIdentificationData", "mso_mdoc_mDL"],
        console.error,
      );
      expect(credentials).toBeDefined();
      expect(Object.keys(credentials).length).toBe(2);
      expect(credentials.dc_sd_jwt_PersonIdentificationData?.typ).toBe(
        "dc+sd-jwt",
      );
      expect(credentials.mso_mdoc_mDL?.typ).toBe("mso_mdoc");
      expect(credentials.unsupported_cred).toBeUndefined();
    } catch (e) {
      if (e instanceof ValidationError) {
        console.error("Schema validation failed");
        expect
          .soft(
            e.message.replace(": ", ":\n\t").replace(/,([A-Za-z])/g, "\n\t$1"),
          )
          .toBeNull();
      } else throw e;
    }
  });
});
