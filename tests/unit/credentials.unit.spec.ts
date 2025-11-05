import { Jwk } from "@pagopa/io-wallet-oauth2";
import { ValidationError } from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import { loadCredentials } from "@/functions";
import { readFileSync, rmSync } from "node:fs";
import { validateSdJwt } from "@/logic";
import { VerificationError } from "@/types";

const issuerKey = JSON.parse(
  readFileSync("tests/data/backup/issuer_jwk.pub", "utf-8"),
) as Jwk;
const types = ["dc_sd_jwt_PersonIdentificationData", "mso_mdoc_mDL"];

describe("validateSdJwt", () => {
  it("should successfully validate a correct sd-jwt", async () => {
    const credential = readFileSync(
      "tests/mocked-data/credentials/dc_sd_jwt_PersonIdentificationData",
      "utf-8",
    );
    const jwt = await validateSdJwt(credential, issuerKey);
    expect(jwt).toBeDefined();
  });

  it("should throw an error for an invalid sd-jwt", async () => {
    const credential = "invalid-credential";
    await expect(validateSdJwt(credential, issuerKey)).rejects.toThrow();
  });
});

describe("validateMdoc", () => {
  it("should successfully validate a correct mdoc", async () => {
    const credential = readFileSync("tests/mocked-data/credentials/mso_mdoc_mDL");
    const mdoc = await validateMdoc(credential, issuerKey);
    expect(mdoc).toBeDefined();
    expect(mdoc.subs.length).toBeGreaterThan(0);
  });

  it("should throw an error for an invalid mdoc", async () => {
    const credential = Buffer.from("invalid-credential");
    await expect(validateMdoc(credential, issuerKey)).rejects.toThrow();
  });
});

describe("loadCredentials", () => {
  it("should load a mix of valid sd-jwt and mdoc credentials", async () => {
    try {
      const credentials = await loadCredentials(
        "tests/mocked-data/credentials",
        types,
        issuerKey,
        console.error,
      );
      expect(credentials).toBeDefined();
      expect(Object.keys(credentials).length).toBe(2);
      expect(credentials.dc_sd_jwt_PersonIdentificationData
?.typ).toBe("dc+sd-jwt");
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

  it("should throw a VerificationError for duplicate subjects", async () => {
    await expect(
      loadCredentials("tests/data/credentials", ["dc_sd_jwt_PersonIdentificationData", "dc_sd_jwt_PersonIdentificationData_copy"], issuerKey, console.error),
    ).rejects.toThrow(VerificationError);
  });
});
