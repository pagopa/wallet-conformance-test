import { Jwk } from "@pagopa/io-wallet-oauth2";
import { ValidationError } from "@pagopa/io-wallet-utils";
import { parse } from "ini";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { loadCredentials } from "@/functions";
import { validateMdoc, validateSdJwt } from "@/logic";
import { Config } from "@/types";

const textConfig = readFileSync("config.ini", "utf-8");
const issuerKey = JSON.parse(
  readFileSync("tests/mocked-data/backup/issuer_jwk.pub", "utf-8"),
) as Jwk;
const config = parse(textConfig) as Config;
const types: string[] = [];

for (const type in config.issuance.credentials.types) {
  if (!config.issuance.credentials.types[type]) continue;

  if (
    config.issuance.credentials.types[type].find(
      (t) => t === config.issuance.url,
    )
  )
    types.push(type);
}

describe("validateMdoc", () => {
  /**
   * Test case to ensure that a correctly formatted mdoc is successfully validated.
   * It reads a sample mdoc from a file, calls the validateMdoc function, and expects
   * the function to return a valid mdoc object with at least one subject.
   */
  it("should successfully validate a correct mdoc", async () => {
    const credential = readFileSync(
      "tests/data/credentials/mso_mdoc_mDL",
      "utf-8",
    );
    const mdoc = await validateMdoc(Buffer.from(credential, "base64url"));
    expect(mdoc).toBeDefined();
    expect(mdoc.subs.length).toBeGreaterThan(0);
  });

  /**
   * Test case to ensure that an invalid mdoc is correctly rejected.
   * It attempts to validate a malformed credential and expects the validateMdoc
   * function to throw an error.
   */
  it("should throw an error for an invalid mdoc", async () => {
    const credential = Buffer.from("invalid-credential");
    await expect(validateMdoc(credential)).rejects.toThrow();
  });
});

describe("validateSdJwt", () => {
  it("should successfully validate a correct sd-jwt", async () => {
    const credential = readFileSync(
      "tests/data/credentials/dc_sd_jwt_PersonIdentificationData",
      "utf-8",
    );
    const jwt = await validateSdJwt(credential);
    expect(jwt).toBeDefined();
  });

  it("should throw an error for an invalid sd-jwt", async () => {
    const credential = "invalid-credential";
    await expect(validateSdJwt(credential)).rejects.toThrow();
  });
});

describe("loadCredentials", () => {
  /**
   * Test case to verify that the loadCredentials function can successfully load a mix of
   * valid SD-JWT and mdoc credentials from a directory. It expects the function to return
   * a record of credentials with the correct types assigned.
   */
  it("should load a mix of valid sd-jwt and mdoc credentials", async () => {
    try {
      const credentials = await loadCredentials(
        "tests/data/credentials",
        types,
      );
      expect(credentials).toBeDefined();
      expect(Object.keys(credentials).length).toBe(2);
      expect(credentials.dc_sd_jwt_mDL?.typ).toBe("dc+sd-jwt");
      expect(credentials.mso_mdoc_mDL?.typ).toBe("mso_mdoc");
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

  /**
   * Test case to verify that the loadCredentials function skips credential files that
   * are not supported. It creates a dummy unsupported credential file and expects the
   * function to ignore it, not including it in the returned credentials record.
   */
  it("should skip unsupported credential types", async () => {
    const unsupportedCredentialPath = "tests/data/credentials/unsupported_cred";
    writeFileSync(unsupportedCredentialPath, "unsupported-data");

    const credentials = await loadCredentials(
      "tests/data/credentials",
      types,
	  console.error,
    );
    expect(credentials.unsupported_cred).toBeUndefined();

    rmSync(unsupportedCredentialPath);
  });
});
