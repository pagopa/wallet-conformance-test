import { Jwk } from "@pagopa/io-wallet-oauth2";
import { ValidationError } from "@pagopa/io-wallet-utils";
import { parse } from "ini";
import { readFileSync, writeFileSync, rmSync } from "node:fs";
import { describe, it, expect } from "vitest";

import { loadCredentials } from "@/functions";
import { validateMdoc, validateSdJwt } from "@/logic";
import { Config, VerificationError } from "@/types";

const textConfig = readFileSync("config.ini", "utf-8");
const issuerKey = JSON.parse(
  readFileSync("tests/data/backup/issuer_jwk.pub", "utf-8"),
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

describe("validateSdJwt", () => {
  it("should successfully validate a correct sd-jwt", async () => {
    const credential = readFileSync(
      "tests/data/credentials/dc_sd_jwt_mDL",
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
    const credential = readFileSync("tests/data/credentials/mso_mdoc_mDL");
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
        "tests/data/credentials",
        types,
        issuerKey,
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

  it("should throw a VerificationError for duplicate subjects", async () => {
    const credential = readFileSync(
      "tests/data/credentials/dc_sd_jwt_mDL",
      "utf-8",
    );
    const newCredentialPath = "tests/data/credentials/dc_sd_jwt_mDL_copy";
    writeFileSync(newCredentialPath, credential);

    await expect(
      loadCredentials("tests/data/credentials", [...types, "dc_sd_jwt_mDL_copy"], issuerKey),
    ).rejects.toThrow(VerificationError);

    rmSync(newCredentialPath);
  });

  it("should skip unsupported credential types", async () => {
    const unsupportedCredentialPath = "tests/data/credentials/unsupported_cred";
    writeFileSync(unsupportedCredentialPath, "unsupported-data");

    const credentials = await loadCredentials(
      "tests/data/credentials",
      types,
      issuerKey,
	  console.error,
      // "tests/data/certs/cert.pem",
    );
    expect(credentials.unsupported_cred).toBeUndefined();

    rmSync(unsupportedCredentialPath);
  });
});
