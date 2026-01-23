import { ValidationError } from "@pagopa/io-wallet-utils";
import { digest } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { rmSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";

import { loadCredentials } from "@/functions";
import { createMockSdJwt } from "@/functions";
import { loadConfig, loadJwks } from "@/logic";
import { KeyPairJwk } from "@/types";

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

describe("Generate Mocked Credentials", () => {
  const backupDir = "./tests/mocked-data/backup";
  const config = loadConfig("./config.ini");
  const iss = "https://issuer.example.com";
  const metadata = {
    iss,
    trustAnchorBaseUrl: `https://127.0.0.1:${config.trust_anchor.port}`,
    trustAnchorJwksPath: config.trust.federation_trust_anchors_jwks_path,
  };

  afterAll(() => {
    rmSync(`${backupDir}/dc_sd_jwt_PersonIdentificationData`, { force: true });
  });

  it("should create a mock SD-JWT using existing keys", async () => {
    const credentialIdentifier = "dc_sd_jwt_PersonIdentificationData";
    const unitKey: KeyPairJwk = (
      await loadJwks(backupDir, `${credentialIdentifier}_jwks`)
    ).publicKey;

    const credential = await createMockSdJwt(metadata, backupDir, backupDir);

    const decoded = await new SDJwtVcInstance({
      hasher: digest,
    }).decode(credential.compact);

    expect(decoded.jwt?.header?.typ).toBe("dc+sd-jwt");
    expect(decoded.jwt?.payload?.iss).toBe(iss);
    expect(decoded.jwt?.payload?.vct).toBe("urn:eudi:pid:1");
    expect(
      (decoded.jwt?.payload?.cnf as { jwk: { kid: string } })?.jwk.kid,
    ).toBe(unitKey.kid);
  });
});
