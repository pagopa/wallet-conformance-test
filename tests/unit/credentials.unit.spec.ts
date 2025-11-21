import { ValidationError } from "@pagopa/io-wallet-utils";
import { afterAll, describe, expect, it } from "vitest";

import { loadCredentials } from "@/functions";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { readFileSync, rmSync } from "node:fs";
import * as path from "path";

import { createMockSdJwt } from "@/functions";
import {
  createFederationMetadata,
  createSubordinateTrustAnchorMetadata,
  loadConfig,
  loadJsonDumps,
} from "@/logic";
import { KeyPair, KeyPairJwk } from "@/types";

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

  afterAll(() => {
    rmSync(`${backupDir}/issuer.jwk`, { force: true });
    rmSync(`${backupDir}/wallet_unit.jwk`, { force: true });
  });

  it("should create a mock SD-JWT by generating new keys", async () => {
    const iss = "https://issuer.example.com";
    const credential = await createMockSdJwt(
      {
        iss,
        trustAnchorBaseUrl: `https://127.0.0.1:${config.server.port}`,
        trustAnchorJwksPath: config.trust.federation_trust_anchors_jwks_path,
      },
      backupDir,
    );

    expect(credential).toBeTypeOf("string");
    expect(credential.length).toBeGreaterThan(0);

    const decoded = await new SDJwtVcInstance({
      hasher: (data: ArrayBuffer | string) =>
        Promise.resolve(
          Buffer.from(
            require("crypto").createHash("sha256").update(data).digest(),
          ),
        ),
    }).decode(credential);

    expect(decoded.jwt?.header?.typ).toBe("dc+sd-jwt");
    expect(decoded.jwt?.header?.trust_chain).toBeDefined();
    expect(decoded.jwt?.payload?.iss).toBe(iss);
    expect(decoded.jwt?.payload?.vct).toBe("urn:eudi:pid:1");
  });

  it("should create a mock SD-JWT using existing keys", async () => {
    const iss = "https://issuer.example.com";
    const metadata = {
      iss,
      trustAnchorBaseUrl: `https://127.0.0.1:${config.server.port}`,
      trustAnchorJwksPath: config.trust.federation_trust_anchors_jwks_path,
    };
    const issuerKeyPair: KeyPair = JSON.parse(
      readFileSync(path.join(backupDir, "issuer_jwks"), "utf-8"),
    );
    const unitKey: KeyPairJwk = JSON.parse(
      readFileSync(path.join(backupDir, "wallet_unit_jwks"), "utf-8"),
    ).publicKey;

    const taEntityConfiguration = await createSubordinateTrustAnchorMetadata({
      entityPublicJwk: issuerKeyPair.publicKey,
      federationTrustAnchorsJwksPath: metadata.trustAnchorJwksPath,
      sub: iss,
      trustAnchorBaseUrl: metadata.trustAnchorBaseUrl,
    });

    const issClaims = loadJsonDumps("issuer_metadata.json", {
      publicKey: issuerKeyPair.publicKey,
      trust_anchor_base_url: metadata.trustAnchorBaseUrl,
      issuer_base_url: metadata.iss,
    });
    const issEntityConfiguration = await createFederationMetadata({
      claims: issClaims,
      entityPublicJwk: issuerKeyPair.publicKey,
      signedJwks: issuerKeyPair,
    });

    const issuerArg = {
      keyPair: issuerKeyPair,
      trust_chain: [issEntityConfiguration, taEntityConfiguration],
    };

    const credential = await createMockSdJwt(
      {
        iss,
        trustAnchorBaseUrl: `https://127.0.0.1:${config.server.port}`,
        trustAnchorJwksPath: config.trust.federation_trust_anchors_jwks_path,
      },
      backupDir,
      issuerArg,
      unitKey,
    );

    const decoded = await new SDJwtVcInstance({
      hasher: (data: ArrayBuffer | string) =>
        Promise.resolve(
          Buffer.from(
            require("crypto").createHash("sha256").update(data).digest(),
          ),
        ),
    }).decode(credential);

    expect(decoded.jwt?.header?.typ).toBe("dc+sd-jwt");
    expect(decoded.jwt?.header?.trust_chain).toStrictEqual(
      issuerArg.trust_chain,
    );
    expect(decoded.jwt?.payload?.iss).toBe(iss);
    expect(decoded.jwt?.payload?.vct).toBe("urn:eudi:pid:1");
    expect(
      (decoded.jwt?.payload?.cnf as { jwk: { kid: string } })?.jwk.kid,
    ).toBe(unitKey.kid);
  });
});
