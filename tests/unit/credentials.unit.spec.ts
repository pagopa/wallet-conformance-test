import { IssuerSignedDocument } from "@auth0/mdl";
import { ItWalletSpecsVersion, ValidationError } from "@pagopa/io-wallet-utils";
import { digest } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { decode } from "cbor";
import { DcqlQuery } from "dcql";
import { rmSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";

import { createMockMdlMdoc, loadCredentials } from "@/functions";
import { createMockSdJwt } from "@/functions";
import {
  buildJwksPath,
  createKeys,
  createVpTokenMdoc,
  loadCertificate,
  loadConfig,
  loadJwks,
  parseMdoc,
} from "@/logic";
import { Config, KeyPairJwk } from "@/types";

const backupDir = "./tests/mocked-data/backup";
const credentialsDir = "./tests/mocked-data/credentials";

describe("Load Mocked Credentials", async () => {
  afterAll(async () =>
    rmSync(
      "tests/mocked-data/federation_trust_anchors/localhost/trust_anchor_cert",
      { force: true },
    ),
  );

  it("should load a mix of valid sd-jwt and mdoc credentials", async () => {
    try {
      const credentials = await loadCredentials(
        credentialsDir,
        ["dc_sd_jwt_PersonIdentificationData", "mso_mdoc_mDL"],
        console.error,
        ItWalletSpecsVersion.V1_0
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

  it("should create a new certificate", async () => {
    const signedJwks = await loadJwks(
      "tests/mocked-data/federation_trust_anchors/localhost",
      "trust_anchor_jwks",
    );
    const der = await loadCertificate(
      "tests/mocked-data/federation_trust_anchors/localhost",
      "trust_anchor_cert",
      signedJwks,
      "CN=test_trust_anchor, O=it_wallet, OU=wallet_lab",
    );

    expect(der).toBeDefined();
  });
});

describe("Generate Mocked Credentials", () => {
  const config = loadConfig("./config.ini");
  const iss = "https://issuer.example.com";
  const metadata = {
    iss,
    trustAnchorBaseUrl: `https://127.0.0.1:${config.trust_anchor.port}`,
    trustAnchorJwksPath: config.trust.federation_trust_anchors_jwks_path,
  };

  afterAll(() => {
    rmSync(
      `${backupDir}/${config.wallet.wallet_version ?? ItWalletSpecsVersion.V1_0}/dc_sd_jwt_PersonIdentificationData`,
      { force: true },
    );
    rmSync(
      `${backupDir}/${config.wallet.wallet_version ?? ItWalletSpecsVersion.V1_0}/mso_mdoc_mDL`,
      { force: true },
    );
  });

  it("should create a mock SD-JWT using existing keys", async () => {
    const credentialIdentifier = "dc_sd_jwt_PersonIdentificationData";
    const unitKey: KeyPairJwk = (
      await loadJwks(backupDir, buildJwksPath(credentialIdentifier))
    ).publicKey;

    const credential = await createMockSdJwt(metadata, backupDir, backupDir);

    const decoded = await new SDJwtVcInstance({
      hasher: digest,
    }).decode(credential.compact);

    expect(decoded.jwt?.header?.typ).toBe("dc+sd-jwt");
    expect(decoded.jwt?.payload?.iss).toBe(iss);
    expect(decoded.jwt?.payload?.vct).toBe("https://pre.ta.wallet.ipzs.it/vct/v1.0.0/personidentificationdata");
    expect(
      (decoded.jwt?.payload?.cnf as { jwk: { kid: string } })?.jwk.kid,
    ).toBe(unitKey.kid);
  });

  it("should create a mock SD-JWT version 1.0.2", async () => {
    const credential = await createMockSdJwt(
      metadata,
      backupDir,
      backupDir,
      ItWalletSpecsVersion.V1_0,
    );

    const decoded = await new SDJwtVcInstance({
      hasher: digest,
    }).decode(credential.compact);

    expect(decoded.jwt?.payload?.status).toHaveProperty("status_assertion");
  });

  it("should create a mock SD-JWT version 1.3.3", async () => {
    const credential = await createMockSdJwt(
      metadata,
      backupDir,
      backupDir,
      ItWalletSpecsVersion.V1_3,
    );

    const decoded = await new SDJwtVcInstance({
      hasher: digest,
    }).decode(credential.compact);

    expect(decoded.jwt?.payload?.status).toHaveProperty("status_list");
  });

  it.each([ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3])(
    "should create a mock MDOC using existing keys",
    async (version) => {
      const credential = await createMockMdlMdoc(
        "CN=test_issuer",
        backupDir,
        backupDir,
        version,
      );

      expect(credential.typ).toBe("mso_mdoc");

      const parsed = credential.parsed as IssuerSignedDocument;
      expect(parsed.docType).toBe("org.iso.18013.5.1.mDL");
      expect(parsed.getIssuerNameSpace("org.iso.18013.5.1")).toBeDefined();

      const parsedCompact = parseMdoc(
        Buffer.from(credential.compact, "base64url"),
      );
      expect(parsedCompact.docType).toEqual(parsed.docType);
      expect(parsedCompact.issuerSigned.issuerAuth.payload.toString()).toEqual(
        parsed.issuerSigned.issuerAuth.payload.toString(),
      );
    },
  );
});

describe("createVpTokenMdoc", () => {
  afterAll(() => {
    rmSync(`${backupDir}/mso_mdoc_mDL`, { force: true });
  });

  it("should throw if no matching credential query found", async () => {
    const keyPair = await createKeys();

    const dcqlQuery: DcqlQuery.Input = {
      credentials: [
        {
          claims: [{ path: ["org.iso.18013.5.1", "family_name"] }],
          format: "mso_mdoc",
          id: "query_1",
          meta: { doctype_value: "org.iso.18013.5.1.mDL" },
        },
      ],
    };

    await expect(
      createVpTokenMdoc({
        clientId: "client_id",
        credential: "invalid_credential",
        dcqlQuery,
        devicePrivateKey: keyPair.privateKey,
        nonce: "nonce",
        responseUri: "https://example.com",
      }),
    ).rejects.toThrow();
  });

  it("should generate device response when matching credential found", async () => {
    const docType = "eu.europa.it.badge";
    const namespace = "eu.europa.it.badge.1";
    const keyPair = await loadJwks(backupDir, "wallet_unit_jwks");
    const credential = await loadCredentials(
      credentialsDir,
      ["mso_mdoc_mDL"],
      console.error,
      ItWalletSpecsVersion.V1_0
    );

    if (!credential.mso_mdoc_mDL) {
      throw new Error("Credential compact is empty");
    }

    const dcqlQuery: DcqlQuery.Input = {
      credentials: [
        {
          claims: [
            { path: [namespace, "family_name"] },
            { path: [namespace, "given_name"] },
          ],
          format: "mso_mdoc",
          id: "query_mdl",
          meta: { doctype_value: docType },
        },
      ],
    };

    const result = await createVpTokenMdoc({
      clientId: "client_id",
      credential: credential.mso_mdoc_mDL!.compact,
      dcqlQuery,
      devicePrivateKey: keyPair.privateKey,
      nonce: "nonce",
      responseUri: "https://example.com",
    });

    expect(result).toHaveProperty("query_mdl");
    expect(result["query_mdl"]).toBeDefined();

    const documents = decode(result["query_mdl"]!).documents;
    expect(documents).toBeDefined();

    const document = documents[0]!;
    expect(document).toBeDefined();
    expect(document.docType).toBe(docType);
    expect(document.issuerSigned.nameSpaces).toBeDefined();
    expect(document.issuerSigned.nameSpaces).toHaveProperty(namespace);
    expect(document.issuerSigned.nameSpaces[namespace].length).toBe(2);
  });
});
