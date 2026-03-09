import { IssuerSignedDocument } from "@auth0/mdl";
import {
  dateToSeconds,
  ItWalletSpecsVersion,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { X509Certificate } from "@peculiar/x509";
import { digest } from "@sd-jwt/crypto-nodejs";
import { decodeJwt } from "@sd-jwt/decode";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import { decode } from "cbor";
import { DcqlQuery } from "dcql";
import { rmSync } from "node:fs";
import { afterAll, describe, expect, it, vi } from "vitest";

import {
  createMockMdlMdoc,
  getCredentialMdocExpiration,
  getCredentialSdJwtExpiration,
  isCredentialMdocExpired,
  isCredentialSdJwtExpired,
  loadCredentials,
} from "@/functions";
import { createMockSdJwt } from "@/functions";
import {
  buildJwksPath,
  createKeys,
  createVpTokenMdoc,
  loadCertificate,
  loadConfig,
  loadJsonDumps,
  loadJwks,
  parseMdoc,
} from "@/logic";
import { KeyPairJwk, zTrustChain, zX5c } from "@/types";

const backupDir = "./tests/mocked-data/backup";
const credentialsDir = "./tests/mocked-data/credentials";

describe("Load Mocked Credentials", async () => {
  afterAll(async () =>
    rmSync(
      "tests/mocked-data/federation_trust_anchors/localhost/trust_anchor_cert",
      { force: true },
    ),
  );

  it("should load a mix of valid sd-jwt and mdoc credentials V1_0", async () => {
    try {
      const credentials = await loadCredentials(
        credentialsDir,
        ["dc_sd_jwt_PersonIdentificationData", "mso_mdoc_mDL"],
        console.error,
        ItWalletSpecsVersion.V1_0,
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

  it("should create a new certificate in case the current one is actually expired", async () => {
    (rmSync(
      "tests/mocked-data/federation_trust_anchors/localhost/trust_anchor_cert",
      { force: true },
    ),
      vi.useFakeTimers());
    const baseDate = new Date(2000, 1, 1);
    //Default expiration for the certificates is an year, so in two years it will be surely expired
    const twoYearsLater = new Date(2002, 1, 1);

    const signedJwks = await loadJwks(
      "tests/mocked-data/federation_trust_anchors/localhost",
      "trust_anchor_jwks",
    );

    vi.setSystemTime(baseDate);

    const derBefore = await loadCertificate(
      "tests/mocked-data/federation_trust_anchors/localhost",
      "trust_anchor_cert",
      signedJwks,
      "CN=test_trust_anchor, O=it_wallet, OU=wallet_lab",
    );

    vi.setSystemTime(twoYearsLater);

    const derAfter = await loadCertificate(
      "tests/mocked-data/federation_trust_anchors/localhost",
      "trust_anchor_cert",
      signedJwks,
      "CN=test_trust_anchor, O=it_wallet, OU=wallet_lab",
    );

    //If the certificate has been regenerated, it should be different from the previous one

    expect(derAfter).not.toEqual(derBefore);
  });

  it("should check the credentials are expired", async () => {
    try {
      const credentials = await loadCredentials(
        credentialsDir,
        ["dc_sd_jwt_PersonIdentificationData", "mso_mdoc_mDL"],
        console.error,
        ItWalletSpecsVersion.V1_0,
      );
      const baseDate = new Date(2000, 1, 1);
      vi.useFakeTimers();
      Object.values(credentials).forEach((credential) => {
        vi.setSystemTime(baseDate);
        if (credential.typ === "dc+sd-jwt") {
          const expiration = getCredentialSdJwtExpiration(
            credential.parsed,
            "expiry_date",
          );
          const exp = credential.parsed.jwt.payload?.exp;
          const jwtExpiration =
            exp !== undefined && typeof exp === "number" ? exp : undefined;
          if (!jwtExpiration)
            throw new Error(
              "Expected the jwt to have a well defined expiration",
            );
          const x5c = zX5c.safeParse(credential.parsed.jwt.header?.x5c);
          const x5cMinExp = x5c.success
            ? x5c.data
                .map((cert) => new X509Certificate(cert))
                .reduce<Date>((cumulated, curr, idx) => {
                  if (idx === 0) return curr.notAfter;
                  return cumulated < curr.notAfter ? cumulated : curr.notAfter;
                }, new Date())
            : undefined;
          if (!x5cMinExp)
            throw new Error(
              "Expected MDoc credential to contain the trust_chain field in the issuerAuth",
            );

          const trust_chain = zTrustChain.safeParse(
            credential.parsed.jwt.header?.trust_chain,
          );
          const trustChainMinExp = trust_chain.success
            ? trust_chain.data.reduce<number>((prev, ec) => {
                const decoded = decodeJwt(ec);
                const exp = decoded.payload.exp;
                if (exp === undefined || typeof exp !== "number")
                  throw new Error(
                    "Expected the Federation ES to contain an expiration",
                  );
                return Math.min(prev, exp);
              }, Infinity)
            : undefined;
          if (!trustChainMinExp)
            throw new Error(
              "Expected the SdJwt to contain the trust_chain header field",
            );

          /**
           * Test all expiration checks
           */
          expect(
            isCredentialSdJwtExpired(credential.parsed, "expiry_date"),
          ).toBe(false);

          /**
           * Credential claim expiration tests
           */
          // Set system time to a second before expiration
          vi.setSystemTime((dateToSeconds(expiration) - 1) * 1000);
          expect(
            isCredentialSdJwtExpired(credential.parsed, "expiry_date", {
              /* An empty object means that none of the checks is performed */
            }),
          ).toBe(false);
          // Set system time to a second after expiration
          vi.setSystemTime((dateToSeconds(expiration) + 1) * 1000);
          expect(
            isCredentialSdJwtExpired(credential.parsed, "expiry_date", {
              /* An empty object means that none of the checks is performed */
            }),
          ).toBe(true);

          /**
           * Credential mdoc expiration checks
           */
          // Set system time to a second before expiration
          vi.setSystemTime((jwtExpiration - 1) * 1000);
          expect(
            isCredentialSdJwtExpired(credential.parsed, undefined, {
              jwt: true,
            }),
          ).toBe(false);
          // Set system time to a second after expiration
          vi.setSystemTime((jwtExpiration + 1) * 1000);
          expect(
            isCredentialSdJwtExpired(credential.parsed, undefined, {
              jwt: true,
            }),
          ).toBe(true);

          /**
           * Credential certificate chain expiration checks
           */
          // Set system time to a second before expiration
          vi.setSystemTime((dateToSeconds(x5cMinExp) - 1) * 1000);
          expect(
            isCredentialSdJwtExpired(credential.parsed, undefined, {
              x5c: true,
            }),
          ).toBe(false);
          // Set system time to a second after expiration
          vi.setSystemTime((dateToSeconds(x5cMinExp) + 1) * 1000);
          expect(
            isCredentialSdJwtExpired(credential.parsed, undefined, {
              x5c: true,
            }),
          ).toBe(true);

          /**
           * Credential certificate chain expiration checks
           */
          // Set system time to a second before expiration
          vi.setSystemTime((trustChainMinExp - 1) * 1000);
          expect(
            isCredentialSdJwtExpired(credential.parsed, undefined, {
              trust_chain: true,
            }),
          ).toBe(false);
          // Set system time to a second after expiration
          vi.setSystemTime((trustChainMinExp + 1) * 1000);
          expect(
            isCredentialSdJwtExpired(credential.parsed, undefined, {
              trust_chain: true,
            }),
          ).toBe(true);
        } else {
          const expiration = getCredentialMdocExpiration(credential.parsed, {
            claimName: "expiry_date",
            namespace: "eu.europa.it.badge.1",
          });
          const issuerAuth = credential.parsed.issuerSigned.issuerAuth;
          const mDocExpiration =
            issuerAuth.decodedPayload.validityInfo.validUntil;
          const certExpiration = issuerAuth.certificate.notAfter;
          const trustChain = issuerAuth.x5chain
            ?.map((buffer) => Buffer.from(buffer).toString("base64"))
            .map((cert) => new X509Certificate(cert));
          const trustChainMinExp = trustChain?.reduce<Date>(
            (cumulated, curr, idx) => {
              if (idx === 0) return curr.notAfter;
              return cumulated < curr.notAfter ? cumulated : curr.notAfter;
            },
            new Date(),
          );
          if (!trustChainMinExp)
            throw new Error(
              "Expected MDoc credential to contain the trust_chain field in the issuerAuth",
            );

          /**
           * Test all expiration checks
           */

          expect(
            isCredentialMdocExpired(credential.parsed, {
              claimName: "expiry_date",
              namespace: "eu.europa.it.badge.1",
            }),
          ).toBe(false);

          /**
           * Credential claim expiration tests
           */
          // Set system time to a second before expiration
          vi.setSystemTime((dateToSeconds(expiration) - 1) * 1000);
          expect(
            isCredentialMdocExpired(
              credential.parsed,
              {
                claimName: "expiry_date",
                namespace: "eu.europa.it.badge.1",
              },
              {
                /* An empty object means that none of the checks is performed */
              },
            ),
          ).toBe(false);
          // Set system time to a second after expiration
          vi.setSystemTime((dateToSeconds(expiration) + 1) * 1000);
          expect(
            isCredentialMdocExpired(
              credential.parsed,
              {
                claimName: "expiry_date",
                namespace: "eu.europa.it.badge.1",
              },
              {
                /* An empty object means that none of the checks is performed */
              },
            ),
          ).toBe(true);

          /**
           * Credential mdoc expiration checks
           */
          vi.setSystemTime((dateToSeconds(mDocExpiration) - 1) * 1000);
          expect(
            isCredentialMdocExpired(credential.parsed, undefined, {
              mdoc: true,
            }),
          ).toBe(false);
          // Set system time to a second after expiration
          vi.setSystemTime((dateToSeconds(mDocExpiration) + 1) * 1000);
          expect(
            isCredentialMdocExpired(credential.parsed, undefined, {
              mdoc: true,
            }),
          ).toBe(true);

          /**
           * Credential certificate expiration checks
           */
          vi.setSystemTime((dateToSeconds(certExpiration) - 1) * 1000);
          expect(
            isCredentialMdocExpired(credential.parsed, undefined, {
              cert: true,
            }),
          ).toBe(false);
          // Set system time to a second after expiration
          vi.setSystemTime((dateToSeconds(certExpiration) + 1) * 1000);
          expect(
            isCredentialMdocExpired(credential.parsed, undefined, {
              cert: true,
            }),
          ).toBe(true);

          /**
           * Credential certificate chain expiration checks
           */
          vi.setSystemTime((dateToSeconds(trustChainMinExp) - 1) * 1000);
          expect(
            isCredentialMdocExpired(credential.parsed, undefined, {
              x5chain: true,
            }),
          ).toBe(false);
          // Set system time to a second after expiration
          vi.setSystemTime((dateToSeconds(trustChainMinExp) + 1) * 1000);
          expect(
            isCredentialMdocExpired(credential.parsed, undefined, {
              x5chain: true,
            }),
          ).toBe(true);
        }
      });
    } catch (e) {
      if (e instanceof ValidationError) {
        console.error("Schema validation failed");
        expect
          .soft(
            e.message.replace(": ", ":\n\t").replace(/,([A-Za-z])/g, "\n\t$1"),
          )
          .toBeNull();
      } else throw e;
    } finally {
      vi.useRealTimers();
    }
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
    Object.values(ItWalletSpecsVersion).forEach((version) => {
      rmSync(`${backupDir}/${version}/dc_sd_jwt_PersonIdentificationData`, {
        force: true,
      });
      rmSync(`${backupDir}/${version}/mso_mdoc_mDL`, { force: true });
    });
  });

  it("should create a mock SD-JWT using existing keys", async () => {
    const credentialIdentifier = "dc_sd_jwt_PersonIdentificationData";
    const unitKey: KeyPairJwk = (
      await loadJwks(backupDir, buildJwksPath(credentialIdentifier))
    ).publicKey;

    const credential = await createMockSdJwt(
      metadata,
      backupDir,
      backupDir,
      config.wallet.wallet_version,
    );

    const decoded = await new SDJwtVcInstance({
      hasher: digest,
    }).decode(credential.compact);

    expect(decoded.jwt?.header?.typ).toBe("dc+sd-jwt");
    expect(decoded.jwt?.payload?.iss).toBe(iss);
    expect(decoded.jwt?.payload?.vct).toBe(
      "https://pre.ta.wallet.ipzs.it/vct/v1.0.0/personidentificationdata",
    );
    expect(
      (decoded.jwt?.payload?.cnf as { jwk: { kid: string } })?.jwk.kid,
    ).toBe(unitKey.kid);
  });

  it("should create a mock SD-JWT PID version 1.0.2", async () => {
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

    const dump = loadJsonDumps(
      "pid.json",
      { expiration: new Date(Date.now()) },
      ItWalletSpecsVersion.V1_0,
    );

    const claimsFromDecoded = decoded.disclosures?.reduce(
      (prev, disclosure) => ({
        ...prev,
        [disclosure.key!]: disclosure.value,
      }),
      {},
    );

    expect(claimsFromDecoded).toEqual({
      ...dump,
      expiry_date: expect.any(String),
    });
  });

  it("should create a mock SD-JWT PID version 1.3.3", async () => {
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

    const dump = loadJsonDumps(
      "pid.json",
      { expiration: new Date(Date.now()) },
      ItWalletSpecsVersion.V1_3,
    );

    const claimsFromDecoded = decoded.disclosures?.reduce(
      (prev, disclosure) => ({
        ...prev,
        [disclosure.key!]: disclosure.value,
      }),
      {},
    );

    expect(claimsFromDecoded).toEqual({
      ...dump,
      date_of_expiry: expect.any(String),
    });
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
        client_id: "client_id",
        credential: "invalid_credential",
        dcqlQuery,
        dpopJwk: keyPair.privateKey,
        nonce: "nonce",
        responseUri: "https://example.com",
      }),
    ).rejects.toThrow();
  });

  it("should generate device response when matching credential found V1_0", async () => {
    const docType = "eu.europa.it.badge";
    const namespace = "eu.europa.it.badge.1";
    const keyPair = await loadJwks(backupDir, "wallet_unit_jwks");
    const credential = await loadCredentials(
      credentialsDir,
      ["mso_mdoc_mDL"],
      console.error,
      ItWalletSpecsVersion.V1_0,
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
      client_id: "client_id",
      credential: credential.mso_mdoc_mDL.compact,
      dcqlQuery,
      dpopJwk: keyPair.privateKey,
      nonce: "nonce",
      responseUri: "https://example.com",
    });

    expect(result).toHaveProperty("query_mdl");
    expect(result["query_mdl"]).toBeDefined();

    const documents = decode(
      Buffer.from(result["query_mdl"]!, "base64url"),
    ).documents;
    expect(documents).toBeDefined();

    const document = documents[0]!;
    expect(document).toBeDefined();
    expect(document.docType).toBe(docType);
    expect(document.issuerSigned.nameSpaces).toBeDefined();
    expect(document.issuerSigned.nameSpaces).toHaveProperty(namespace);
    expect(document.issuerSigned.nameSpaces[namespace].length).toBe(2);
  });
});
