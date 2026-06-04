import { fromBER } from "asn1js";
import { decodeJwt, importJWK, jwtVerify } from "jose";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ContentInfo, SignedData } from "pkijs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { PidIdentityConfig } from "@/types/pid-issuance";

import { createKeys } from "@/logic/jwk";
import {
  getSimulatedConsentState,
  resetSimulatedConsentState,
  setSimulatedConsentState,
} from "@/logic/pid-mrtd/consent";
import { buildDg1, buildDg11, TD1_MRZ_BYTE_LENGTH } from "@/logic/pid-mrtd/dg";
import { generatePidMrtdFixtures } from "@/logic/pid-mrtd/generate-fixtures";
import { encodeLdsSecurityObject } from "@/logic/pid-mrtd/lds-security-object";
import {
  ACR_CIE_HIGH,
  ACR_SPID_SUBSTANTIAL,
  buildMrtdPopInitUrl,
  mintHighIdToken,
  mintMrtdProofJwt,
  mintSubstantialIdToken,
  resetMockIdpKeyCache,
} from "@/logic/pid-mrtd/mock-idp";
import {
  createEphemeralIasPki,
  loadPersistedPidMrtdPki,
} from "@/logic/pid-mrtd/pki";
import { initPkijsCryptoEngine } from "@/logic/pid-mrtd/pkijs-engine";
import {
  mrtdProofJwtPayloadSchema,
  parseMrtdValidationJwtClaims,
} from "@/logic/pid-mrtd/schemas";
import {
  assembleMrtdValidationJwtClaims,
  buildMrtdDocumentArtifacts,
  signMrtdValidationJwt,
} from "@/logic/pid-mrtd/validation-jwt";

const SAMPLE_MRZ = "P<ITARSS80A15H501Q<<<<<<<<<<<<<<<0";

const SAMPLE_IDENTITY: PidIdentityConfig = {
  birthdate: "1980-01-15",
  family_name: "Rossi",
  given_name: "Mario",
  mrz: SAMPLE_MRZ,
  personal_administrative_number: "AA12345BB",
  place_of_birth: "Roma",
  tax_id_code: "RSSMRA80A15H501Q",
};

describe("PID MRTD domain layer (REQ-03)", () => {
  let fixtureDir: string;

  beforeEach(() => {
    resetMockIdpKeyCache();
    resetSimulatedConsentState();
    initPkijsCryptoEngine();
    fixtureDir = mkdtempSync(path.join(tmpdir(), "wct-pid-mrtd-domain-"));
  });

  afterEach(() => {
    if (fixtureDir) {
      rmSync(fixtureDir, { force: true, recursive: true });
    }
  });

  it("builds DG1 with TD1 MRZ length", () => {
    const dg1 = buildDg1(SAMPLE_MRZ);
    expect(dg1.byteLength, "TD1 MRZ zone").toBe(TD1_MRZ_BYTE_LENGTH);
  });

  it("builds DG11 from identity config", () => {
    const dg11 = buildDg11(SAMPLE_IDENTITY);
    expect(dg11.byteLength).toBeGreaterThan(4);
    expect(dg11[0]).toBe(0x6b);
  });

  it("encodes LDS Security Object DER", () => {
    const hash = new Uint8Array(32).fill(0xab);
    const der = encodeLdsSecurityObject([{ dataGroupNumber: 1, hash }]);
    expect(der[0]).toBe(0x30);
    expect(der.byteLength).toBeGreaterThan(40);
  });

  it("mints substantial and high ID tokens with expected acr", async () => {
    const substantial = await mintSubstantialIdToken(SAMPLE_IDENTITY);
    const high = await mintHighIdToken(SAMPLE_IDENTITY);

    expect(decodeJwt(substantial).acr).toBe(ACR_SPID_SUBSTANTIAL);
    expect(decodeJwt(high).acr).toBe(ACR_CIE_HIGH);
  });

  it("mints MRTD proof JWT with init URL and session claims", async () => {
    const jwt = await mintMrtdProofJwt({
      issuerUrl: "https://issuer.example.com/",
      mrtdAuthSession: "sess-1",
      mrtdPopJwtNonce: "nonce-1",
      state: "state-xyz",
    });

    const payload = mrtdProofJwtPayloadSchema.parse(decodeJwt(jwt));
    expect(payload.htu).toBe(
      buildMrtdPopInitUrl("https://issuer.example.com/"),
    );
    expect(payload.mrtd_auth_session).toBe("sess-1");
    expect(payload.state).toBe("state-xyz");
  });

  it("loads persisted PKI and builds verifiable CMS SOD", async () => {
    await generatePidMrtdFixtures(fixtureDir, { force: true });
    const pki = await loadPersistedPidMrtdPki({
      issuance_pid: { fixture_storage_path: fixtureDir, mode: "l2plus" },
    });
    const ias = await createEphemeralIasPki();

    const artifacts = await buildMrtdDocumentArtifacts({
      challenge: "challenge-abc",
      ias,
      identity: SAMPLE_IDENTITY,
      pki,
    });

    expect(artifacts.sodMrtd.byteLength).toBeGreaterThan(100);
    expect(artifacts.challengeSigned.length).toBeGreaterThan(10);

    const cmsAsn1 = fromBER(Buffer.from(artifacts.sodMrtd));
    const contentInfo = new ContentInfo({ schema: cmsAsn1.result });
    const signedData = new SignedData({ schema: contentInfo.content });
    expect(signedData.signerInfos.length).toBe(1);
  });

  it("assembles and signs mrtd_validation_jwt claims", async () => {
    await generatePidMrtdFixtures(fixtureDir, { force: true });
    const pki = await loadPersistedPidMrtdPki({
      issuance_pid: { fixture_storage_path: fixtureDir, mode: "l2plus" },
    });
    const ias = await createEphemeralIasPki();
    const walletKeys = await createKeys();

    const artifacts = await buildMrtdDocumentArtifacts({
      challenge: "pop-challenge",
      ias,
      identity: SAMPLE_IDENTITY,
      mrz: SAMPLE_IDENTITY.mrz,
      pki,
    });

    const claims = assembleMrtdValidationJwtClaims(
      artifacts,
      SAMPLE_IDENTITY.mrz,
    );
    parseMrtdValidationJwtClaims(claims);

    const jwt = await signMrtdValidationJwt({
      claims,
      walletPrivateJwk: walletKeys.privateKey,
    });

    const key = await importJWK(walletKeys.publicKey, "ES256");
    const verified = await jwtVerify(jwt, key);
    expect(verified.payload.challenge_signed).toBe(claims.challenge_signed);
    expect(verified.payload.sod_mrtd).toBe(claims.sod_mrtd);
  });

  it("simulates consent state for CI_052", () => {
    expect(getSimulatedConsentState()).toBe("granted");
    setSimulatedConsentState("denied");
    expect(getSimulatedConsentState()).toBe("denied");
    resetSimulatedConsentState();
    expect(getSimulatedConsentState()).toBe("granted");
  });
});
