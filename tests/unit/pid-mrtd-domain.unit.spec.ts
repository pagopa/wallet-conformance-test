import { fromBER } from "asn1js";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
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
  MRTD_PROOF_JWT_TYP,
  MRTD_VALIDATION_JWT_TYP,
  mrtdProofJwtPayloadSchema,
  parseMrtdValidationJwtClaims,
} from "@/logic/pid-mrtd/schemas";
import {
  assembleMrtdValidationJwtClaims,
  buildMrtdDocumentArtifacts,
  signMrtdValidationJwt,
} from "@/logic/pid-mrtd/validation-jwt";

const SAMPLE_MRZ = "P<ITARSS80A15H501Q<<<<<<<<<<<<<<<0";

function decodeUtf8TlvValue(buffer: Uint8Array, tagOffset: number): string {
  const lengthOffset = tagOffset + 2;
  const lengthByte = buffer[lengthOffset];
  if (lengthByte === undefined || lengthByte >= 0x80) {
    throw new Error("Test helper supports only short TLV lengths");
  }
  const valueStart = lengthOffset + 1;
  return new TextDecoder().decode(
    buffer.subarray(valueStart, valueStart + lengthByte),
  );
}

function indexOfSubarray(
  haystack: Uint8Array,
  needle: readonly number[],
): number {
  if (needle.length === 0) {
    return -1;
  }
  for (let i = 0; i <= haystack.length - needle.length; i++) {
    let found = true;
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        found = false;
        break;
      }
    }
    if (found) {
      return i;
    }
  }
  return -1;
}

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

  it("builds DG11 with valid ICAO two-byte TLV tags", () => {
    const dg11 = buildDg11(SAMPLE_IDENTITY);
    expect(dg11[0], "DG11 template tag").toBe(0x6b);

    const fullNameTagOffset = indexOfSubarray(dg11, [0x5f, 0x0e]);
    expect(fullNameTagOffset, "5F0E full name tag").toBeGreaterThan(0);

    const birthTagOffset = indexOfSubarray(dg11, [0x5f, 0x2b]);
    expect(birthTagOffset, "5F2B date of birth tag").toBeGreaterThan(0);

    const decodedBirth = decodeUtf8TlvValue(dg11, birthTagOffset);
    expect(decodedBirth, "5F2B YYYYMMDD").toBe("19800115");
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

  it("mints MRTD proof JWT aligned with L2+ spec (tables 12.1/12.2)", async () => {
    const jwt = await mintMrtdProofJwt({
      aud: "https://wallet.example/client-1",
      issuerUrl: "https://issuer.example.com/",
      mrtdAuthSession: "sess-1",
      mrtdPopJwtNonce: "nonce-1",
      state: "state-xyz",
    });

    const header = decodeProtectedHeader(jwt);
    expect(header.typ, "JOSE typ").toBe(MRTD_PROOF_JWT_TYP);
    expect(header.kid, "signing kid").toBeTruthy();

    const payload = mrtdProofJwtPayloadSchema.parse(decodeJwt(jwt));
    expect(payload.htu).toBe(
      buildMrtdPopInitUrl("https://issuer.example.com/"),
    );
    expect(payload.aud).toBe("https://wallet.example/client-1");
    expect(payload.htm).toBe("POST");
    expect(payload.status).toBe("require_interaction");
    expect(payload.type).toBe("mrtd+ias");
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

  it("assembles and signs normative mrtd_validation_jwt", async () => {
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

    const claims = assembleMrtdValidationJwtClaims(artifacts, {
      aud: "https://issuer.example.com",
      iss: "https://wallet.example",
    });
    parseMrtdValidationJwtClaims(claims);

    expect(claims.document_type).toBe("cie");
    expect(claims.mrtd.dg1.length).toBeGreaterThan(0);
    expect(claims.ias.ias_pk.kty).toBe("EC");

    const jwt = await signMrtdValidationJwt({
      claims,
      walletPrivateJwk: walletKeys.privateKey,
    });

    const header = decodeProtectedHeader(jwt);
    expect(header.typ).toBe(MRTD_VALIDATION_JWT_TYP);
    expect(header.kid).toBe(walletKeys.privateKey.kid);

    const key = await importJWK(walletKeys.publicKey, "ES256");
    const verified = await jwtVerify(jwt, key);
    const payload = parseMrtdValidationJwtClaims(verified.payload);
    expect(payload.ias.challenge_signed).toBe(claims.ias.challenge_signed);
    expect(payload.mrtd.sod_mrtd).toBe(claims.mrtd.sod_mrtd);
  });

  it("simulates consent state for CI_052", () => {
    expect(getSimulatedConsentState()).toBe("granted");
    setSimulatedConsentState("denied");
    expect(getSimulatedConsentState()).toBe("denied");
    resetSimulatedConsentState();
    expect(getSimulatedConsentState()).toBe("granted");
  });
});
