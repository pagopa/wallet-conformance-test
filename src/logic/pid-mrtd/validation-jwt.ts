import { type JWK, SignJWT } from "jose";

import type { EphemeralIasPki, LoadedPidMrtdPki } from "@/logic/pid-mrtd/pki";
import type { PidIdentityConfig } from "@/types/pid-issuance";

import {
  createSodCmsSignedData,
  signMrtdChallenge,
} from "@/logic/pid-mrtd/cms";
import {
  buildDg1,
  buildDg11,
  sha256Digest,
  wrapDg1Container,
} from "@/logic/pid-mrtd/dg";
import { bytesToBase64Url } from "@/logic/pid-mrtd/encoding";
import {
  type MrtdValidationJwtClaims,
  mrtdValidationJwtClaimsSchema,
} from "@/logic/pid-mrtd/schemas";

export interface BuildMrtdDocumentArtifactsParams {
  challenge: string;
  ias: EphemeralIasPki;
  identity: PidIdentityConfig;
  mrz?: string;
  pki: LoadedPidMrtdPki;
}

export interface MrtdDocumentArtifacts {
  challengeSigned: string;
  dg1: Uint8Array;
  dg11: Uint8Array;
  sodIas: Uint8Array;
  sodMrtd: Uint8Array;
}

export interface SignMrtdValidationJwtParams {
  claims: MrtdValidationJwtClaims;
  walletPrivateJwk: JWK;
}

/** Maps binary artifacts to base64url JWT claim strings (pre-signing). */
export function assembleMrtdValidationJwtClaims(
  artifacts: MrtdDocumentArtifacts,
  mrz?: string,
): MrtdValidationJwtClaims {
  return mrtdValidationJwtClaimsSchema.parse({
    challenge_signed: artifacts.challengeSigned,
    dg1: bytesToBase64Url(artifacts.dg1),
    dg11: bytesToBase64Url(artifacts.dg11),
    mrz,
    sod_ias: bytesToBase64Url(artifacts.sodIas),
    sod_mrtd: bytesToBase64Url(artifacts.sodMrtd),
  });
}

/**
 * Builds DG1/DG11, SOD_MRTD, SOD_IAS, and `challenge_signed` for the L2+ validation JWT.
 */
export async function buildMrtdDocumentArtifacts(
  params: BuildMrtdDocumentArtifactsParams,
): Promise<MrtdDocumentArtifacts> {
  const mrz = params.mrz ?? params.identity.mrz;
  if (!mrz) {
    throw new Error(
      "MRZ is required to build MRTD document artifacts for l2plus",
    );
  }

  const nun = params.identity.personal_administrative_number;
  if (!nun) {
    throw new Error(
      "personal_administrative_number (NUN) is required for SOD_IAS in l2plus",
    );
  }

  const dg1Raw = buildDg1(mrz);
  const dg1 = wrapDg1Container(dg1Raw);
  const dg11 = buildDg11(params.identity);

  const sodMrtd = await createSodCmsSignedData(params.pki, [
    { dataGroupNumber: 1, hash: sha256Digest(dg1) },
    { dataGroupNumber: 11, hash: sha256Digest(dg11) },
  ]);

  const sodIas = await createSodCmsSignedData(params.pki, [
    {
      dataGroupNumber: 16,
      hash: sha256Digest(new TextEncoder().encode(nun)),
    },
  ]);

  const challengeSigned = await signMrtdChallenge(
    params.challenge,
    params.ias.privateKey,
  );

  return { challengeSigned, dg1, dg11, sodIas, sodMrtd };
}

/** Signs the assembled claims as `mrtd_validation_jwt` with the wallet key (FR-18). */
export async function signMrtdValidationJwt(
  params: SignMrtdValidationJwtParams,
): Promise<string> {
  const { importJWK } = await import("jose");
  const alg = params.walletPrivateJwk.alg ?? "ES256";
  const key = await importJWK(params.walletPrivateJwk, alg);

  return new SignJWT(params.claims)
    .setProtectedHeader({ alg, typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(key);
}
