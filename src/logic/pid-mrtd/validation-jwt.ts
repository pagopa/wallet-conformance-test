import { exportJWK, importJWK, type JWK, SignJWT } from "jose";

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
  MRTD_VALIDATION_JWT_TYP,
  type MrtdValidationJwtClaims,
  mrtdValidationJwtClaimsSchema,
} from "@/logic/pid-mrtd/schemas";

export interface AssembleMrtdValidationJwtParams {
  aud: string;
  iss: string;
}

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
  iasPublicJwk: JWK;
  sodIas: Uint8Array;
  sodMrtd: Uint8Array;
}

export interface SignMrtdValidationJwtParams {
  claims: MrtdValidationJwtClaims;
  walletPrivateJwk: JWK;
}

/** Maps binary artifacts to the normative nested JWT payload (pre-signing). */
export function assembleMrtdValidationJwtClaims(
  artifacts: MrtdDocumentArtifacts,
  params: AssembleMrtdValidationJwtParams,
): MrtdValidationJwtClaims {
  return mrtdValidationJwtClaimsSchema.parse({
    aud: params.aud,
    document_type: "cie",
    ias: {
      challenge_signed: artifacts.challengeSigned,
      ias_pk: artifacts.iasPublicJwk,
      sod_ias: bytesToBase64Url(artifacts.sodIas),
    },
    iss: params.iss,
    mrtd: {
      dg1: bytesToBase64Url(artifacts.dg1),
      dg11: bytesToBase64Url(artifacts.dg11),
      sod_mrtd: bytesToBase64Url(artifacts.sodMrtd),
    },
  });
}

/**
 * Builds DG1/DG11, SOD_MRTD, SOD_IAS, `challenge_signed`, and IAS public JWK.
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

  const iasPublicJwk = await exportJWK(params.ias.publicKey);

  return { challengeSigned, dg1, dg11, iasPublicJwk, sodIas, sodMrtd };
}

/** Signs the normative payload as `mrtd_validation_jwt` with the wallet key (FR-18). */
export async function signMrtdValidationJwt(
  params: SignMrtdValidationJwtParams,
): Promise<string> {
  const alg = params.walletPrivateJwk.alg ?? "ES256";
  const key = await importJWK(params.walletPrivateJwk, alg);
  const kid = params.walletPrivateJwk.kid;
  if (!kid) {
    throw new Error(
      "walletPrivateJwk.kid is required to sign mrtd_validation_jwt",
    );
  }

  return new SignJWT(params.claims)
    .setProtectedHeader({ alg, kid, typ: MRTD_VALIDATION_JWT_TYP })
    .setIssuer(params.claims.iss)
    .setAudience(params.claims.aud)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(key);
}
