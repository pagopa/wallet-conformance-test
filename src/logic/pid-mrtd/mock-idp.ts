import { exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";

import type { PidIdentityConfig } from "@/types/pid-issuance";

import {
  type MockIdTokenPayload,
  mockIdTokenPayloadSchema,
  type MrtdProofJwtPayload,
  mrtdProofJwtPayloadSchema,
} from "@/logic/pid-mrtd/schemas";

/** Default mock IdP issuer (in-process simulation, REQ-03). */
export const MOCK_IDP_ISSUER = "https://mock-idp.wct.pagopa.it";

/** SPID/CIE substantial LoA for `mode = l2plus` (align with REQ-00 / PID Provider). */
export const ACR_SPID_SUBSTANTIAL = "https://www.spid.gov.it/SpidL2";

/** CIE+PIN high LoA for `mode = l3` (CI_051). */
export const ACR_CIE_HIGH = "https://www.spid.gov.it/SpidL3";

export interface MintMrtdProofJwtParams {
  issuerUrl: string;
  mrtdAuthSession?: string;
  mrtdPopJwtNonce?: string;
  state: string;
}

export interface MockIdpSignOptions {
  issuer?: string;
  /** Override signing key (defaults to ephemeral ES256 per call). */
  privateJwk?: JWK;
}

let cachedIdpKey: CryptoKey | undefined;
let cachedIdpJwk: JWK | undefined;

export function buildMrtdPopInitUrl(issuerUrl: string): string {
  const base = issuerUrl.replace(/\/+$/u, "");
  return `${base}/edoc-proof/init`;
}

export function buildMrtdPopVerifyUrl(issuerUrl: string): string {
  const base = issuerUrl.replace(/\/+$/u, "");
  return `${base}/edoc-proof/verify`;
}

/** Exposes the cached mock IdP public JWK for tests that verify JWT signatures. */
export async function getMockIdpPublicJwk(): Promise<JWK> {
  await resolveIdpSigningKey();
  if (!cachedIdpJwk) {
    throw new Error("Mock IdP public JWK not initialized");
  }
  return cachedIdpJwk;
}

/** OIDC ID Token for CIE LoA High (`l3`). */
export async function mintHighIdToken(
  identity: PidIdentityConfig,
  options?: MockIdpSignOptions,
): Promise<string> {
  const issuer = options?.issuer ?? MOCK_IDP_ISSUER;
  const key = await resolveIdpSigningKey(options);
  const claims = buildIdTokenClaims(identity, ACR_CIE_HIGH, issuer);

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", typ: "JWT" })
    .setIssuer(issuer)
    .setSubject(claims.sub)
    .setIssuedAt()
    .setExpirationTime("2h")
    .sign(key);
}

/** MRTD Proof JWT embedded in `challenge_info` after mock IdP redirect (L2+). */
export async function mintMrtdProofJwt(
  params: MintMrtdProofJwtParams,
  options?: MockIdpSignOptions,
): Promise<string> {
  const issuer = options?.issuer ?? MOCK_IDP_ISSUER;
  const key = await resolveIdpSigningKey(options);
  const initUrl = buildMrtdPopInitUrl(params.issuerUrl);

  const payload: MrtdProofJwtPayload = mrtdProofJwtPayloadSchema.parse({
    htu: initUrl,
    iss: issuer,
    mrtd_auth_session: params.mrtdAuthSession ?? crypto.randomUUID(),
    mrtd_pop_jwt_nonce: params.mrtdPopJwtNonce ?? crypto.randomUUID(),
    state: params.state,
  });

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", typ: "JWT" })
    .setIssuer(issuer)
    .setIssuedAt()
    .setExpirationTime("2h")
    .sign(key);
}

/** OIDC ID Token for SPID/CIE substantial (`l2plus` without standalone `l2`). */
export async function mintSubstantialIdToken(
  identity: PidIdentityConfig,
  options?: MockIdpSignOptions,
): Promise<string> {
  const issuer = options?.issuer ?? MOCK_IDP_ISSUER;
  const key = await resolveIdpSigningKey(options);
  const claims = buildIdTokenClaims(identity, ACR_SPID_SUBSTANTIAL, issuer);

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", typ: "JWT" })
    .setIssuer(issuer)
    .setSubject(claims.sub)
    .setIssuedAt()
    .setExpirationTime("2h")
    .sign(key);
}

/** Clears cached IdP keys (unit tests). */
export function resetMockIdpKeyCache(): void {
  cachedIdpKey = undefined;
  cachedIdpJwk = undefined;
}

function buildIdTokenClaims(
  identity: PidIdentityConfig,
  acr: string,
  issuer: string,
): MockIdTokenPayload {
  return mockIdTokenPayloadSchema.parse({
    acr,
    birthdate: identity.birthdate,
    email: identity.email,
    family_name: identity.family_name,
    given_name: identity.given_name,
    iss: issuer,
    phone_number: identity.phone_number,
    sub: identity.tax_id_code,
    tax_id_code: identity.tax_id_code,
  });
}

async function resolveIdpSigningKey(
  options?: MockIdpSignOptions,
): Promise<CryptoKey> {
  if (options?.privateJwk) {
    const key = await importJWK(options.privateJwk, "ES256");
    if (!(key instanceof CryptoKey)) {
      throw new Error("Mock IdP signing key must be a CryptoKey");
    }
    return key;
  }

  if (!cachedIdpKey) {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    cachedIdpKey = privateKey;
    cachedIdpJwk = await exportJWK(publicKey);
  }

  return cachedIdpKey;
}
