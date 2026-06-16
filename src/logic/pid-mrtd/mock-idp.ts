import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { z } from "zod";

import { PidIdentityConfig } from "@/types/pid-issuance";

/**
 * ACR values for the Italian IT-Wallet eID flows.
 * L3 = CIE+PIN (LoA High), L2+ = SPID/CIEid (LoA Substantial).
 */
export const ACR_HIGH = "https://www.agid.gov.it/loa/3" as const;
export const ACR_SUBSTANTIAL = "https://www.spid.gov.it/SpidL2" as const;

/**
 * Minimal OIDC ID Token claim set that the PID Provider AS expects in the
 * CIE+PIN (L3) mock eID callback. Only the claims the AS uses for PID
 * issuance are validated; extra claims are allowed.
 */
const idTokenClaimsSchema = z.object({
  acr: z.string(),
  aud: z.string(),
  iss: z.string(),
  sub: z.string(),
});

export type IdTokenClaims = z.infer<typeof idTokenClaimsSchema>;

export interface MintedToken {
  /** Compact-serialized ID Token JWT */
  idToken: string;
  /**
   * `kid` that was embedded in the JWT `jwks` (JWK Set URI not used —
   * the SUT must accept unsigned/arbitrary keys in test mode).
   */
  issuerKid: string;
}

/**
 * Mints a synthetic OIDC ID Token for the L3 (CIE+PIN, LoA High) flow.
 *
 * The token is signed with an ephemeral EC P-256 key. The PID Provider AS
 * must be running in test mode (signature verification disabled) to accept it.
 *
 * @param identity - Identity attributes from `[issuance_pid]` config section.
 * @param aud      - `aud` claim — the AS client ID or issuer that will consume
 *                   this token (typically the authorization server base URL).
 * @param iss      - `iss` claim — the mock IdP identifier (e.g. the wallet
 *                   tool's own base URL or a well-known mock IdP URL).
 * @param nonce    - Optional `nonce` forwarded from the authorization request.
 */
export async function mintHighIdToken(
  identity: PidIdentityConfig,
  aud: string,
  iss: string,
  nonce?: string,
): Promise<MintedToken> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", {
    extractable: true,
  });

  const publicJwk = await exportJWK(publicKey);
  const kid = `mock-idp-${Date.now()}`;
  const publicJwkWithKid = { ...publicJwk, kid } as Parameters<
    SignJWT["setProtectedHeader"]
  >[0]["jwk"];

  const claims: Record<string, unknown> = {
    acr: ACR_HIGH,
    aud,
    birthdate: identity.birthdate,
    email: identity.email,
    family_name: identity.family_name,
    given_name: identity.given_name,
    iss,
    nationalities: identity.nationalities,
    phone_number: identity.phone_number,
    place_of_birth: identity.place_of_birth,
    sub: identity.tax_id_code,
    tax_id_code: identity.tax_id_code,
  };

  if (nonce) {
    claims["nonce"] = nonce;
  }

  for (const key of Object.keys(claims)) {
    if (claims[key] === undefined) {
      delete claims[key];
    }
  }

  const idToken = await new SignJWT(claims)
    .setProtectedHeader({
      alg: "ES256",
      jwk: publicJwkWithKid,
      kid,
      typ: "JWT",
    })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);

  return { idToken, issuerKid: kid };
}

/**
 * Mints a synthetic OIDC ID Token for the L2+ (SPID/CIEid, LoA Substantial) flow.
 *
 * Identical to `mintHighIdToken` except the `acr` is set to
 * {@link ACR_SUBSTANTIAL}. This function is reserved for future L2+ test
 * orchestration and is **not** used by the current L3 flow.
 */
export async function mintSubstantialIdToken(
  identity: PidIdentityConfig,
  aud: string,
  iss: string,
  nonce?: string,
): Promise<MintedToken> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", {
    extractable: true,
  });

  const publicJwk = await exportJWK(publicKey);
  const kid = `mock-idp-${Date.now()}`;
  const publicJwkWithKid = { ...publicJwk, kid } as Parameters<
    SignJWT["setProtectedHeader"]
  >[0]["jwk"];

  const claims: Record<string, unknown> = {
    acr: ACR_SUBSTANTIAL,
    aud,
    birthdate: identity.birthdate,
    email: identity.email,
    family_name: identity.family_name,
    given_name: identity.given_name,
    iss,
    nationalities: identity.nationalities,
    phone_number: identity.phone_number,
    place_of_birth: identity.place_of_birth,
    sub: identity.tax_id_code,
    tax_id_code: identity.tax_id_code,
  };

  if (nonce) {
    claims["nonce"] = nonce;
  }

  for (const key of Object.keys(claims)) {
    if (claims[key] === undefined) {
      delete claims[key];
    }
  }

  const idToken = await new SignJWT(claims)
    .setProtectedHeader({
      alg: "ES256",
      jwk: publicJwkWithKid,
      kid,
      typ: "JWT",
    })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);

  return { idToken, issuerKid: kid };
}
