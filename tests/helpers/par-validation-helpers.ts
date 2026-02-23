import {
  createClientAttestationPopJwt,
  CreatePushedAuthorizationRequestOptions,
  Jwk,
  JwtSignerJwk,
  SignJwtCallback,
} from "@pagopa/io-wallet-oauth2";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";

import { partialCallbacks, signJwtCallback } from "@/logic";
import {
  PushedAuthorizationRequestDefaultStep,
  PushedAuthorizationRequestResponse,
  PushedAuthorizationRequestStepOptions,
} from "@/step/issuance/pushed-authorization-request-step";
import { AttestationResponse, KeyPairJwk } from "@/types";

/**
 * Options to build a custom OAuth-Client-Attestation-PoP JWT for negative tests.
 */
export interface TamperedPopOptions {
  /** Audience (authorization server identifier) */
  authorizationServer: string;
  /** The wallet attestation JWT to embed in the PoP */
  clientAttestation: string;
  /** Override: use a specific expiry (e.g. Date in the past for an expired PoP) */
  expiresAt?: Date;
  /** Override: use a specific `issuedAt` */
  issuedAt?: Date;
  /** Override: use a fixed jti (for replay tests) */
  jti?: string;
  /** The real unit-key pair from the wallet attestation (used as default signer) */
  realUnitKey: KeyPairJwk;
  /** Override: use a completely different (wrong) key pair to sign the PoP */
  useWrongKey?: boolean;
  /** Override: set a custom `aud` claim instead of the real issuer */
  wrongAud?: string;
}

/**
 * JWA algorithm identifier union.
 * Used to constrain algorithm parameters to valid JWA algorithm names.
 */
type JwaAlg = "ES256" | "ES384" | "ES512" | "HS256" | "RS256";

/**
 * Builds a (possibly tampered) OAuth-Client-Attestation-PoP JWT.
 *
 * By default it creates a valid PoP. Pass overrides to produce negative test cases:
 * - `useWrongKey: true` — sign with a fresh random key (signature won't verify against cnf.jwk)
 * - `wrongAud` — set a bad audience claim
 * - `expiresAt` — control the expiry (pass a past date for an expired PoP)
 * - `jti` — fix the jti for replay tests
 */
export async function buildTamperedPopJwt(
  options: TamperedPopOptions,
): Promise<string> {
  const {
    authorizationServer,
    clientAttestation,
    expiresAt,
    issuedAt,
    jti,
    realUnitKey,
    useWrongKey,
    wrongAud,
  } = options;

  if (useWrongKey) {
    // Generate a fresh key that has no relation to the wallet attestation cnf.jwk
    const { privateKey, publicKey } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const wrongPrivateJwk = {
      ...(await exportJWK(privateKey)),
      kid: "wrong-pop-key",
      kty: "EC" as const,
    };
    const wrongPublicJwk = {
      ...(await exportJWK(publicKey)),
      kid: "wrong-pop-key",
      kty: "EC" as const,
    };

    const customCallbacks = {
      ...partialCallbacks,
      signJwt: signJwtCallback([wrongPrivateJwk]),
    };

    return createClientAttestationPopJwt({
      authorizationServer: wrongAud ?? authorizationServer,
      callbacks: customCallbacks,
      clientAttestation,
      expiresAt,
      issuedAt,
      jti,
      signer: {
        alg: "ES256",
        kid: wrongPublicJwk.kid,
        method: "jwk",
        publicJwk: wrongPublicJwk as Jwk,
      },
    });
  }

  // Use the real unit key as signer, optionally overriding aud/exp/jti
  const realCallbacks = {
    ...partialCallbacks,
    signJwt: signJwtCallback([realUnitKey]),
  };

  const signer: JwtSignerJwk = {
    alg: realUnitKey.alg ?? "ES256",
    kid: realUnitKey.kid,
    method: "jwk",
    // Strip private key fields
    publicJwk: (({ d, dp, dq, p, q, qi, alg: _alg, ...pub }) => pub)(
      realUnitKey,
    ) as Jwk,
  };

  return createClientAttestationPopJwt({
    authorizationServer: wrongAud ?? authorizationServer,
    callbacks: realCallbacks,
    clientAttestation,
    expiresAt,
    issuedAt,
    jti,
    signer,
  });
}

/**
 * Creates a fake AttestationResponse whose wallet attestation JWT is signed
 * by a fresh key pair that is NOT registered with the local Trust Anchor.
 *
 * When the issuer tries to resolve the trust chain for this attestation it will
 * find an unregistered key and should reject the PAR request.
 */
export async function createFakeAttestationResponse(): Promise<
  Omit<AttestationResponse, "created">
> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = "fake-unregistered-key-id";

  const fakeKey: { privateKey: KeyPairJwk; publicKey: KeyPairJwk } = {
    privateKey: { ...privateJwk, kid, kty: "EC" as const },
    publicKey: { ...publicJwk, kid, kty: "EC" as const },
  };

  // Build a minimal wallet-attestation JWT signed by the unregistered key.
  // The trust_chain header would reference this key which the TA cannot resolve.
  const signingKey = await importJWK(privateJwk, "ES256");
  const fakeAttestation = await new SignJWT({
    cnf: { jwk: fakeKey.publicKey },
    iss: "https://wallet-provider.example.fake",
    sub: "fake-wallet-instance",
  })
    .setProtectedHeader({ alg: "ES256", kid })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(signingKey);

  return {
    attestation: fakeAttestation,
    providerKey: fakeKey,
    unitKey: fakeKey,
  };
}

/**
 * Returns a SignJwtCallback that signs the JWT normally but then mutates
 * a claim in the payload without re-signing (breaking the cryptographic
 * signature integrity).
 * The issuer should reject because the signature no longer matches the payload.
 */
export function signThenTamperPayload(
  realPrivateKey: KeyPairJwk,
  realPublicKey: KeyPairJwk,
  field: string,
  value: unknown,
): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const key = await importKeyPairJwk(realPrivateKey);
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader(header)
      .sign(key);

    const tampered = tamperJwtPayload(jwt, field, value);

    return {
      jwt: tampered,
      signerJwk: realPublicKey as Jwk,
    };
  };
}

/**
 * Returns a SignJwtCallback that signs with the real key but injects a custom
 * `iss` claim in the JWT payload.
 * The issuer should reject because `iss` must equal `client_id`.
 */
export function signWithCustomIss(
  iss: string,
  realPrivateKey: KeyPairJwk,
  realPublicKey: KeyPairJwk,
): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const key = await importKeyPairJwk(realPrivateKey);
    const modifiedPayload = { ...(payload as Record<string, unknown>), iss };
    const jwt = await new SignJWT(modifiedPayload)
      .setProtectedHeader(header)
      .sign(key);

    return {
      jwt,
      signerJwk: realPublicKey as Jwk,
    };
  };
}

/**
 * Returns a SignJwtCallback that signs with HMAC-SHA256 (HS256).
 * HS256 is a symmetric algorithm not permitted by the IT-Wallet spec.
 * The issuer should reject the PAR as non-compliant.
 */
export function signWithHS256(secret: string): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const key = await importJWK(
      { k: Buffer.from(secret).toString("base64url"), kty: "oct" },
      "HS256",
    );
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader({ ...header, alg: "HS256" })
      .sign(key);

    return {
      jwt,
      // Cast is safe: { kty: "oct" } is structurally compatible with Jwk minimal shape
      signerJwk: { kty: "oct" } as Jwk,
    };
  };
}

/**
 * Returns a SignJwtCallback that signs with one algorithm (signAlg) but
 * declares a different algorithm (headerAlg) in the JWT header.
 *
 * This tests whether the issuer uses the alg header to validate the signature.
 * If the issuer correctly uses headerAlg from the alg header, validation will fail
 * because the JWT was actually signed with signAlg.
 *
 * @param headerAlg - Algorithm declared in the JWT header (e.g., "ES256")
 * @param signAlg - Algorithm actually used to sign (e.g., "ES384")
 */
export function signWithMismatchedAlgorithm(
  headerAlg: JwaAlg,
  signAlg: JwaAlg,
): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    // Generate a key pair for the signing algorithm
    const { privateKey, publicKey } = await generateKeyPair(signAlg, {
      extractable: true,
    });
    const privateJwk = await exportJWK(privateKey);
    const publicJwk = await exportJWK(publicKey);

    const key = await importJWK(privateJwk, signAlg);

    // Sign with signAlg but declare headerAlg in the header
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader({ ...header, alg: headerAlg })
      .sign(key);

    return {
      jwt,
      signerJwk: publicJwk as Jwk,
    };
  };
}

/**
 * Returns a SignJwtCallback that signs with the real key but overrides the
 * `alg` header to an unexpected value (e.g. "RS256").
 * The issuer should reject because the algorithm is not in the allowed set
 * (ES256/ES384/ES512) or the alg/key type mismatch is detectable.
 *
 * When using RS256, this will generate a proper RSA key pair to sign with,
 * so the JWT is validly formed but uses the wrong key type.
 */
export function signWithWrongAlgHeader(
  alg: JwaAlg,
  realPrivateKey: KeyPairJwk,
  realPublicKey: KeyPairJwk,
): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    let key: Awaited<ReturnType<typeof importJWK>>;
    let signerJwk: Jwk;

    // If requesting RS256 but the real key is EC, generate a proper RSA key
    if (alg === "RS256" && realPrivateKey.kty === "EC") {
      const { privateKey, publicKey } = await generateKeyPair("RS256", {
        extractable: true,
      });
      const privateJwk = await exportJWK(privateKey);
      const publicJwk = await exportJWK(publicKey);

      key = await importJWK(privateJwk, "RS256");
      signerJwk = { ...publicJwk, kty: "RSA" } as Jwk;
    } else {
      // Otherwise use the real key with the specified algorithm
      key = await importKeyPairJwk(realPrivateKey);
      signerJwk = realPublicKey as Jwk;
    }

    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader({ ...header, alg })
      .sign(key);

    return {
      jwt,
      signerJwk,
    };
  };
}

/**
 * Returns a SignJwtCallback that signs with a fresh, unrelated EC key.
 * The issuer should reject the PAR because the signature doesn't match
 * the public key declared in the wallet attestation.
 */
export function signWithWrongKey(): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const { privateKey, publicKey } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const privateJwk = await exportJWK(privateKey);
    const publicJwk = await exportJWK(publicKey);

    const key = await importJWK(privateJwk, "ES256");
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader(header)
      .sign(key);

    return {
      jwt,
      signerJwk: { ...publicJwk, kty: "EC" } as Jwk,
    };
  };
}

/**
 * Returns a SignJwtCallback that signs with the real key but uses a custom
 * `kid` value in the JWS protected header.
 * The issuer should reject because the `kid` doesn't match the wallet
 * attestation public key.
 */
export function signWithWrongKid(
  kid: string,
  realPrivateKey: KeyPairJwk,
  realPublicKey: KeyPairJwk,
): SignJwtCallback {
  return async (_signer, { header, payload }) => {
    const key = await importKeyPairJwk(realPrivateKey);
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader({ ...header, kid })
      .sign(key);

    return {
      jwt,
      signerJwk: { ...realPublicKey, kid } as Jwk,
    };
  };
}

/**
 * Decodes the payload of a compact JWS, mutates a single claim, and
 * re-encodes it without re-signing — the signature becomes invalid.
 */
export function tamperJwtPayload(
  jwt: string,
  field: string,
  value: unknown,
): string {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid compact JWT format");
  const [headerPart, payloadPart, sig] = parts as [string, string, string];

  const decoded = JSON.parse(Buffer.from(payloadPart, "base64url").toString());
  decoded[field] = value;
  const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64url");
  return `${headerPart}.${tampered}.${sig}`;
}

// ---------------------------------------------------------------------------
// OAuth-Client-Attestation-PoP (CI_028) helpers
// ---------------------------------------------------------------------------

export function withParOverrides(
  StepClass: typeof PushedAuthorizationRequestDefaultStep,
  overrides: Partial<CreatePushedAuthorizationRequestOptions>,
): typeof PushedAuthorizationRequestDefaultStep {
  return class extends StepClass {
    async run(
      options: PushedAuthorizationRequestStepOptions,
    ): Promise<PushedAuthorizationRequestResponse> {
      return super.run({ ...options, createParOverrides: overrides });
    }
  } as typeof PushedAuthorizationRequestDefaultStep;
}

/**
 * Returns a step class that replaces only the `signJwt` callback while
 * preserving `generateRandom` and `hash` from `partialCallbacks`.
 *
 * This avoids the shallow-merge footgun of passing a `callbacks` object to
 * `withParOverrides` directly — doing so would silently drop `generateRandom`
 * and `hash`, causing runtime failures unrelated to the test intent.
 */
export function withSignJwtOverride(
  StepClass: typeof PushedAuthorizationRequestDefaultStep,
  signJwt: SignJwtCallback,
): typeof PushedAuthorizationRequestDefaultStep {
  return withParOverrides(StepClass, {
    callbacks: {
      ...partialCallbacks,
      signJwt,
    } as CreatePushedAuthorizationRequestOptions["callbacks"],
  });
}

/**
 * Helper to import a KeyPairJwk for signing.
 * Avoids repeated casts to Parameters<typeof importJWK>[0].
 */
async function importKeyPairJwk(
  key: KeyPairJwk,
): Promise<Awaited<ReturnType<typeof importJWK>>> {
  return importJWK(key as Parameters<typeof importJWK>[0], key.alg ?? "ES256");
}
