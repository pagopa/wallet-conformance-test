import type {
  EncryptJweCallback,
  JweEncryptor,
  Jwk,
  SignJwtCallback,
  VerifyJwtCallback,
} from "@pagopa/io-wallet-oauth2";

import { SignCallback } from "@pagopa/io-wallet-oid-federation";
import {
  CompactEncrypt,
  importJWK,
  type JWK,
  jwtVerify,
  SignJWT,
} from "jose";

import { jwkFromSigner } from "./jwk";

/**
 * Creates a callback function for signing JWTs.
 *
 * @param privateJwks An array of private JSON Web Keys.
 * @returns A callback function that can be used to sign JWTs.
 */
export function signJwtCallback(privateJwks: JWK[]): SignJwtCallback {
  return async (signer, { header, payload }) => {
    const publicJwk = await jwkFromSigner(signer);
    const privateJwk = privateJwks.find(
      (jwkPrv) => jwkPrv.kid === publicJwk.kid,
    );

    if (!privateJwk)
      throw new Error(
        `No private key available for \n${JSON.stringify(publicJwk)}`,
      );

    const key = await importJWK(privateJwk as JWK, signer.alg);
    const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(key);
    return {
      jwt,
      signerJwk: publicJwk as Jwk,
    };
  };
}

/**
 * Signs the given payload using the provided JWK and returns the raw signature bytes.
 *
 * @param toBeSigned - The signing input bytes ("header_b64url.payload_b64url")
 * @param jwk - The JSON Web Key to use for signing
 * @returns A Uint8Array containing the raw signature bytes
 */
export const signCallback: SignCallback = async ({ jwk, toBeSigned }) => {
  const alg = jwk.alg ?? "ES256";
  const key = await importJWK(jwk as unknown as JWK, alg);

  // crypto.subtle.sign requires the hash algorithm to be specified explicitly as a
  // Web Crypto API name ("SHA-256", "SHA-384", "SHA-512"), whereas JWA algorithm names
  // (e.g. "ES256") encode both the curve and the hash in a single string.
  // importJWK already selects the correct curve from the JWK, but crypto.subtle
  // does not derive the hash automatically — it must be passed separately.
  // ES256 → SHA-256, ES384 → SHA-384, ES512 → SHA-512 (per RFC 7518 §3.4).
  const hashAlgorithm = alg === "ES384" ? "SHA-384" : alg === "ES512" ? "SHA-512" : "SHA-256";
  const signatureBuffer = await crypto.subtle.sign(
    { name: "ECDSA", hash: hashAlgorithm },
    key as CryptoKey,
    // Buffer.from copies bytes into a plain ArrayBuffer, satisfying BufferSource type
    Buffer.from(toBeSigned),
  );

  return new Uint8Array(signatureBuffer);
};

/**
 * Verifies a JWT with the signer's public key.
 *
 * @param signer The JWT signer.
 * @param jwt The JWT to verify.
 * @returns A promise that resolves to an object containing the verification result.
 */
export const verifyJwt: VerifyJwtCallback = async (signer, jwt) => {
  const publicJwk = await jwkFromSigner(signer);
  const key = await importJWK(publicJwk as JWK, signer.alg);

  try {
    await jwtVerify(jwt.compact, key);

    return {
      signerJwk: publicJwk as Jwk,
      verified: true,
    };
  } catch {
    return {
      verified: false,
    };
  }
};

/**
 * Returns a callback function for JWE encryption.
 *
 * The returned callback can be used to encrypt data using the provided public key
 * and JWE header parameters.
 *
 * @param publicKey The public JWK to use for encryption.
 * @param header The JWE header parameters.
 * @returns An `EncryptJweCallback` function.
 */
export function getEncryptJweCallback(publicKey: Jwk): EncryptJweCallback {
  return async (jweEncryptor: JweEncryptor, data: string) => {
    const key = await importJWK(publicKey, jweEncryptor.alg);

    const plaintext = new TextEncoder().encode(data);
    const jwe = await new CompactEncrypt(plaintext)
      .setProtectedHeader({
        alg: jweEncryptor.alg,
        enc: jweEncryptor.enc,
        kid: publicKey.kid,
      })
      .encrypt(key);

    return {
      encryptionJwk: publicKey,
      jwe: jwe,
    };
  };
}
