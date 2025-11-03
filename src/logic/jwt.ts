import type {
  Jwk,
  SignJwtCallback,
  VerifyJwtCallback,
} from "@pagopa/io-wallet-oauth2";

import { SignCallback } from "@pagopa/io-wallet-oid-federation";
import { CompactSign, importJWK, type JWK, jwtVerify, SignJWT } from "jose";

import { jwkFromSigner } from ".";

/**
 * Creates a callback function for signing JWTs.
 *
 * @param privateJwks An array of private JSON Web Keys.
 * @returns A callback function that can be used to sign JWTs.
 */
export function signJwtCallback(privateJwks: JWK[]): SignJwtCallback {
  return async (signer, { header, payload }) => {
    const publicJwk = jwkFromSigner(signer);
    const privateJwk = privateJwks.find(
      (jwkPrv) => jwkPrv.kid === publicJwk.kid,
    );

    if (!privateJwk)
      throw new Error(
        `No private key available for \n${JSON.stringify(publicJwk)}`,
      );

    const key = await importJWK(privateJwk as JWK, signer.alg);

    return {
      jwt: await new SignJWT(payload).setProtectedHeader(header).sign(key),
      signerJwk: publicJwk as Jwk,
    };
  };
}

/**
 * Signs the given payload using the provided JWK and returns the raw signature bytes.
 *
 * @param toBeSigned - The payload to sign (typically the header and payload of a JWT)
 * @param jwk - The JSON Web Key to use for signing
 * @returns A Buffer containing the raw signature bytes
 */
export const signCallback: SignCallback = async ({ jwk, toBeSigned }) => {
  const alg = jwk.alg ?? "ES256";
  const key = await importJWK(jwk as unknown as JWK, alg);

  // sign with JWS compact format.
  const jws = await new CompactSign(toBeSigned)
    .setProtectedHeader({ alg: alg })
    .sign(key);

  // JWS compact format is "header.payload.signature"
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error("JWS compact format is not valid");
  }
  const signatureBase64Url = parts[2];
  if (!signatureBase64Url) {
    throw new Error("Invalid JWS format: signature part is empty");
  }
  const signatureBytes = new Uint8Array(
    Buffer.from(signatureBase64Url, "base64"),
  );

  return signatureBytes;
};

/**
 * Verifies a JWT with the signer's public key.
 *
 * @param signer The JWT signer.
 * @param jwt The JWT to verify.
 * @returns A promise that resolves to an object containing the verification result.
 */
export const verifyJwt: VerifyJwtCallback = async (signer, jwt) => {
  const publicJwk = jwkFromSigner(signer);
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
