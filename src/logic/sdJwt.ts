import { Jwk } from "@pagopa/io-wallet-oauth2";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { SDJwt, SDJwtInstance } from "@sd-jwt/core";
import { digest, generateSalt } from "@sd-jwt/crypto-nodejs";
import { jwtVerify } from "jose";

import { SdJwt, sdJwtSchema, VerificationError } from "@/types";

/**
 * Validates a Self-Signed Digital JWT (SD-JWT).
 *
 * This function takes a credential in SD-JWT format and an issuer's public key (in JWK format)
 * to verify the JWT's integrity and authenticity. It first parses the JWT and validates its
 * structure against a predefined schema. It then uses the provided issuer key to verify the
 * signature of the JWT.
 *
 * @param {string} credential - The SD-JWT credential string to be validated.
 * @param {Jwk} issuerKey - The public key of the issuer in JWK format, used for signature verification.
 * @returns {Promise<SdJwt>} A promise that resolves with the parsed JWT if the validation is successful.
 * @throws {VerificationError} If the signature verification fails.
 * @throws {Error} If the JWT is malformed or fails schema validation.
 */
export async function validateSdJwt(
  credential: string,
): Promise<SdJwt> {
  const jwt = parseWithErrorHandling(
    sdJwtSchema,
    await SDJwt.extractJwt(credential),
    "Error validating sdJwt",
  );

  return jwt;
}
