import { Jwk } from "@pagopa/io-wallet-oauth2";
import { parseWithErrorHandling } from "@pagopa/io-wallet-oid-federation";
import { SDJwt, SDJwtInstance } from "@sd-jwt/core";
import { digest, ES256, generateSalt } from "@sd-jwt/crypto-nodejs";

import { sdJwt, VerificationError } from "@/types";

export async function validateSdJwt(
  credential: string,
  name: string,
  issuerKey: Jwk,
) {
  const jwt = parseWithErrorHandling(
    sdJwt,
    await SDJwt.extractJwt(credential),
    `Error validating sdJwt ${name}`,
  );

  // Mock signer as it's not needed for verification
  const signer = () => "";
  const verifier = await ES256.getVerifier(issuerKey);

  const sdjwt = new SDJwtInstance({
    hasher: digest,
    saltGenerator: generateSalt,
    signAlg: jwt.payload._sd_alg as string,
    signer,
    verifier,
  });

  // If validation is successful, add it to the credentials record
  if (!(await sdjwt.verify(jwt.encoded)))
    throw new VerificationError(
      `signature verification for credential ${name} failed`,
    );

  return jwt;
}
