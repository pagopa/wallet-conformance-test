import { Jwk } from "@pagopa/io-wallet-oauth2";
import { SDJwt, SDJwtInstance } from "@sd-jwt/core";
import { digest, ES256, generateSalt } from "@sd-jwt/crypto-nodejs";

import { SdJwt, sdJwt, SdJwtException } from "@/types";

export async function validateSdJwt(
  credential: string,
  name: string,
  issuerKey: Jwk,
) {
  let jwt: SdJwt;
  try {
    jwt = sdJwt.parse(await SDJwt.extractJwt(credential));
  } catch (e) {
    // TODO: format zod error
    throw e;
  }

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
    throw new SdJwtException(
      `signature verification for credential ${name} failed`,
    );

  return jwt;
}
