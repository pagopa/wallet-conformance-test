import { importJWK, SignJWT } from "jose";
import crypto from "node:crypto";

import { KeyPair } from "@/types";

/**
 * Creates a VP Token SD-JWT by combining the provided SD-JWT with a Key Binding JWT (KB-JWT).
 * @param param0
 * @returns
 */
export async function createVpTokenSdJwt({
  client_id,
  dpopJwk,
  nonce,
  sdJwt,
}: {
  client_id: string;
  dpopJwk: KeyPair["privateKey"];
  nonce: string;
  sdJwt: string;
}): Promise<string> {
  const suffixedSdJwt = sdJwt.endsWith("~") ? sdJwt : `${sdJwt}~`;
  const sd_hash = crypto
    .createHash("sha256")
    .update(suffixedSdJwt)
    .digest("base64url");

  // Use dpop key for the key binding JWT (wallet holder's key)
  const dpopPrivateKey = await importJWK(dpopJwk, "ES256");
  const kbJwt = await new SignJWT({
    nonce,
    sd_hash,
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "kb+jwt",
    })
    .setAudience(client_id)
    .setIssuedAt()
    .sign(dpopPrivateKey);

  // <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>

  return `${suffixedSdJwt}${kbJwt}`;
}

export function generateSRIHash(content: string): string {
  const digest = crypto.createHash("sha256").update(content).digest("base64");
  return `sha256-${digest}`;
}
