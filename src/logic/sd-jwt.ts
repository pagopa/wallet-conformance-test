import { importJWK, SignJWT } from "jose";
import crypto from "node:crypto";

import { VpTokenOptions } from "@/types";

/**
 * Creates a VP Token SD-JWT by combining the provided SD-JWT with a Key Binding JWT (KB-JWT).
 * @param param0
 * @returns
 */
export async function createVpTokenSdJwt(
  options: Omit<VpTokenOptions, "dcqlQuery" | "responseUri">,
): Promise<string> {
  const suffixedSdJwt = options.credential.endsWith("~")
    ? options.credential
    : `${options.credential}~`;
  const sd_hash = crypto
    .createHash("sha256")
    .update(suffixedSdJwt)
    .digest("base64url");

  // Use dpop key for the key binding JWT (wallet holder's key)
  const dpopPrivateKey = await importJWK(options.dpopJwk, "ES256");
  const kbJwt = await new SignJWT({
    nonce: options.nonce,
    sd_hash,
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "kb+jwt",
    })
    .setAudience(options.client_id)
    .setIssuedAt()
    .sign(dpopPrivateKey);

  // <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>

  return `${suffixedSdJwt}${kbJwt}`;
}

export function generateSRIHash(content: string): string {
  const digest = crypto.createHash("sha256").update(content).digest("base64");
  return `sha256-${digest}`;
}
