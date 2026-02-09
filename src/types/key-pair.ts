import { Jwk } from "@pagopa/io-wallet-oauth2";
import z from "zod";

/**
 * Represents a cryptographic key pair, containing a private and a public key
 * in JWK format.
 */
export interface KeyPair {
  /**
   * The private key in JWK format.
   */
  privateKey: KeyPairJwk;
  /**
   * The public key in JWK format.
   */
  publicKey: KeyPairJwk;
}

// export type KeyPairJwk = Jwk & { kid: string } & { kty: "EC" | "RSA" };

export const keyPairJwkSchema = z.object({
  kid: z.string(),
  kty: z.literal("EC").or(z.literal("RSA")),
  crv: z.optional(z.string()),
  x: z.optional(z.string()),
  y: z.optional(z.string()),
  e: z.optional(z.string()),
  n: z.optional(z.string()),
  alg: z.optional(z.string()),
  d: z.optional(z.string()),
  dp: z.optional(z.string()),
  dq: z.optional(z.string()),
  ext: z.optional(z.boolean()),
  k: z.optional(z.string()),
  key_ops: z.optional(z.array(z.string())),
  oth: z.optional(
    z.array(
      z.object({
        d: z.optional(z.string()),
        r: z.optional(z.string()),
        t: z.optional(z.string())
      }).passthrough()
    )
  ),
  p: z.optional(z.string()),
  q: z.optional(z.string()),
  qi: z.optional(z.string()),
  use: z.optional(z.string()),
  x5c: z.optional(z.array(z.string())),
  x5t: z.optional(z.string()),
  "x5t#S256": z.optional(z.string()),
  x5u: z.optional(z.string())
}).passthrough();

export type KeyPairJwk = z.infer<typeof keyPairJwkSchema>;
