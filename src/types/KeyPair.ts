import { Jwk } from "@pagopa/io-wallet-oauth2";

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

export type KeyPairJwk = Jwk & { kid: string } & { kty: "EC" | "RSA" };
