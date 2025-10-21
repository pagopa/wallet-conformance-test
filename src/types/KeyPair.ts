import { Jwk } from "@pagopa/io-wallet-oauth2";

/**
 * Represents a cryptographic key pair, containing a private and a public key
 * in JWK format.
 */
export interface KeyPair {
  /**
   * The private key in JWK format.
   */
  privateKey: Jwk;
  /**
   * The public key in JWK format.
   */
  publicKey: Jwk;
}
