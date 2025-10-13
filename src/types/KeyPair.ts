import { JWK } from "jose";

/**
 * Represents a cryptographic key pair, containing a private and a public key
 * in JWK format.
 */
export interface KeyPair {
  /**
   * The private key in JWK format.
   */
  privateKey: JWK;
  /**
   * The public key in JWK format.
   */
  publicKey: JWK;
}
