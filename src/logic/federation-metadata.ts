import {
  createItWalletEntityConfiguration,
  ItWalletEntityConfigurationClaimsOptions,
  SignCallback,
} from "@pagopa/io-wallet-oid-federation";

import { Config } from "@/types/Config";

import { signCallback } from "../logic/jwt";
import { KeyPair, KeyPairJwk } from "../types/KeyPair";
import { loadJsonDumps, loadJwks } from "./utils";

export interface CreateFederationMetadataOptions {
  claims: ItWalletEntityConfigurationClaimsOptions;

  /**
   * The public JWK of the entity to include the federation metadata.
   */
  entityPublicJwk: KeyPairJwk;

  /**
   * The JWKS used to sign the federation metadata.
   */
  signedJwks: KeyPair;
}

export const createFederationMetadata = async (
  options: CreateFederationMetadataOptions,
): Promise<string> => {
  const { privateKey, publicKey } = options.signedJwks;
  const iat = Math.floor(Date.now() / 1000);

  const signJwtCallback: SignCallback = async ({ toBeSigned }) =>
    signCallback({ jwk: privateKey, toBeSigned });

  const entityJwks = [options.entityPublicJwk];
  // Ensure the signing key is included in the JWKS
  if (options.entityPublicJwk.kid !== publicKey.kid) {
    entityJwks.push(publicKey);
  }

  return await createItWalletEntityConfiguration({
    claims: {
      ...options.claims,
      exp: iat + 3600,
      iat,
      jwks: {
        keys: entityJwks,
      },
    },
    header: { alg: "ES256", kid: publicKey.kid, typ: "entity-statement+jwt" },
    signJwtCallback,
  });
};

/**
 * Creates the trust anchor federation metadata JWT.
 * @param federationTrustAnchorsJwksPath Path to the folder containing the trust anchor JWKS files.
 * @returns The signed federation metadata JWT as a string.
 */
export const createTrustAnchorMetadata = async (
  federationTrustAnchorsJwksPath: Config["trust"]["federation_trust_anchors_jwks_path"],
): Promise<string> => {
  const placeholders = {
    sub: "https://127.0.0.1:3001",
    trust_anchor_base_url: "https://127.0.0.1:3001",
  };
  const claims = loadJsonDumps("trust_anchor_metadata.json", placeholders);
  const signedJwks = await loadJwks(
    federationTrustAnchorsJwksPath,
    "trust_anchor_jwks",
  );
  return await createFederationMetadata({
    claims,
    entityPublicJwk: signedJwks.publicKey,
    signedJwks,
  });
};

/**
 * Options for creating a Trust Anchor's entity statement about a subordinate entity.
 */
export interface CreateSubordinateEntityStatementOptions {
  /**
   * Public JWK of the subordinate entity (e.g., wallet provider).
   * This key will be included in the entity statement.
   */
  entityPublicJwk: KeyPairJwk;

  /**
   * Path to the folder containing the trust anchor JWKS files.
   * The trust anchor's private key will be used to sign the entity statement.
   */
  federationTrustAnchorsJwksPath: Config["trust"]["federation_trust_anchors_jwks_path"];

  /**
   * Subject (sub) claim - the identifier of the subordinate entity.
   * Typically the base URL of the subordinate entity (e.g., wallet provider URL).
   */
  sub: string;
}

/**
 * Creates an entity statement signed by the Trust Anchor for a subordinate entity.
 *
 * In OpenID Federation, the Trust Anchor issues entity statements about its subordinates
 * (e.g., wallet providers). This function creates such a statement, signed by the Trust
 * Anchor's private key, containing metadata about the subordinate entity.
 *
 * @param options Options for creating the entity statement.
 * @returns The signed entity statement JWT (signed by Trust Anchor, about the subordinate).
 */
export const createSubordinateTrustAnchorMetadata = async (
  options: CreateSubordinateEntityStatementOptions,
): Promise<string> => {
  const placeholders = {
    sub: options.sub,
    trust_anchor_base_url: "https://127.0.0.1:3001",
  };
  const claims = loadJsonDumps("trust_anchor_metadata.json", placeholders);
  const signedJwks = await loadJwks(
    options.federationTrustAnchorsJwksPath,
    "trust_anchor_jwks",
  );
  return await createFederationMetadata({
    claims,
    entityPublicJwk: options.entityPublicJwk,
    signedJwks,
  });
};
