import {
  createItWalletEntityConfiguration,
  ItWalletEntityConfigurationClaimsOptions,
  SignCallback,
} from "@pagopa/io-wallet-oid-federation";

import { Config, KeyPair, KeyPairJwk } from "@/types";

import { signCallback } from "./jwt";
import { loadJsonDumps, loadJwks, loadJwksWithSelfSignedX5c } from "./utils";

export interface CreateFederationMetadataOptions {
  claims: Omit<ItWalletEntityConfigurationClaimsOptions, "exp" | "iat">;

  /**
   * The public JWK of the entity to include in the federation metadata's JWKS.
   */
  entityPublicJwk: KeyPairJwk;

  /**
   * The JWKS used to sign the federation metadata.
   */
  signedJwks: KeyPair;
}

/**
 * Creates a signed JWT representing an entity's configuration in an OIDC federation.
 *
 * This function generates an "entity statement" which is a JWT that contains metadata
 * about an entity (like a wallet or trust anchor), including its public keys (JWKS).
 * The statement is signed by one of the entity's keys.
 *
 * @param options The options for creating the federation metadata.
 * @returns A promise that resolves to the signed federation metadata JWT.
 */
export const createFederationMetadata = async (
  options: CreateFederationMetadataOptions,
): Promise<string> => {
  const { privateKey, publicKey } = options.signedJwks;
  const iat = Math.floor(Date.now() / 1000);

  const signJwtCallback: SignCallback = async ({ toBeSigned }) =>
    signCallback({ jwk: privateKey, toBeSigned });

  const entityJwks = [options.entityPublicJwk];
  // Ensure the signing key is included in the JWKS if it differs from the entity's public key
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
    } as ItWalletEntityConfigurationClaimsOptions,
    header: { alg: "ES256", kid: publicKey.kid, typ: "entity-statement+jwt" },
    signJwtCallback,
  });
};

/**
 * Creates the trust anchor federation metadata JWT.
 * @param federationTrustAnchorsJwksPath Path to the folder containing the trust anchor JWKS files.
 * @returns The signed federation metadata JWT as a string.
 */
export const createTrustAnchorMetadata = async (options: {
  trustAnchor: Config["trust"];
  trustAnchorBaseUrl: string;
}): Promise<string> => {
  const placeholders = {
    sub: options.trustAnchorBaseUrl,
    trust_anchor_base_url: options.trustAnchorBaseUrl,
  };
  const claims = loadJsonDumps("trust_anchor_metadata.json", placeholders);
  const signedJwks = await loadJwksWithSelfSignedX5c(
    options.trustAnchor,
    "trust_anchor",
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

  /**
   * The base URL of the Trust Anchor.
   */
  trustAnchorBaseUrl: string;
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
    trust_anchor_base_url: options.trustAnchorBaseUrl,
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

/**
 * Options for creating subordinate wallet metadata.
 */
export interface CreateSubordinateWalletUnitMetadataOptions {
  sub: string;
  trustAnchor: Config["trust"];
  trustAnchorBaseUrl: string;
  walletBackupStoragePath: string;
}

/**
 * Creates a subordinate wallet metadata JWT signed by the Trust Anchor.
 *
 * @param options Options for creating the subordinate wallet metadata.
 * @returns The signed subordinate wallet metadata JWT.
 */
export const createSubordinateWalletUnitMetadata = async (
  options: CreateSubordinateWalletUnitMetadataOptions,
): Promise<string> => {
  const signedJwks = await loadJwksWithSelfSignedX5c(
    options.trustAnchor,
    "trust_anchor",
  );

  const walletJwks = await loadJwks(
    options.walletBackupStoragePath,
    "wallet_unit_jwks",
  );
  return await createFederationMetadata({
    claims: {
      iss: options.trustAnchorBaseUrl,
      sub: options.sub,
    },
    entityPublicJwk: walletJwks.publicKey,
    signedJwks,
  });
};
