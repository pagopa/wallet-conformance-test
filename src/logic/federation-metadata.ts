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
   * The JWKS used to sign the federation metadata.
   */
  signedJwks: KeyPair;

  /**
   * The public JWK of the entity to include the federation metadata.
   */
  entityPublicJwk: KeyPairJwk;
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
  if(options.entityPublicJwk.kid !== publicKey.kid) {
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
  return await createFederationMetadata({ claims, signedJwks, entityPublicJwk: signedJwks.publicKey });
};


/**
 * Options for creating subordinate trust anchor federation metadata.
 */
export interface createSubordinateTrustAnchorMetadataOptions {
  /**
   * Path to the folder containing the trust anchor JWKS files.
   */
  federationTrustAnchorsJwksPath: Config["trust"]["federation_trust_anchors_jwks_path"];

  /**
   * Public JWK of the entity creating the subordinate trust anchor metadata.
   */
  entityPublicJwk: KeyPairJwk;

  /**
   * Subject (sub) claim for the entity configuration.
   * Typically the base URL of the subordinate trust anchor.
   */
  sub: string;
}

/**
 * Creates the subordinate trust anchor federation metadata JWT.
 * @param options Options for creating the subordinate trust anchor metadata.
 * @returns The signed subordinate trust anchor federation metadata JWT as a string.
 */
export const createSubordinateTrustAnchorMetadata = async (
  options: createSubordinateTrustAnchorMetadataOptions,
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
  return await createFederationMetadata({ claims, signedJwks, entityPublicJwk: options.entityPublicJwk });
};
