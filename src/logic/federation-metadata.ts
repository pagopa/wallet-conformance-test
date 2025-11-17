import {
  createItWalletEntityConfiguration,
  ItWalletEntityConfigurationClaimsOptions,
  SignCallback,
} from "@pagopa/io-wallet-oid-federation";

import { Config } from "@/types/Config";

import { signCallback } from "../logic/jwt";
import { KeyPair } from "../types/KeyPair";
import { loadJsonDumps, loadJwks } from "./utils";

export interface CreateFederationMetadataOptions {
  claims: ItWalletEntityConfigurationClaimsOptions;
  jwks: KeyPair;
}

export const createFederationMetadata = async (
  options: CreateFederationMetadataOptions,
): Promise<string> => {
  const { privateKey, publicKey } = options.jwks;
  const iat = Math.floor(Date.now() / 1000);

  const signJwtCallback: SignCallback = async ({ toBeSigned }) =>
    signCallback({ jwk: privateKey, toBeSigned });

  return await createItWalletEntityConfiguration({
    claims: {
      ...options.claims,
      exp: iat + 3600,
      iat,
      jwks: {
        keys: [
          {
            ...publicKey,
          },
        ],
      },
    },
    header: { alg: "ES256", kid: publicKey.kid, typ: "entity-statement+jwt" },
    signJwtCallback,
  });
};

export interface createTrustAnchorMetadataOptions {
  federationTrustAnchorsJwksPath: Config["trust"]["federation_trust_anchors_jwks_path"];
  sub?: string;
}

/**
 * Creates the trust anchor federation metadata JWT.
 * @param federationTrustAnchorsJwksPath Path to the folder containing the trust anchor JWKS files.
 * @returns The signed federation metadata JWT as a string.
 */
export const createTrustAnchorMetadata = async (
  options: createTrustAnchorMetadataOptions,
): Promise<string> => {
  const placeholders = {
    sub: options.sub || "https://127.0.0.1:3001",
    trust_anchor_base_url: "https://127.0.0.1:3001",
  };
  const claims = loadJsonDumps("trust_anchor_metadata.json", placeholders);
  const jwks = await loadJwks(
    options.federationTrustAnchorsJwksPath,
    "trust_anchor_jwks",
  );
  return await createFederationMetadata({ claims, jwks });
};
