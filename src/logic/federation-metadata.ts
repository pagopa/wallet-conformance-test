
import { signCallback } from "../logic/jwt";
import { KeyPair } from "../types/KeyPair";
import { 
  createItWalletEntityConfiguration, 
  ItWalletEntityConfigurationClaimsOptions, 
  SignCallback 
} from "../../../io-wallet-sdk/packages/oid-federation/dist";
import { loadJsonDumps, loadJwks } from "./utils";
import { Config } from "@/types/Config";

export interface CreateFederationMetadataOptions {
  claims: ItWalletEntityConfigurationClaimsOptions
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
      }
    },
    header: { alg: "ES256", kid: publicKey.kid, typ: "entity-statement+jwt" },
    signJwtCallback,
  });
};

export interface createTrustAnchorMetadataOptions {
  federationTrustAnchorsJwksPath: Config["trust"]["federation_trust_anchors_jwks_path"],
  iss?: string,
}

/**
 * Creates the trust anchor federation metadata JWT.
 * ..param federationTrustAnchorsJwksPath Path to the folder containing the trust anchor JWKS files.
 * ..returns The signed federation metadata JWT as a string.
 */
export const createTrustAnchorMetadata = async (options: createTrustAnchorMetadataOptions) : Promise<string> => {
    const claims = {
      ...loadJsonDumps("federation_metadata.json"),
      ...(options.iss ? { iss: options.iss } : {})
    };
    const jwks = await loadJwks(options.federationTrustAnchorsJwksPath);
    return await createFederationMetadata({ claims, jwks });
}