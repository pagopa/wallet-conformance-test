import {
  createItWalletEntityConfiguration,
  ItWalletEntityConfigurationClaimsOptions,
  SignCallback,
} from "@pagopa/io-wallet-oid-federation";
import { decodeJwt } from "@sd-jwt/decode";

import { Config, KeyPair, KeyPairJwk } from "@/types";

import { signCallback, signJwtCallback } from "./jwt";
import {
  buildJwksPath,
  CLOCK_SKEW_TOLERANCE_MS,
  loadJsonDumps,
  loadJwks,
  loadJwksWithX5C,
  VALIDITY_MS,
} from "./utils";

export interface CreateFederationMetadataOptions {
  claims: Omit<
    ItWalletEntityConfigurationClaimsOptions,
    "exp" | "iat" | "jwks"
  >;

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
  walletVersion: Config["wallet"]["wallet_version"];
}): Promise<string> => {
  const signedJwks = await loadJwksWithX5C(
    options.trustAnchor.federation_trust_anchors_jwks_path,
    "trust_anchor",
    options.trustAnchor.ca_cert_path,
    options.trustAnchor.certificate_subject,
  );
  const trust_marks = await getTrustMarks(
    options.trustAnchorBaseUrl,
    options.trustAnchor.federation_trust_anchors_jwks_path,
    options.trustAnchorBaseUrl,
  );

  const placeholders = {
    sub: options.trustAnchorBaseUrl,
    trust_anchor_base_url: options.trustAnchorBaseUrl,
    trust_marks,
  };
  const claims = loadJsonDumps(
    "trust_anchor_metadata.json",
    placeholders,
    options.walletVersion,
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
  federationTrustAnchor: Config["trust"];

  /**
   * Subject (sub) claim - the identifier of the subordinate entity.
   * Typically the base URL of the subordinate entity (e.g., wallet provider URL).
   */
  sub: string;

  /**
   * The base URL of the Trust Anchor.
   */
  trustAnchorBaseUrl: string;

  /**
   * The wallet version to use when loading JSON dumps for claim templates.
   */
  walletVersion: Config["wallet"]["wallet_version"];
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
  const signedJwks = await loadJwksWithX5C(
    options.federationTrustAnchor.federation_trust_anchors_jwks_path,
    "trust_anchor",
    options.federationTrustAnchor.ca_cert_path,
    options.federationTrustAnchor.certificate_subject,
  );
  const trust_marks = await getTrustMarks(
    options.trustAnchorBaseUrl,
    options.federationTrustAnchor.federation_trust_anchors_jwks_path,
    options.trustAnchorBaseUrl,
  );

  const placeholders = {
    sub: options.sub,
    trust_anchor_base_url: options.trustAnchorBaseUrl,
    trust_marks,
  };
  const claims = loadJsonDumps(
    "trust_anchor_metadata.json",
    placeholders,
    options.walletVersion,
  );

  return await createFederationMetadata({
    claims,
    entityPublicJwk: options.entityPublicJwk,
    signedJwks,
  });
};

/**
 * Options for creating a subordinate Credential Issuer entity statement.
 */
export interface CreateSubordinateCredentialIssuerMetadataOptions {
  sub: string;
  trustAnchor: Config["trust"];
  trustAnchorBaseUrl: string;
  walletBackupStoragePath: string;
}

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
  const signedJwks = await loadJwksWithX5C(
    options.trustAnchor.federation_trust_anchors_jwks_path,
    "trust_anchor",
    options.trustAnchor.ca_cert_path,
    options.trustAnchor.certificate_subject,
  );

  const walletJwks = await loadJwks(
    options.walletBackupStoragePath,
    buildJwksPath("wallet_unit"),
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

/**
 * Creates a subordinate Credential Issuer entity statement JWT signed by the Trust Anchor.
 *
 * @param options Options for creating the subordinate CI entity statement.
 * @returns The signed subordinate entity statement JWT.
 */
export const createSubordinateCredentialIssuerMetadata = async (
  options: CreateSubordinateCredentialIssuerMetadataOptions,
): Promise<string> => {
  const signedJwks = await loadJwksWithX5C(
    options.trustAnchor.federation_trust_anchors_jwks_path,
    "trust_anchor",
    options.trustAnchor.ca_cert_path,
    options.trustAnchor.certificate_subject,
  );

  const issuerJwks = await loadJwks(
    options.walletBackupStoragePath,
    "issuer_pid_mocked_jwks",
  );
  return await createFederationMetadata({
    claims: {
      iss: options.trustAnchorBaseUrl,
      sub: options.sub,
    },
    entityPublicJwk: issuerJwks.publicKey,
    signedJwks,
  });
};

export const hasTrustChainExpired = (trust_chain: string[]) =>
  trust_chain.some((statement) => {
    const decoded = decodeJwt(statement);
    const exp = decoded.payload.exp;
    return (
      exp === undefined ||
      typeof exp !== "number" ||
      exp * 1000 < Date.now() - CLOCK_SKEW_TOLERANCE_MS
    );
  });

export async function getTrustMarks(
  trust_anchor_base_url: string,
  jwksPath: string,
  sub: string,
): Promise<{ trust_mark: string; trust_mark_type: string }[]> {
  const id = `${trust_anchor_base_url}/trust_marks/authorization_policy/credential-issuer`;

  const jwks = await loadJwks(jwksPath, buildJwksPath("trust_anchor"));

  const iat = Math.floor(Date.now() / 1000);
  const trustMarkPayload = {
    exp: iat + (VALIDITY_MS / 1000),
    iat,
    iss: trust_anchor_base_url,
    logo_uri: "https://io.italia.it/assets/img/io-it-logo-blue.svg",
    organization_type: "private",
    sub,
    trust_mark_type: id,
  };
  const trustMarkHeader = {
    alg: jwks.privateKey.alg ?? "ES256",
    kid: jwks.privateKey.kid,
  };

  const trust_mark = await signJwtCallback([jwks.privateKey])(
    {
      alg: jwks.publicKey.alg ?? "ES256",
      kid: jwks.publicKey.kid,
      method: "jwk",
      publicJwk: jwks.publicKey,
    },
    {
      header: trustMarkHeader,
      payload: trustMarkPayload,
    },
  );

  return [
    {
      trust_mark: trust_mark.jwt,
      trust_mark_type: id,
    },
  ];
}
