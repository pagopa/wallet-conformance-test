import { JwtPayload } from "@pagopa/io-wallet-oauth2";
import {
  StatusList,
  StatusListJWTHeaderParameters,
} from "@sd-jwt/jwt-status-list";

import { StatusListTokenCreationError } from "@/errors";
import { Config } from "@/types";

import { signJwtCallback } from "./jwt";
import { hasObjectProperties, loadJwksWithX5C } from "./utils";

export interface CreateStatusListTokenOptions {
  statusListEndpointBaseUrl: string;
  trustAnchor: Config["trust"];
}

/**
 * Creates a signed Status List JWT for the Trust Anchor.
 *
 * Every mocked credential refers to index 0 of the status list, which is
 * always VALID (0x00). Four bits per status entry are used because the IT
 * Wallet specification mandates support for at least five credential states.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/credential-revocation.html#token-status-lists
 *
 * @param options Options for creating the status list token.
 * @returns The signed status list JWT as a string.
 * @throws An error if the trust anchor key pair is missing the required `alg` or `x5c` fields.
 */
export const createStatusListToken = async (
  options: CreateStatusListTokenOptions,
): Promise<string> => {
  //Set the status as VALID (0x00)
  const list = new StatusList([0], 4);
  const { privateKey, publicKey } = await loadJwksWithX5C(
    options.trustAnchor.federation_trust_anchors_jwks_path,
    "trust_anchor",
    options.trustAnchor.ca_cert_path,
    options.trustAnchor.certificate_subject,
  );

  try {
    hasObjectProperties(publicKey, ["alg", "x5c"]);
  } catch (e) {
    if (e instanceof Error) {
      throw new StatusListTokenCreationError(
        `Error creating status list token, details: ${e.message}`,
      );
    }
    throw new StatusListTokenCreationError(
      `Error creating status list token, details: ${JSON.stringify(e)}`,
    );
  }

  const header: StatusListJWTHeaderParameters = {
    alg: publicKey.alg,
    kid: publicKey.kid,
    typ: "statuslist+jwt",
    x5c: publicKey.x5c,
  };

  const iat = Math.floor(Date.now() / 1000);
  const payload: JwtPayload = {
    exp: iat + 86400, // 24h —  spec recommendation
    iat,
    status_list: {
      bits: list.getBitsPerStatus(),
      lst: list.compressStatusList(),
    },
    sub: `${options.statusListEndpointBaseUrl}/status-list`,
    ttl: 43200, // 12h cache TTL (≤ exp - iat)
  };

  const signResult = await signJwtCallback([privateKey])(
    {
      alg: publicKey.alg,
      kid: publicKey.kid,
      method: "x5c",
      x5c: publicKey.x5c,
    },
    {
      header,
      payload,
    },
  );

  return signResult.jwt;
};
