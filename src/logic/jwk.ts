import type { JwtSigner } from "@openid4vc/oauth2";

import { KeyPair, TokenClaims, tokenClaimsSchema } from "@/types";
import { type JsonWebKey, jsonWebKeySchema } from "@openid-federation/core";
import { exportJWK, generateKeyPair } from "jose";
import KSUID from "ksuid";
import { writeFileSync } from "node:fs";

/**
 * Generates a new cryptographic key pair (ECDSA with P-256 curve),
 * saves it to a file, and returns the key pair.
 *
 * @param fileName The name of the file to save the key pair to.
 * @returns A promise that resolves to the generated key pair.
 */
export async function generateKey(fileName: string): Promise<KeyPair> {
  const keyPair = await generateKeyPair("ES256", {
    crv: "P-256",
    extractable: true,
  });
  const priv = await exportJWK(keyPair.privateKey);
  const pub = await exportJWK(keyPair.publicKey);

  const kid = KSUID.randomSync().string;
  const exportedPair: KeyPair = {
    privateKey: {
      kid: kid,
      ...priv,
    },
    publicKey: {
      kid: kid,
      ...pub,
    },
  };
  writeFileSync(fileName, JSON.stringify(exportedPair));

  return exportedPair;
}

/**
 * Extracts a JWK from a trust chain array based on the signer's KID.
 *
 * @param trustChains An array of JWTs representing the trust chain.
 * @param signerKid The KID of the signer to look for in the trust chain.
 * @returns The JWK found in the trust chain.
 * @throws An error if the trust chain is empty or the key is not found.
 */
function jwkFromTrustChain(
  trustChains: string[],
  signerKid: string,
): JsonWebKey {
  if (!trustChains[0]) throw new Error("empty trust chain");
  // TODO check if trust chain is valid
  const payload = trustChains[0].split(".")[1];

  if (!payload) throw new TypeError("malformed jwt in trust chain");

  const claims: TokenClaims = tokenClaimsSchema.parse(
    JSON.parse(Buffer.from(payload, "base64url").toString()),
  );
  const federationJwk = claims.jwks.keys.find(
    (key: JsonWebKey) => key.kid === signerKid,
  );

  if (!federationJwk) throw new Error("key not found in trust chain");

  return federationJwk;
}

/**
 * Extracts a public JWK from a JWT signer.
 *
 * @param signer The JWT signer.
 * @returns The extracted public JWK.
 * @throws An error if the signer method is not supported.
 */
export function jwkFromSigner(signer: JwtSigner): JsonWebKey {
  const { didUrl, kid, trustChain } = signer;
  let didJwk: string;

  switch (signer.method) {
    case "did":
      if (!didUrl) throw new Error("missing did JWK");

      didJwk = didUrl.split("#")[0]?.replace("did:jwk:", "");
      if (!didJwk) throw new Error(`malformed did JWK: "${didUrl}"`);

      return jsonWebKeySchema.parse(
        JSON.parse(Buffer.from(didJwk, "base64url").toString()),
      );
    case "jwk":
      return jsonWebKeySchema.parse(signer.publicJwk);
    case "federation":
      if (trustChain && trustChain.length > 0)
        return jwkFromTrustChain(trustChain, kid);
      else throw new Error("missing signer's trust chain");
    default:
      throw new Error(`signer method "${signer.method}" not supported`);
  }
}
