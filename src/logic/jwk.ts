import { Jwk, type JwtSigner } from "@pagopa/io-wallet-oauth2";
import {
  jsonWebKeySchema as JWK,
  jsonWebKeySetSchema as JWKS,
} from "@pagopa/io-wallet-oid-federation";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { exportJWK, generateKeyPair } from "jose";
import KSUID from "ksuid";
import { writeFileSync } from "node:fs";

import { KeyPair } from "@/types";

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
    privateKey: parseWithErrorHandling(JWK, {
      kid: kid,
      ...priv,
    }),
    publicKey: parseWithErrorHandling(JWK, {
      kid: kid,
      ...pub,
    }),
  };
  writeFileSync(fileName, JSON.stringify(exportedPair));

  return exportedPair;
}

/**
 * Extracts a public JWK from a JWT signer.
 *
 * @param signer The JWT signer.
 * @returns The extracted public JWK.
 * @throws An error if the signer method is not supported.
 */
export function jwkFromSigner(signer: JwtSigner): Jwk {
  const { didUrl, kid, trustChain } = signer as {
    didUrl?: string;
    kid?: string;
    trustChain?: string[];
  };
  let didJwk: string | undefined;

  switch (signer.method) {
    case "did":
      if (!didUrl) throw new Error("missing DID JWK");

      didJwk = didUrl.split("#")[0]?.replace("did:jwk:", "");
      if (!didJwk || didJwk.length < 1)
        throw new Error(`malformed JWK in DID: "${didUrl}"`);

      return parseWithErrorHandling(
        JWK,
        JSON.parse(Buffer.from(didJwk, "base64url").toString()),
        "malformed signer's JWK in DID",
      );
    case "jwk":
      return parseWithErrorHandling(
        JWK,
        signer.publicJwk,
        "malformed signer's JWK",
      );
    case "federation":
      if (!kid) throw new Error("missing signer key's kid");
      if (trustChain && trustChain.length > 0)
        return jwkFromTrustChain(trustChain, kid);
      else throw new Error("missing signer's trust chain");
    default:
      throw new Error(`signer method "${signer.method}" not supported`);
  }
}

/**
 * Extracts a JWK from a trust chain array based on the signer's KID.
 *
 * @param trustChains An array of JWTs representing the trust chain.
 * @param signerKid The KID of the signer to look for in the trust chain.
 * @returns The JWK found in the trust chain.
 * @throws An error if the trust chain is empty or the key is not found.
 */
function jwkFromTrustChain(trustChains: string[], signerKid: string): Jwk {
  if (!trustChains[0]) throw new Error("empty trust chain");
  // TODO check if trust chain is valid
  const payload = trustChains[0].split(".")[1];

  if (!payload) throw new TypeError("malformed jwt in trust chain");

  const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
  const jwks = parseWithErrorHandling(JWKS, claims.jwks);
  const federationJwk = jwks.keys.find((key: Jwk) => key.kid === signerKid);

  if (!federationJwk) throw new Error("key not found in trust chain");

  return federationJwk;
}
