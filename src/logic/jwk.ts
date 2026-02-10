import { Jwk, type JwtSigner } from "@pagopa/io-wallet-oauth2";
import {
  jsonWebKeySchema,
  jsonWebKeySetSchema,
} from "@pagopa/io-wallet-oid-federation";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { decodeJwt, exportJWK, generateKeyPair, importX509 } from "jose";
import KSUID from "ksuid";
import { writeFileSync } from "node:fs";

import { KeyPair, KeyPairJwk } from "@/types";

/**
 * Generates a new cryptographic key pair (ECDSA with P-256 curve) and saves it to a file.
 *
 * @param fileName The name of the file to save the key pair to.
 * @returns A promise that resolves to the generated key pair.
 */
export async function createAndSaveKeys(fileName: string): Promise<KeyPair> {
  const exportedPair = await createKeys();
  writeFileSync(fileName, JSON.stringify(exportedPair));

  return exportedPair;
}

/**
 * Generates a new cryptographic key pair (ECDSA with P-256 curve)
 * and returns the key pair without saving it to a file.
 *
 * @returns A promise that resolves to the generated key pair.
 */
export async function createKeys(): Promise<KeyPair> {
  const keyPair = await generateKeyPair("ES256", {
    crv: "P-256",
    extractable: true,
  });
  const priv = await exportJWK(keyPair.privateKey);
  const pub = await exportJWK(keyPair.publicKey);

  const kid = KSUID.randomSync().string;
  const exportedPair: KeyPair = {
    privateKey: parseWithErrorHandling(jsonWebKeySchema, {
      alg: "ES256",
      kid: kid,
      ...priv,
    }) as KeyPairJwk,
    publicKey: parseWithErrorHandling(jsonWebKeySchema, {
      alg: "ES256",
      kid: kid,
      ...pub,
    }) as KeyPairJwk,
  };

  return exportedPair;
}

/**
 * Extracts a public JWK from a JWT signer.
 *
 * @param signer The JWT signer.
 * @returns The extracted public JWK.
 * @throws An error if the signer method is not supported.
 */
export async function jwkFromSigner(signer: JwtSigner): Promise<Jwk> {
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
        jsonWebKeySchema,
        JSON.parse(Buffer.from(didJwk, "base64url").toString()),
        "malformed signer's JWK in DID",
      );
    case "federation":
      if (!kid) throw new Error("missing signer key's kid");
      if (!trustChain || !trustChain.length) {
        throw new Error("missing signer's trust chain");
      }
      return jwkFromTrustChain(trustChain, kid);
    case "jwk":
      return parseWithErrorHandling(
        jsonWebKeySchema,
        signer.publicJwk,
        "malformed signer's JWK",
      );
    case "x5c":
      return await jwkFromCertificateChain(signer.x5c, signer.alg);
    default:
      throw new Error(`signer method "${signer.method}" not supported`);
  }
}

/**
 * Converts a Base64 encoded DER certificate to PEM format.
 *
 * @param certificate The Base64 encoded DER certificate.
 * @returns The certificate in PEM format.
 */
function convertBase64DerToPem(certificate: string): string {
  return `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;
}

/**
 * Extracts a JWK from a certificate chain (x5c).
 *
 * @param x5c An array of Base64 encoded DER certificates. The first certificate is used.
 * @param alg The algorithm used for the key.
 * @returns A promise that resolves to the extracted JWK.
 * @throws An error if the certificate chain is missing or empty.
 */
async function jwkFromCertificateChain(
  x5c: string[] | undefined,
  alg: string,
): Promise<Jwk> {
  if (!x5c || x5c.length === 0) {
    throw new Error("missing x5c certificate");
  }

  const pem = convertBase64DerToPem(x5c[0] as string);
  const key = await importX509(pem, alg, { extractable: true });
  const jwk = await exportJWK(key);

  return parseWithErrorHandling(
    jsonWebKeySchema,
    jwk,
    "malformed signer's JWK from x5c",
  );
}

/**
 * Extracts a JWK from a trust chain array based on the signer's KID.
 *
 * @param trustChain An array of JWTs representing the trust chain.
 * @param signerKid The KID of the signer to look for in the trust chain.
 * @returns The JWK found in the trust chain.
 * @throws An error if the trust chain is empty or the key is not found.
 */
function jwkFromTrustChain(trustChain: string[], signerKid: string): Jwk {
  const entityConfigurationJwt = trustChain[0];
  if (!entityConfigurationJwt) throw new Error("empty trust chain");

  const keys: Jwk[] = [];
  const decodedEntityConfig = decodeJwt(entityConfigurationJwt);

  // Get top-level jwks
  if (decodedEntityConfig.jwks) {
    keys.push(
      ...parseWithErrorHandling(jsonWebKeySetSchema, decodedEntityConfig.jwks)
        .keys,
    );
  }

  // Check also in metadata entries for additional jwks like openid_credential_verifier
  if (decodedEntityConfig.metadata) {
    for (const entry of Object.values(decodedEntityConfig.metadata)) {
      if (entry.jwks && Array.isArray(entry.jwks.keys)) {
        keys.push(
          ...parseWithErrorHandling(jsonWebKeySetSchema, entry.jwks).keys,
        );
      }
    }
  }

  const federationJwk = keys.find((key) => key.kid === signerKid);
  if (!federationJwk) throw new Error("key not found in trust chain");

  return federationJwk;
}
