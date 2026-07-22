import {
  Jwk,
  type JwtSigner,
  type VerifyJwtCallback,
} from "@pagopa/io-wallet-oauth2";
import {
  fetchAndValidateTrustChain,
  jsonWebKeySchema,
  jsonWebKeySetSchema,
} from "@pagopa/io-wallet-oid-federation";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import * as x509 from "@peculiar/x509";
import {
  calculateJwkThumbprint,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importX509,
} from "jose";
import { writeFileSync } from "node:fs";

import { KeyPair, KeyPairJwk } from "@/types";

import { loadCertificate } from "./pem";
import { buildCertPath, partialCallbacksWithTrustAnchorUrls } from "./utils";

interface JwkFromSignerOptions {
  trustAnchorUrls?: string[];
}

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
 * Generates a new cryptographic key pair (ECDSA with P-256 curve) with a self-signed X.509 certificate and saves it to a file.
 *
 * @param fileName The name of the file to save the key pair to.
 * @returns A promise that resolves to the generated key pair.
 */
export async function createAndSaveKeysWithX5C(
  fileName: string,
  jwksPath: string,
  caCertPath: string,
  caSubject: string,
): Promise<KeyPair> {
  const exportedPair = await createKeys();
  const x5c = await loadCertificate(
    caCertPath,
    buildCertPath(fileName),
    exportedPair,
    caSubject,
  );
  exportedPair.publicKey.x5c = [x5c];
  writeFileSync(`${jwksPath}/${fileName}`, JSON.stringify(exportedPair));

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

  const kid = await calculateJwkThumbprint(pub, "sha256");
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
export async function jwkFromSigner(
  signer: JwtSigner,
  payload?: Parameters<VerifyJwtCallback>[1]["payload"],
  options: JwkFromSignerOptions = {},
): Promise<Jwk> {
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
      return await jwkFromFederation(
        kid,
        trustChain,
        payload,
        options.trustAnchorUrls,
      );
    case "jwk":
      return parseWithErrorHandling(
        jsonWebKeySchema,
        signer.publicJwk,
        "malformed signer's JWK",
      );
    case "x5c":
      return await jwkFromCertificateChain(signer.x5c, signer.alg, kid);
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
 * @param kid Optional key ID to inject into the extracted JWK.
 * @returns A promise that resolves to the extracted JWK.
 * @throws An error if the certificate chain is missing or empty.
 */
async function jwkFromCertificateChain(
  x5c: string[] | undefined,
  alg: string,
  kid?: string,
): Promise<Jwk> {
  if (!x5c || x5c.length === 0) {
    throw new Error("missing x5c certificate");
  }

  if (x5c.length > 1) {
    const certs = x5c.map(
      (certB64) => new x509.X509Certificate(Buffer.from(certB64, "base64")),
    );
    for (let i = 0; i < certs.length - 1; i++) {
      const cert = certs[i];
      const issuerCert = certs[i + 1];
      if (!cert || !issuerCert) break;
      const valid = await cert.verify({
        publicKey: issuerCert,
        signatureOnly: true,
      });
      if (!valid) {
        throw new Error(
          `x5c certificate chain signature invalid at index ${i}`,
        );
      }
    }
  }

  const pem = convertBase64DerToPem(x5c[0] as string);
  const key = await importX509(pem, alg, { extractable: true });
  const jwk = await exportJWK(key);
  // exportJWK() from jose doesn't add a kid when exporting from an X.509 certificate
  const jwkWithKid = kid ? { ...jwk, kid } : jwk;

  return parseWithErrorHandling(
    jsonWebKeySchema,
    jwkWithKid,
    "malformed signer's JWK from x5c",
  );
}

/**
 * Extracts a JWK from a trust chain array based on the signer's KID.
 * Also cryptographically verifies the entity configuration self-signature.
 *
 * @param trustChain An array of JWTs representing the trust chain.
 * @param signerKid The KID of the signer to look for in the trust chain.
 * @returns The JWK found in the trust chain.
 * @throws An error if the trust chain is empty, the entity config signature is invalid,
 *         or the key is not found.
 */
async function jwkFromFederation(
  signerKid: string,
  trustChain?: string[],
  payload?: Parameters<VerifyJwtCallback>[1]["payload"],
  trustAnchorUrls?: string[],
): Promise<Jwk> {
  const ecTrustChain =
    trustChain ??
    (await (() => {
      if (!payload?.iss) throw new Error("missing iss in payload");
      const trustedAnchors = toNonEmptyTrustAnchorUrls(trustAnchorUrls);
      return fetchAndValidateTrustChain(payload.iss, {
        callbacks: {
          ...partialCallbacksWithTrustAnchorUrls(trustAnchorUrls),
          fetch,
        },
        ...(trustedAnchors ? { trustAnchorUrls: trustedAnchors } : {}),
      });
    })());
  const entityConfigurationJwt = ecTrustChain ? ecTrustChain[0] : undefined;
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

function toNonEmptyTrustAnchorUrls(
  trustAnchorUrls: string[] | undefined,
): [string, ...string[]] | undefined {
  if (!trustAnchorUrls || trustAnchorUrls.length === 0) {
    return undefined;
  }

  return trustAnchorUrls as [string, ...string[]];
}
