import { decodeJwt, Jwk, type JwtSigner } from "@pagopa/io-wallet-oauth2";
import {
  itWalletEntityStatementClaimsSchema,
  jsonWebKeySchema,
} from "@pagopa/io-wallet-oid-federation";
import { Fetch, parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import * as x509 from "@peculiar/x509";
import {
  compactVerify,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  importX509,
  type JWK,
  jwtVerify,
} from "jose";
import KSUID from "ksuid";
import { writeFileSync } from "node:fs";

import { KeyPair, KeyPairJwk } from "@/types";

import { buildCertPath, loadCertificate } from "./utils";
import z from "zod";

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
 * For federation signers, the trust chain is verified end-to-end. If the signer
 * does not include a trust chain, it is resolved automatically via the OID-FED
 * `authority_hints` + `federation_fetch_endpoint` mechanism using `options.issuerUrl`
 * as the starting entity URL.
 *
 * @param signer The JWT signer.
 * @param trustAnchorUrls Optional list of trusted TA base URLs for anchor binding.
 * @param options Optional fetch function and issuer URL used when the trust chain
 *   must be resolved from the network.
 * @returns The extracted public JWK.
 * @throws An error if the signer method is not supported.
 */
export async function jwkFromSigner(
  signer: JwtSigner,
  trustAnchorUrls?: string[],
  options?: {
    fetch?: Fetch;
    issuerUrl?: string;
  },
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
    case "federation": {
      if (!kid) throw new Error("missing signer key's kid");
      let chain: string[];
      if (trustChain?.length) {
        chain = trustChain;
        await validateTrustChain(chain, trustAnchorUrls, options?.fetch);
      } else {
        if (!options?.issuerUrl) {
          throw new Error(
            "federation signer has no trust chain; provide issuerUrl in options to resolve it",
          );
        }
        chain = await fetchAndValidateTrustChain(
          options.issuerUrl,
          trustAnchorUrls ?? [],
          options.fetch ?? fetch,
        );
      }
      return await jwkFromTrustChain(chain, kid);
    }
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
 * Extracts a JWK from a certificate chain (x5c) and validates the chain.
 *
 * @param x5c An array of Base64 encoded DER certificates. The first certificate is the leaf.
 * @param alg The algorithm used for the key.
 * @param kid Optional key ID to inject into the extracted JWK.
 * @returns A promise that resolves to the extracted JWK.
 * @throws An error if the certificate chain is missing, empty, or chain validation fails.
 */
async function jwkFromCertificateChain(
  x5c: string[] | undefined,
  alg: string,
  kid?: string,
): Promise<Jwk> {
  if (!x5c || x5c.length === 0) {
    throw new Error("missing x5c certificate");
  }

  const leafPem = convertBase64DerToPem(x5c[0] as string);

  if (x5c.length > 1) {
    const leafCert = new x509.X509Certificate(
      Buffer.from(x5c[0] as string, "base64"),
    );
    const otherCerts = x5c
      .slice(1)
      .map((cert) => new x509.X509Certificate(Buffer.from(cert, "base64")));
    const builder = new x509.X509ChainBuilder({ certificates: otherCerts });
    const chain = await builder.build(leafCert);

    for (let i = 0; i < chain.length - 1; i++) {
      const cert = chain[i];
      const issuer = chain[i + 1];
      if (!cert || !issuer) continue;
      const valid = await cert.verify({
        publicKey: issuer,
        signatureOnly: true,
      });
      if (!valid) {
        throw new Error(
          `x5c certificate chain signature invalid at position ${i}`,
        );
      }
    }
  }

  const key = await importX509(leafPem, alg, { extractable: true });
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
 * Fetches an entity's self-signed configuration JWT from its well-known endpoint.
 */
async function fetchEntityConfiguration(
  entityUrl: string,
  fetchFn: Fetch,
): Promise<string> {
  const url = `${entityUrl}/.well-known/openid-federation`;
  const response = await fetchFn(url, {
    headers: { Accept: "application/entity-statement+jwt" },
  });
  if (!response.ok) {
    throw new Error(
      `failed to fetch entity configuration from ${url}: HTTP ${response.status}`,
    );
  }
  return response.text();
}

/** JWT string paired with its already-decoded payload, threaded through the pipeline. */
type ChainEntry = {
  jwt: string;
  payload: z.infer<typeof itWalletEntityStatementClaimsSchema>;
};

async function fetchECSequence(
  entityUrl: string,
  trustAnchorUrls: string[],
  fetch: Fetch,
): Promise<[ChainEntry, ...ChainEntry[]]> {
  const jwt = await fetchEntityConfiguration(entityUrl, fetch);
  const { payload } = decodeJwt({
    jwt,
    payloadSchema: itWalletEntityStatementClaimsSchema,
  });
  const entry: ChainEntry = { jwt, payload };

  const authorityHints = payload.authority_hints ?? [];
  if (!authorityHints.length) {
    throw new Error(`entity config for "${entityUrl}" has no authority_hints`);
  }

  const reachedAnchor = authorityHints.find((h) => trustAnchorUrls.includes(h));
  if (reachedAnchor) {
    const anchorJwt = await fetchEntityConfiguration(reachedAnchor, fetch);
    const { payload: anchorPayload } = decodeJwt({
      jwt: anchorJwt,
      payloadSchema: itWalletEntityStatementClaimsSchema,
    });
    return [entry, { jwt: anchorJwt, payload: anchorPayload }];
  } else {
    for (const hint of authorityHints) {
      try {
        const restChain = await fetchECSequence(hint, trustAnchorUrls, fetch);
        return [entry, ...restChain];
      } catch {
        continue;
      }
    }
    throw new Error(`no path to a trusted anchor found from "${entityUrl}"`);
  }
}

async function fetchAndVerifyECSequence(
  entityUrl: string,
  trustAnchorUrls: string[],
  fetch: Fetch,
): Promise<[ChainEntry, ...ChainEntry[]]> {
  const ecs = await fetchECSequence(entityUrl, trustAnchorUrls, fetch);

  await Promise.all(
    ecs.map(async (entry) => {
      const keys = collectKeysFromEntityConfig(entry);
      await verifyEntityConfigSignature(entry.jwt, keys);
    }),
  );

  return ecs;
}

async function ecSequenceToTrustChain(
  entityUrl: string,
  trustAnchorUrls: string[],
  fetch: Fetch,
): Promise<[ChainEntry, ...ChainEntry[]]> {
  const ecs = await fetchAndVerifyECSequence(entityUrl, trustAnchorUrls, fetch);

  const subStmtEntries: (ChainEntry | undefined)[] = await Promise.all(
    ecs.map(async (entry, idx) => {
      if (idx === ecs.length - 1) return undefined;

      const fetchEndpoint =
        ecs[idx + 1]?.payload.metadata?.federation_entity
          ?.federation_fetch_endpoint;
      if (!fetchEndpoint) {
        throw new Error(
          `superior entity at position ${idx + 1} has no federation_fetch_endpoint`,
        );
      }

      const fetchUrl = `${fetchEndpoint}?sub=${encodeURIComponent(entry.payload.sub)}`;
      const subStmtResponse = await fetch(fetchUrl, {
        headers: { Accept: "application/entity-statement+jwt" },
      });
      if (!subStmtResponse.ok) {
        throw new Error(
          `failed to fetch subordinate statement from ${fetchUrl}: HTTP ${subStmtResponse.status}`,
        );
      }

      const jwt = await subStmtResponse.text();
      const decoded = decodeJwt({
        jwt,
        payloadSchema: itWalletEntityStatementClaimsSchema,
      });
      const kid = decoded.header.kid;
      if (!kid) throw new Error("subordinate statement missing kid in header");

      // The subordinate statement is signed by the issuer (ecs[idx+1]),
      // not the subject — use the superior's JWKS to find the signing key.
      const issuerKeys = ecs[idx + 1]?.payload.jwks.keys;
      if (!issuerKeys)
        throw new Error("issuer JWKS not found for subordinate statement");
      const pk = issuerKeys.find((key) => key.kid === kid);
      if (!pk) throw new Error(`issuer signing key with kid "${kid}" not found`);

      const importedPk = await importJWK(pk as JWK);
      await jwtVerify(jwt, importedPk);

      return { jwt, payload: decoded.payload };
    }),
  );

  const subStmts = subStmtEntries.filter((e): e is ChainEntry => e !== undefined);

  return [ecs[0]!, ...subStmts, ecs[ecs.length - 1]!];
}

async function fetchAndValidateTrustChain(
  entityUrl: string,
  trustAnchorUrls: string[],
  fetch: Fetch,
): Promise<string[]> {
  const chain = await ecSequenceToTrustChain(entityUrl, trustAnchorUrls, fetch);

  // Check exp — jwtVerify covers standard JWTs during fetch, but not the
  // CompactSign-wrapped format used by our own ECs.
  const now = Math.floor(Date.now() / 1000);
  for (let i = 0; i < chain.length; i++) {
    if ((chain[i]?.payload.exp ?? 0) < now) {
      throw new Error(`trust chain element at position ${i} has expired`);
    }
  }

  // Leaf EC subject must match the subject of the first subordinate statement.
  if (chain.length > 1 && chain[0]!.payload.sub !== chain[1]!.payload.sub) {
    throw new Error(
      "leaf EC subject does not match first subordinate statement subject",
    );
  }

  // Each subordinate statement's issuer must be the subject of the next element.
  for (let j = 1; j < chain.length - 1; j++) {
    if (chain[j]!.payload.iss !== chain[j + 1]!.payload.sub) {
      throw new Error(`trust chain link broken at position ${j}`);
    }
  }

  // The last element's issuer must be a known trust anchor.
  const lastEntry = chain[chain.length - 1]!;
  if (trustAnchorUrls.length > 0 && !trustAnchorUrls.includes(lastEntry.payload.iss)) {
    throw new Error(
      `trust chain root "${lastEntry.payload.iss}" is not a trusted anchor`,
    );
  }

  return chain.map((e) => e.jwt);
}

/**
 * Extracts the JWKS keys from a decoded entity configuration payload.
 */
function collectKeysFromEntityConfig(decoded: {
  payload: z.infer<typeof itWalletEntityStatementClaimsSchema>;
}): Jwk[] {
  return decoded.payload.jwks.keys as unknown as Jwk[];
}

/**
 * Cryptographically validates an inline (pre-built) trust chain.
 *
 * Used when the signer supplies a trust chain directly rather than having it
 * fetched from the network. Verifies every element's signature, checks `exp`,
 * enforces structural `iss`/`sub` consistency, and optionally binds the root
 * to a known trust anchor.
 *
 * The first element must be the leaf EC (self-signed). The last element must
 * be the trust anchor EC (self-signed). Intermediate elements are subordinate
 * statements; the last sub-stmt is verified against the anchor's keys, earlier
 * ones require `fetchFn` to resolve the intermediate issuer's EC on demand.
 *
 * @param trustChain Array of JWTs forming the chain.
 * @param trustAnchorUrls Optional list of trusted TA URLs for anchor binding.
 * @param fetch Optional fetch function to resolve intermediate issuer keys.
 * @throws If any signature is invalid, any element is expired, the structural
 *   links are broken, or the root is not a trusted anchor.
 */
async function validateTrustChain(
  trustChain: string[],
  trustAnchorUrls?: string[],
  fetch?: Fetch,
): Promise<void> {
  if (!trustChain[0]) throw new Error("empty trust chain");

  const decoded = trustChain.map((jwt) =>
    decodeJwt({ jwt, payloadSchema: itWalletEntityStatementClaimsSchema }),
  );

  // Check exp on every element — jwtVerify handles it for standard JWTs but
  // not for the CompactSign-wrapped format used by our own ECs.
  const now = Math.floor(Date.now() / 1000);
  for (let i = 0; i < decoded.length; i++) {
    if ((decoded[i]?.payload.exp ?? 0) < now) {
      throw new Error(`trust chain element at position ${i} has expired`);
    }
  }

  // Verify the leaf EC's self-signature.
  const leafKeys = collectKeysFromEntityConfig(decoded[0]!);
  await verifyEntityConfigSignature(trustChain[0], leafKeys);

  // Verify the trust anchor EC's self-signature and anchor binding.
  const anchorJwt = trustChain[trustChain.length - 1]!;
  const anchorDecoded = decoded[decoded.length - 1]!;
  const anchorKeys = collectKeysFromEntityConfig(anchorDecoded);
  await verifyEntityConfigSignature(anchorJwt, anchorKeys);

  if (
    trustAnchorUrls?.length &&
    !trustAnchorUrls.includes(anchorDecoded.payload.iss)
  ) {
    throw new Error(
      `trust chain root "${anchorDecoded.payload.iss}" is not a trusted anchor`,
    );
  }

  // Structural consistency: leaf subject must match the first sub-stmt subject,
  // and each sub-stmt's issuer must be the subject of the following element.
  if (decoded.length > 1) {
    if (decoded[0]!.payload.sub !== decoded[1]!.payload.sub) {
      throw new Error(
        "leaf EC subject does not match first subordinate statement subject",
      );
    }
    for (let j = 1; j < decoded.length - 1; j++) {
      if (decoded[j]!.payload.iss !== decoded[j + 1]!.payload.sub) {
        throw new Error(`trust chain link broken at position ${j}`);
      }
    }
  }

  // Verify each subordinate statement's signature.
  // The last sub-stmt was signed by the TA — use the anchor keys already decoded.
  // Earlier sub-stmts require fetching the intermediate issuer's EC.
  for (let i = 1; i < trustChain.length - 1; i++) {
    const subStmtJwt = trustChain[i]!;
    const subStmtDecoded = decoded[i]!;
    const kid = subStmtDecoded.header.kid;
    if (!kid)
      throw new Error(`subordinate statement at position ${i} missing kid`);

    let issuerKeys: Jwk[];
    if (i === trustChain.length - 2) {
      issuerKeys = anchorKeys;
    } else if (fetch) {
      const issuerEcJwt = await fetchEntityConfiguration(
        subStmtDecoded.payload.iss,
        fetch,
      );
      const issuerDecoded = decodeJwt({
        jwt: issuerEcJwt,
        payloadSchema: itWalletEntityStatementClaimsSchema,
      });
      issuerKeys = collectKeysFromEntityConfig(issuerDecoded);
    } else {
      // No fetchFn — skip intermediate sub-stmt signature verification.
      continue;
    }

    const pk = issuerKeys.find((k) => k.kid === kid);
    if (!pk)
      throw new Error(
        `signing key with kid "${kid}" not found in issuer's JWKS`,
      );
    const importedPk = await importJWK(pk as JWK);
    await jwtVerify(subStmtJwt, importedPk);
  }
}

/**
 * Extracts the signer's JWK from the leaf EC of an already-validated trust chain.
 *
 * @param trustChain Array of JWTs forming the chain (must already be validated).
 * @param signerKid The KID of the key to extract from the leaf EC.
 * @returns The matching JWK.
 * @throws If the chain is empty or the key is not found.
 */
async function jwkFromTrustChain(
  trustChain: string[],
  signerKid: string,
): Promise<Jwk> {
  const leafJwt = trustChain[0];
  if (!leafJwt) throw new Error("empty trust chain");

  const decodedLeaf = decodeJwt({
    jwt: leafJwt,
    payloadSchema: itWalletEntityStatementClaimsSchema,
  });
  const keys = collectKeysFromEntityConfig(decodedLeaf);
  const federationJwk = keys.find((key) => key.kid === signerKid);
  if (!federationJwk) throw new Error("key not found in trust chain");
  return federationJwk;
}

/**
 * Cryptographically verifies a self-signed entity configuration JWT using the
 * public key declared in its own JWKS.
 *
 * Two signature formats are supported:
 * 1. Standard JWT signing (used by external issuers/verifiers): signature is over
 *    `base64url(header).base64url(payload)` — verified with `jwtVerify`.
 * 2. CompactSign-wrapped signing (used by this codebase's `signCallback`): the
 *    signature input is wrapped as the payload of an inner JWS, i.e. the signature
 *    is over `base64url({alg}).base64url(header_b64.payload_b64)` — verified by
 *    reconstructing the inner JWS and using `compactVerify`.
 *
 * @param jwt The compact JWT to verify.
 * @param keys The keys extracted from the JWT's own payload.
 * @throws An error if no suitable verification key is found or if the signature is invalid.
 */
async function verifyEntityConfigSignature(
  jwt: string,
  keys: Jwk[],
): Promise<void> {
  const header = decodeProtectedHeader(jwt);
  const signingKey = keys.find((k) => k.kid === header.kid) ?? keys[0];
  if (!signingKey) {
    throw new Error(
      "no key found in entity configuration to verify its signature",
    );
  }
  const alg =
    (signingKey as { alg?: string }).alg ?? (header.alg as string) ?? "ES256";
  const cryptoKey = await importJWK(signingKey as JWK, alg);

  // Try standard JWT signature verification first (external entity configs).
  try {
    await jwtVerify(jwt, cryptoKey);
    return;
  } catch {
    // Fall through to try the CompactSign-wrapped format.
  }

  // Fallback: entity configs created with signCallback embed the standard JWT
  // signing input (header_b64.payload_b64) as the payload of an inner JWS.
  // Reconstruct that inner JWS and use compactVerify to verify the signature.
  const [headerB64, payloadB64, signatureB64] = jwt.split(".");
  if (!headerB64 || !payloadB64 || !signatureB64) {
    throw new Error("malformed JWT in trust chain");
  }
  const jwsHeaderB64 = Buffer.from(JSON.stringify({ alg })).toString(
    "base64url",
  );
  const toBeSignedB64 = Buffer.from(`${headerB64}.${payloadB64}`).toString(
    "base64url",
  );
  const reconstructedJws = `${jwsHeaderB64}.${toBeSignedB64}.${signatureB64}`;
  await compactVerify(reconstructedJws, cryptoKey);
}
