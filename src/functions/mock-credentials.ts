import { IssuerSignedDocument } from "@auth0/mdl";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { SDJwt } from "@sd-jwt/core";
import { Tagged } from "cbor";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import z from "zod";

import { CredentialNamespaceNotFoundError } from "@/errors";
import {
  buildCertPath,
  buildJwksPath,
  ensureDir,
  EXPIRY_LEEWAY_MS,
  hasTrustChainExpired,
  hasX509CertificateExpired,
  loadCertificate,
  loadJwks,
} from "@/logic";
import {
  Config,
  Credential,
  zDateOrDateTime,
  zTrustChain,
  zX5c,
} from "@/types";

import {
  buildMockMdlMdoc_V1_0,
  buildMockSdJwt_V1_0,
} from "./V1_0/mock-credentials";
import {
  buildMockMdlMdoc_V1_3,
  buildMockSdJwt_V1_3,
} from "./V1_3/mock-credentials";

export async function createMockMdlMdoc(
  subject: string,
  backupPath: string,
  credentialsPath: string,
  version: ItWalletSpecsVersion,
): Promise<Credential> {
  const issuerKeyPair = await loadJwks(backupPath, "issuer_mdl_mocked_jwks");

  const credentialIdentifier = "mso_mdoc_mDL";
  const { publicKey: deviceKey } = await loadJwks(
    backupPath,
    buildJwksPath(credentialIdentifier),
  );
  const issuerCertificate = await loadCertificate(
    backupPath,
    buildCertPath(credentialIdentifier),
    issuerKeyPair,
    subject,
  );

  const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000 * 365);
  let mockedMdoc: Credential;
  switch (version) {
    case ItWalletSpecsVersion.V1_0:
      mockedMdoc = await buildMockMdlMdoc_V1_0(
        expiration,
        deviceKey,
        issuerCertificate,
        issuerKeyPair,
      );
      break;
    case ItWalletSpecsVersion.V1_3:
      mockedMdoc = await buildMockMdlMdoc_V1_3(
        expiration,
        deviceKey,
        issuerCertificate,
        issuerKeyPair,
      );
      break;
    default:
      throw new Error("unimplemented IT-Wallet Specifications Version");
  }

  const pathVersion = `${credentialsPath}/${version}`;
  if (!existsSync(pathVersion))
    mkdirSync(pathVersion, {
      recursive: true,
    });

  writeFileSync(`${pathVersion}/${credentialIdentifier}`, mockedMdoc.compact);
  return mockedMdoc;
}

export async function createMockSdJwt(
  metadata: {
    iss: string;
    network: Config["network"];
    trust: Config["trust"];
    trustAnchor: Config["trust_anchor"];
  },
  backupPath: string,
  credentialsPath: string,
  version: ItWalletSpecsVersion,
): Promise<Credential> {
  const keyPair = await loadJwks(backupPath, "issuer_pid_mocked_jwks");

  const credentialIdentifier = "dc_sd_jwt_PersonIdentificationData";
  const { publicKey: unitKey } = await loadJwks(
    backupPath,
    buildJwksPath(credentialIdentifier),
  );

  const certificate = await loadCertificate(
    backupPath,
    "issuer_cert",
    keyPair,
    "CN=test_issuer",
  );

  const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000 * 365);
  let mockedSdjwt: Credential;
  switch (version) {
    case ItWalletSpecsVersion.V1_0:
      mockedSdjwt = await buildMockSdJwt_V1_0(
        metadata,
        expiration,
        unitKey,
        certificate,
        keyPair,
      );
      break;
    case ItWalletSpecsVersion.V1_3:
      mockedSdjwt = await buildMockSdJwt_V1_3(
        metadata,
        expiration,
        unitKey,
        certificate,
        keyPair,
      );
      break;
    default:
      throw new Error("unimplemented IT-Wallet Specifications Version");
  }

  const pathVersion = `${credentialsPath}/${version}`;
  ensureDir(pathVersion);

  writeFileSync(`${pathVersion}/${credentialIdentifier}`, mockedSdjwt.compact);
  return mockedSdjwt;
}

/**
 * Utility to extract the expiration date claim from an Mdoc, if present
 * @param document The mdoc document
 * @param path Path to the expiration date claim
 * @returns A {@link Date} in case the expiration date claim is found
 * @throws {Error} In case the claim is not found
 */
export function getCredentialMdocExpiration(
  document: IssuerSignedDocument,
  path: {
    claimName: string;
    namespace: string;
  },
): Date {
  const claims = document.issuerSigned.nameSpaces[path.namespace];
  if (!claims)
    throw new CredentialNamespaceNotFoundError(
      "Specified namespace not found in credential",
    );

  const claimValue = claims.find(
    (claim) => claim.elementIdentifier === path.claimName,
  )?.elementValue;

  const dateString = z
    .instanceof(Tagged)
    .transform(({ value }) => value)
    .pipe(zDateOrDateTime)
    .parse(claimValue);
  return new Date(dateString);
}

/**
 * Utility to extract the expiration date claim from an SDJwt, if present
 * @param parsed The decoded and parsed SDJwt
 * @param claimName the name of the expiration date claim name
 * @returns A {@link Date} in case the expiration date claim is found
 * @throws {Error} In case the claim is not found
 */
export function getCredentialSdJwtExpiration(
  parsed: Awaited<ReturnType<typeof SDJwt.decodeSDJwt>>,
  claimName: string,
): Date {
  const claimValue =
    parsed.jwt.payload?.[claimName] ??
    parsed.disclosures.find((disclosure) =>
      disclosure.key ? disclosure.key === claimName : false,
    )?.value;

  const dateString = zDateOrDateTime.parse(claimValue);
  return new Date(dateString);
}

/**
 * Utility to check if an MDoc credential is expired, it checks:
 * - If the trust chain is expired (the `x5chain` {@link IssuerAuth} field)
 * - If the binding key certificate is expired (the `certificate` {@link IssuerAuth} field)
 * - If the MDoc itself is expired
 * - If the credential is expired by checking an eventual expired field
 * @param document The mdoc document
 * @param path Path to the expiration date claim, if left undefined, the expiration claim check will be skipped
 * @param checks optional config to perform only a subset of the checks, by default all checks are performed
 * @returns A {@link boolean} indicating the expiration status in case the expiration date claim is found
 * @throws {Error} In case the claim is not found
 */
export function isCredentialMdocExpired(
  document: IssuerSignedDocument,
  path?: {
    claimName: string;
    namespace: string;
  },
  checks: {
    cert: boolean;
    mdoc: boolean;
    x5chain: boolean;
  } = {
    cert: true,
    mdoc: true,
    x5chain: true,
  },
): boolean {
  const now = Date.now();
  const isCredentialExpired =
    path !== undefined &&
    getCredentialMdocExpiration(document, path).getTime() < now;

  const exp =
    document.issuerSigned.issuerAuth.decodedPayload.validityInfo.validUntil.getTime();
  const isMDocExpired = checks.mdoc && exp < now;

  const isCertExpired =
    checks.cert &&
    hasX509CertificateExpired(document.issuerSigned.issuerAuth.certificate);

  const mDocChain = document.issuerSigned.issuerAuth.x5chain;
  const isTrustChainExpired =
    checks.x5chain &&
    mDocChain !== undefined &&
    mDocChain
      .map((buffer) => Buffer.from(buffer).toString("base64"))
      .reduce<boolean>(
        (prev, cert) => prev || hasX509CertificateExpired(cert),
        false,
      );

  return (
    isCredentialExpired || isMDocExpired || isTrustChainExpired || isCertExpired
  );
}

/**
 * Utility to check if an SDJwt credential is expired, it checks:
 * - If the federation metadata is expired (the `trust_chain` header field)
 * - If the binding key certificate is expired (the `x5c` header field)
 * - If the SdJwt itself is expired
 * - If the credential is expired by checking an eventual expired field
 * @param parsed The decoded and parsed SDJwt
 * @param path Name of the expiration date claim, if left undefined, the expiration claim check will be skipped
 * @param checks optional config to perform only a subset of the checks, by default all checks are performed
 * @returns A {@link boolean} indicating the expiration status in case the expiration date claim is found
 * @throws {Error} In case the claim is not found
 */
export function isCredentialSdJwtExpired(
  parsed: Awaited<ReturnType<typeof SDJwt.decodeSDJwt>>,
  claimName?: string,
  checks: {
    jwt: boolean;
    trust_chain: boolean;
    x5c: boolean;
  } = {
    jwt: true,
    trust_chain: true,
    x5c: true,
  },
): boolean {
  const now = Date.now();
  const isCredentialExpired =
    claimName !== undefined &&
    getCredentialSdJwtExpiration(parsed, claimName).getTime() <
      now - EXPIRY_LEEWAY_MS;

  const exp = parsed.jwt.payload?.exp;
  const isJwtExpired =
    checks.jwt &&
    exp !== undefined &&
    typeof exp === "number" &&
    exp * 1000 < now - EXPIRY_LEEWAY_MS;

  const jwt_trust_chain = zTrustChain.safeParse(parsed.jwt.header?.trust_chain);
  const isTrustChainExpired =
    checks.trust_chain &&
    jwt_trust_chain.success &&
    hasTrustChainExpired(jwt_trust_chain.data);

  const jwt_x5c = zX5c.safeParse(parsed.jwt.header?.x5c);
  const isX5cExpired =
    checks.x5c &&
    jwt_x5c.success &&
    jwt_x5c.data.reduce<boolean>(
      (prev, cert) => prev || hasX509CertificateExpired(cert),
      false,
    );

  return (
    isCredentialExpired || isJwtExpired || isTrustChainExpired || isX5cExpired
  );
}
