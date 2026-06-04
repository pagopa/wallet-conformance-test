import * as x509 from "@peculiar/x509";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import type { Config } from "@/types";
import type { KeyPair } from "@/types";

import { createKeys } from "@/logic/jwk";
import {
  createSignedCertificate,
  hasX509CertificateExpired,
} from "@/logic/pem";
import {
  CSCA_CERT_BASENAME,
  DSC_CERT_BASENAME,
  type PidMrtdFixturePaths,
  resolvePidMrtdFixtureDir,
  resolvePidMrtdFixturePaths,
} from "@/logic/pid-mrtd/fixture-paths";

const SIGNING_ALGORITHM = {
  hash: "SHA-256",
  name: "ECDSA",
  namedCurve: "P-256",
} as const satisfies EcdsaParams & EcKeyImportParams;

/** ICAO-style mock CSCA (Country Signing CA), ECDSA P-256. */
export const MOCK_CSCA_SUBJECT = "CN=WCT Mock CSCA,O=PagoPA,C=IT";

/** ICAO-style mock DSC (Document Signing Certificate), ECDSA P-256. */
export const MOCK_DSC_SUBJECT = "CN=WCT Mock DSC,O=PagoPA,C=IT";

const FIXTURE_VALIDITY_MS = 1000 * 60 * 60 * 24 * 365 * 10;

export interface GeneratePidMrtdFixturesOptions {
  /** When true, regenerate even if valid fixtures already exist. */
  force?: boolean;
}

/**
 * Creates CSCA/DSC fixtures when missing or expired; no-op when valid files exist.
 */
export async function ensurePidMrtdFixtures(
  fixtureDir?: string,
  config?: Pick<Config, "issuance_pid" | "wallet">,
): Promise<PidMrtdFixturePaths> {
  const dir = fixtureDir ?? resolvePidMrtdFixtureDir(config);
  return generatePidMrtdFixtures(dir);
}

/**
 * Generates persisted CSCA/DSC mock certificates for the L2+ MRTD path (FR-15/FR-16).
 * Uses `@peculiar/x509` for generation and chain verification (REQ-02.5).
 */
export async function generatePidMrtdFixtures(
  fixtureDir = resolvePidMrtdFixtureDir(),
  options: GeneratePidMrtdFixturesOptions = {},
): Promise<PidMrtdFixturePaths> {
  const paths = resolvePidMrtdFixturePaths(fixtureDir);

  if (!options.force && fixturesAreValid(paths)) {
    return paths;
  }

  removeFixtureFiles(paths);

  const cscaKeyPair = await createKeys();
  const dscKeyPair = await createKeys();

  const cscaCert = await createSelfSignedCscaCertificate(
    cscaKeyPair,
    MOCK_CSCA_SUBJECT,
  );
  const dscCert = await createSignedCertificate(
    cscaKeyPair,
    MOCK_CSCA_SUBJECT,
    dscKeyPair,
    MOCK_DSC_SUBJECT,
    false,
  );

  const cscaPrivateKey = await crypto.subtle.importKey(
    "jwk",
    cscaKeyPair.privateKey,
    SIGNING_ALGORITHM,
    true,
    ["sign"],
  );
  const dscPrivateKey = await crypto.subtle.importKey(
    "jwk",
    dscKeyPair.privateKey,
    SIGNING_ALGORITHM,
    true,
    ["sign"],
  );

  writeFixtureMaterial(
    paths.dir,
    CSCA_CERT_BASENAME,
    cscaCert.toString("pem"),
    await privateKeyToPem(cscaPrivateKey),
  );
  writeFixtureMaterial(
    paths.dir,
    DSC_CERT_BASENAME,
    dscCert.toString("pem"),
    await privateKeyToPem(dscPrivateKey),
  );

  return paths;
}

/**
 * Creates a long-lived self-signed CSCA certificate (ECDSA P-256, CA=true).
 */
async function createSelfSignedCscaCertificate(
  keyPair: KeyPair,
  subject: string,
): Promise<x509.X509Certificate> {
  const keys = await importSigningKeys(keyPair);
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + FIXTURE_VALIDITY_MS);

  return x509.X509CertificateGenerator.createSelfSigned({
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.digitalSignature, // eslint-disable-line no-bitwise
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(keys.publicKey),
    ],
    keys,
    name: subject,
    notAfter,
    notBefore,
    signingAlgorithm: SIGNING_ALGORITHM,
  });
}

function fixturesAreValid(paths: PidMrtdFixturePaths): boolean {
  if (
    !existsSync(paths.cscaCertPath) ||
    !existsSync(paths.cscaKeyPath) ||
    !existsSync(paths.dscCertPath) ||
    !existsSync(paths.dscKeyPath)
  ) {
    return false;
  }

  try {
    const cscaPem = readFileSync(paths.cscaCertPath, "utf-8");
    const dscPem = readFileSync(paths.dscCertPath, "utf-8");
    if (
      hasX509CertificateExpired(cscaPem) ||
      hasX509CertificateExpired(dscPem)
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function importSigningKeys(keyPair: KeyPair): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.privateKey,
    SIGNING_ALGORITHM,
    true,
    ["sign"],
  );
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.publicKey,
    SIGNING_ALGORITHM,
    true,
    ["verify"],
  );
  return { privateKey, publicKey };
}

async function privateKeyToPem(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("pkcs8", key);
  const b64 = Buffer.from(exported).toString("base64");
  const lines = b64.match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----\n`;
}

function removeFixtureFiles(paths: PidMrtdFixturePaths): void {
  for (const filePath of [
    paths.cscaCertPath,
    paths.cscaKeyPath,
    paths.dscCertPath,
    paths.dscKeyPath,
  ]) {
    rmSync(filePath, { force: true });
  }
}

function writeFixtureMaterial(
  dir: string,
  baseName: string,
  certPem: string,
  keyPem: string,
): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, `${baseName}.pem`), certPem);
  writeFileSync(path.join(dir, `${baseName}.key`), keyPem, { mode: 0o600 });
}
