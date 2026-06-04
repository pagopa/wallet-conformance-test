import * as x509 from "@peculiar/x509";
import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { CertificateExpiredError } from "@/errors";
import { KeyPair } from "@/types";

import { createKeys } from "./jwk";
import { CLOCK_SKEW_TOLERANCE_MS, ensureDir, VALIDITY_MS } from "./utils";

const SIGNING_ALGORITHM = {
  hash: "SHA-256",
  name: "ECDSA",
  namedCurve: "P-256",
} as const satisfies EcdsaParams & EcKeyImportParams;

/**
 * Creates a self-signed X.509 certificate and saves it to a file in PEM format.
 *
 * @param fileName The name of the file to save the certificate to.
 * @param keyPair The key pair to use for signing the certificate.
 * @param subject The subject name for the certificate.
 * @returns A promise that resolves to the base64-encoded DER representation of the certificate.
 */
export async function createAndSaveCertificate(
  fileName: string,
  keyPair: KeyPair,
  subject: string,
): Promise<string> {
  const certificate = await createCertificate(keyPair, subject);
  writeFileSync(fileName, certificate.toString("pem"));

  // Return DER string representation of the certificate
  return Buffer.from(certificate.rawData).toString("base64");
}

/**
 * Generates a key pair, creates a self-signed X.509 certificate, and writes both
 * the cert and private key to collision-resistant PEM files inside `dir`.
 *
 * The key file is written with mode 0o600 (owner read/write only) to prevent
 * accidental exposure of private key material.
 *
 * @param dir Directory to write the files into (created if absent).
 * @param baseName Base filename (without extension) for the cert and key files.
 * @param subject The subject / CN for the certificate.
 * @param extraExtensions Additional X.509 extensions appended to the default set.
 * @returns The cert PEM, key PEM, and absolute paths of the written cert and key files.
 */
export async function createAndSaveCertificateWithKey(
  dir: string,
  baseName: string,
  subject: string,
  extraExtensions: x509.Extension[] = [],
): Promise<{
  certPath: string;
  certPem: string;
  keyPath: string;
  keyPem: string;
}> {
  mkdirSync(dir, { recursive: true });

  const certPath = path.resolve(path.join(dir, `${baseName}.cert.pem`));
  const keyPath = path.resolve(path.join(dir, `${baseName}.key.pem`));

  const keyPair = await createKeys();
  const cert = await createCertificate(keyPair, subject, extraExtensions);
  const certPem = cert.toString("pem");

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.privateKey,
    SIGNING_ALGORITHM,
    true,
    ["sign"],
  );
  const keyPem = await privateKeyToPem(privateKey);

  writeFileSync(certPath, certPem);
  writeFileSync(keyPath, keyPem, { mode: 0o600 });

  return { certPath, certPem, keyPath, keyPem };
}

/**
 * Creates a self-signed X.509 certificate.
 *
 * @param keyPair The key pair to use for signing the certificate.
 * @param subject The subject name for the certificate.
 * @param extraExtensions Additional X.509 extensions appended to the default set.
 * @returns A promise that resolves to the certificate object.
 */
export async function createCertificate(
  keyPair: KeyPair,
  subject: string,
  extraExtensions: x509.Extension[] = [],
): Promise<x509.X509Certificate> {
  // Import JWK -> CryptoKey

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

  const keys = { privateKey, publicKey };

  // Create self-signed cert (X.509)
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + VALIDITY_MS);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      await x509.SubjectKeyIdentifierExtension.create(publicKey),
      ...extraExtensions,
    ],
    keys,
    name: subject,
    notAfter,
    notBefore,
    signingAlgorithm: SIGNING_ALGORITHM,
  });

  return cert;
}

/**
 * Creates an X.509 certificate signed by an issuer (CA) key pair.
 *
 * Unlike {@link createCertificate}, which produces a self-signed certificate,
 * this function uses `X509CertificateGenerator.create()` so the resulting
 * certificate is signed by a different issuer key.
 *
 * @param issuerKeyPair - The issuer's key pair used to sign the certificate.
 * @param issuerSubject - The issuer's distinguished name (e.g. "CN=TrustAnchor").
 * @param subjectKeyPair - The subject's key pair whose public key is certified.
 * @param subjectName - The subject's distinguished name.
 * @param isCA - Whether this certificate is a CA certificate (BasicConstraints).
 * @returns The signed X.509 certificate.
 */
export async function createSignedCertificate(
  issuerKeyPair: KeyPair,
  issuerSubject: string,
  subjectKeyPair: KeyPair,
  subjectName: string,
  isCA: boolean,
  extraExtensions: x509.Extension[] = [],
): Promise<x509.X509Certificate> {
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    issuerKeyPair.privateKey,
    SIGNING_ALGORITHM,
    true,
    ["sign"],
  );

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    subjectKeyPair.publicKey,
    SIGNING_ALGORITHM,
    true,
    ["verify"],
  );

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + VALIDITY_MS);

  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(isCA, isCA ? 0 : undefined, true),
    new x509.KeyUsagesExtension(
      isCA
        ? x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.digitalSignature // eslint-disable-line no-bitwise
        : x509.KeyUsageFlags.digitalSignature,
      true,
    ),
    await x509.SubjectKeyIdentifierExtension.create(publicKey),
    ...extraExtensions,
  ];

  const cert = await x509.X509CertificateGenerator.create({
    extensions,
    issuer: issuerSubject,
    notAfter,
    notBefore,
    publicKey,
    serialNumber: randomBytes(16).toString("hex"),
    signingAlgorithm: SIGNING_ALGORITHM,
    signingKey,
    subject: subjectName,
  });

  return cert;
}

/**
 * Returns `true` when the certificate (base64-DER) carries a
 * SubjectAlternativeName extension (OID 2.5.29.17).
 */
export function hasSanExtension(certDerBase64: string): boolean {
  const cert = new x509.X509Certificate(certDerBase64);
  return !!cert.getExtension("2.5.29.17");
}

export function hasX509CertificateExpired(
  x5c: string | x509.X509Certificate,
): boolean {
  const certificate =
    typeof x5c === "string" ? new x509.X509Certificate(x5c) : x5c;
  return certificate.notAfter.getTime() < Date.now() - CLOCK_SKEW_TOLERANCE_MS;
}

/**
 * Loads a certificate from a file, or creates and saves it if it doesn't exist.
 *
 * @param certPath The directory path where the certificate is stored.
 * @param filename The name of the certificate file.
 * @param keyPair The key pair to use if creating a new certificate.
 * @param subject The subject name to use if creating a new certificate.
 * @returns A promise that resolves to the base64-DER encoded certificate
 *          (DER-encoded X.509, base64-encoded, no PEM headers) — suitable
 *          for use in an x5c header array per RFC 7517 §4.7.
 */
export async function loadCertificate(
  certPath: string,
  filename: string,
  keyPair: KeyPair,
  subject: string,
): Promise<string> {
  const dirCreated = ensureDir(certPath);

  if (!dirCreated) {
    try {
      const certPem = readFileSync(`${certPath}/${filename}`, "utf-8");
      const certDerBase64 = pemToBase64Der(certPem);

      if (hasX509CertificateExpired(certDerBase64))
        throw new CertificateExpiredError(
          "Certificate has expired and has to be regenerated",
        );

      return certDerBase64;
    } catch {
      /* fall through to generate */
    }
  }

  return await createAndSaveCertificate(
    `${certPath}/${filename}`,
    keyPair,
    subject,
  );
}

/**
 * Loads an existing cert/key pair from `dir` if one is present, otherwise
 * creates a new one via {@link createAndSaveCertificateWithKey}.
 *
 * File discovery: looks for `${baseName}.cert.pem` and `${baseName}.key.pem` in `dir`.
 * Falls through to creation if the directory is absent, those files are missing,
 * or either file cannot be read.
 *
 * @param dir Directory to search or write files into.
 * @param baseName Base filename (without extension) for the cert and key files.
 * @param subject The subject / CN — used only when creation is needed.
 * @param extraExtensions Additional X.509 extensions — used only when creation is needed.
 * @returns The cert PEM, key PEM, and absolute paths of the cert and key files.
 */
export async function loadOrCreateCertificateWithKey(
  dir: string,
  baseName: string,
  subject: string,
  extraExtensions: x509.Extension[] = [],
): Promise<{
  certPath: string;
  certPem: string;
  keyPath: string;
  keyPem: string;
}> {
  const dirCreated = ensureDir(dir);

  if (!dirCreated) {
    const certPath = path.resolve(path.join(dir, `${baseName}.cert.pem`));
    const keyPath = path.resolve(path.join(dir, `${baseName}.key.pem`));
    if (existsSync(certPath) && existsSync(keyPath)) {
      const certPem = readFileSync(certPath, "utf-8");
      const keyPem = readFileSync(keyPath, "utf-8");

      const cert = new x509.X509Certificate(certPem);
      if (hasX509CertificateExpired(cert)) {
        rmSync(certPath);
        rmSync(keyPath);
      } else {
        return { certPath, certPem, keyPath, keyPem };
      }
    }
  }

  return createAndSaveCertificateWithKey(
    dir,
    baseName,
    subject,
    extraExtensions,
  );
}

/**
 * Strips PEM headers/footers and whitespace, returning the raw base64-DER
 * string suitable for an x5c array entry.
 */
export function pemToBase64Der(pem: string): string {
  // Single-certificate PEM only. Multi-cert bundles are not supported.
  return pem
    .replaceAll("-----BEGIN CERTIFICATE-----", "")
    .replaceAll("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "")
    .trim();
}

/**
 * Exports a private CryptoKey to PKCS#8 PEM format.
 *
 * @param key The private CryptoKey to export.
 * @returns The key in PKCS#8 PEM format.
 */
async function privateKeyToPem(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("pkcs8", key);
  const b64 = Buffer.from(exported).toString("base64");
  const chunks = b64.match(/.{1,64}/g);
  if (!chunks) {
    throw new Error("Unable to export empty private key");
  }
  const lines = chunks.join("\n");
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----\n`;
}
