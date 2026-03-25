import * as x509 from "@peculiar/x509";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

import { KeyPair } from "@/types";

import { createKeys } from "./jwk";

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
    { name: "ECDSA", namedCurve: "P-256" },
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
  const signingAlgorithm = {
    hash: "SHA-256",
    name: "ECDSA",
    namedCurve: "P-256",
  };

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.privateKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    keyPair.publicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );

  const keys = { privateKey, publicKey };

  // Create self-signed cert (X.509)
  const now = new Date();
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
    notBefore: now,
    signingAlgorithm,
  });

  return cert;
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
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----\n`;
}
