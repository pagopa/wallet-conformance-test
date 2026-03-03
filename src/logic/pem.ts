import * as x509 from "@peculiar/x509";
import { writeFileSync } from "node:fs";

import { KeyPair } from "@/types";

/**
 * Creates a self-signed X.509 certificate and saves it to a file in PEM format.
 *
 * @param fileName The name of the file to save the certificate to.
 * @param keyPair The key pair to use for signing the certificate.
 * @param subject The subject name for the certificate.
 * @returns A promise that resolves to the certificate in PEM format.
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
 * Creates a self-signed X.509 certificate.
 *
 * @param keyPair The key pair to use for signing the certificate.
 * @param subject The subject name for the certificate.
 * @returns A promise that resolves to the certificate object.
 */
export async function createCertificate(
  keyPair: KeyPair,
  subject: string,
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
    ],
    keys,
    name: subject,
    notBefore: now,
    signingAlgorithm,
  });

  return cert;
}
