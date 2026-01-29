import * as x509 from "@peculiar/x509";
import { writeFileSync } from "node:fs";

import { KeyPair } from "@/types";

export async function createAndSaveCertificate(
  fileName: string,
  keyPair: KeyPair,
  subject: string,
): Promise<string> {
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

  // const attrs = [
  // 	{ name: "commonName", value: "trust_anchor" },
  // 	{ name: "organizationName", value: "it_wallet" },
  // 	{ name: "organizationalUnitName", value: "wallet_lab" },
  // 	{ name: "countryName", value: "IT" },
  // 	{ name: "stateOrProvince", value: "Roma" },
  // 	{ name: "localityName", value: "Roma" },
  // 	{ name: "emailAddress", value: "example@email.it" },
  // 	{ name: "organizationIdentifier", value: "2.5.4.97" },
  // ];
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

  // Export certificate to PEM
  const certPem = cert.toString("pem");

  writeFileSync(fileName, JSON.stringify(certPem));
  return certPem;
}
