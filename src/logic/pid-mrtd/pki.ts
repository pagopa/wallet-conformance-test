import * as x509 from "@peculiar/x509";
import { fromBER } from "asn1js";
import { importPKCS8 } from "jose";
import { readFileSync } from "node:fs";
import { Certificate } from "pkijs";

import type { PidMrtdFixturePaths } from "@/logic/pid-mrtd/fixture-paths";
import type { Config } from "@/types";

import { PidMrtdPkiLoadError } from "@/errors";
import { createKeys } from "@/logic/jwk";
import { createCertificate } from "@/logic/pem";
import { ensurePidMrtdFixtures } from "@/logic/pid-mrtd/generate-fixtures";
import { verifyCscaDscChain } from "@/logic/pid-mrtd/verify-csca-dsc-chain";

const SIGNING_ALGORITHM = {
  hash: "SHA-256",
  name: "ECDSA",
  namedCurve: "P-256",
} as const satisfies EcdsaParams & EcKeyImportParams;

/** Mock IAS (chip) certificate subject for ephemeral keys. */
export const MOCK_IAS_SUBJECT = "CN=WCT Mock IAS,O=PagoPA,C=IT";

export interface EphemeralIasPki {
  certificate: x509.X509Certificate;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export interface LoadedPidMrtdPki {
  csca: x509.X509Certificate;
  dsc: x509.X509Certificate;
  dscPkijsCertificate: Certificate;
  dscPrivateKey: CryptoKey;
  paths: PidMrtdFixturePaths;
}

/** Generates an in-memory IAS key pair and self-signed certificate (per run, FR-15). */
export async function createEphemeralIasPki(): Promise<EphemeralIasPki> {
  const keyPair = await createKeys();
  const certificate = await createCertificate(keyPair, MOCK_IAS_SUBJECT);

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

  return { certificate, privateKey, publicKey };
}

/**
 * Ensures CSCA/DSC fixtures exist, verifies the chain, and loads signing material.
 */
export async function loadPersistedPidMrtdPki(
  config?: Partial<Pick<Config, "issuance_pid" | "wallet">>,
): Promise<LoadedPidMrtdPki> {
  const paths = await ensurePidMrtdFixtures(undefined, config);

  const chainValid = await verifyCscaDscChain(paths);
  if (!chainValid) {
    throw new PidMrtdPkiLoadError(
      "CSCA → DSC fixture chain verification failed",
      paths.dir,
    );
  }

  const cscaPem = readFileSync(paths.cscaCertPath, "utf-8");
  const dscPem = readFileSync(paths.dscCertPath, "utf-8");
  const dscKeyPem = readFileSync(paths.dscKeyPath, "utf-8");

  const csca = new x509.X509Certificate(cscaPem);
  const dsc = new x509.X509Certificate(dscPem);
  const dscPrivateKey = await importPKCS8(dscKeyPem, "ES256");
  const dscPkijsCertificate = readPkijsCertificate(dsc);

  return {
    csca,
    dsc,
    dscPkijsCertificate,
    dscPrivateKey,
    paths,
  };
}

function readPkijsCertificate(cert: x509.X509Certificate): Certificate {
  const der = new Uint8Array(cert.rawData);
  const asn1 = fromBER(der);
  if (asn1.offset === -1) {
    throw new Error(
      "Failed to parse X.509 certificate DER (fromBER offset = -1)",
    );
  }
  return new Certificate({ schema: asn1.result });
}
