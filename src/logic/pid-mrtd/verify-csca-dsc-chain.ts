import { readFileSync } from "node:fs";
import { Certificate, CryptoEngine, setEngine } from "pkijs";

import type { PidMrtdFixturePaths } from "@/logic/pid-mrtd/fixture-paths";

let pkijsEngineInitialized = false;

/**
 * Configures PKIjs to use the Node.js Web Crypto implementation.
 * Safe to call multiple times; only the first call has effect.
 */
export function initPkijsCryptoEngine(): void {
  if (pkijsEngineInitialized) {
    return;
  }

  const webcrypto = globalThis.crypto;
  setEngine(
    "node",
    webcrypto,
    new CryptoEngine({
      crypto: webcrypto,
      name: "node",
      subtle: webcrypto.subtle,
    }),
  );
  pkijsEngineInitialized = true;
}

/**
 * Verifies that the DSC certificate was issued by the CSCA using PKIjs
 * (structural X.509 path validation for REQ-02 / FR-21).
 */
export async function verifyCscaDscChain(
  paths: Pick<PidMrtdFixturePaths, "cscaCertPath" | "dscCertPath">,
): Promise<boolean> {
  initPkijsCryptoEngine();

  const csca = readCertificateFromPem(paths.cscaCertPath);
  const dsc = readCertificateFromPem(paths.dscCertPath);

  return dsc.verify(csca);
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const buffer = Buffer.from(base64, "base64");
  return buffer.buffer.slice(
    buffer.byteOffset,
    buffer.byteOffset + buffer.byteLength,
  );
}

function readCertificateFromPem(pemPath: string): Certificate {
  const pem = readFileSync(pemPath, "utf-8");
  const asn1 = pemToArrayBuffer(pem);
  return Certificate.fromBER(asn1);
}
