import * as asn1js from "asn1js";
import { readFileSync } from "node:fs";
import {
  BasicConstraints,
  Certificate,
  CertificateChainValidationEngine,
  CryptoEngine,
  setEngine,
} from "pkijs";

import type { PidMrtdFixturePaths } from "@/logic/pid-mrtd/fixture-paths";

const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_KEY_USAGE = "2.5.29.15";
/** KeyUsage `keyCertSign` bit (RFC 5280), aligned with PKIjs chain builder checks. */
const KEY_USAGE_KEY_CERT_SIGN = 0x04;

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
 * Validates mock ICAO CSCA → DSC fixtures (REQ-02 / FR-21):
 *
 * 1. CSCA as trusted self-signed anchor (signature, validity, CA + keyCertSign)
 * 2. DSC as non-CA end-entity issued by that CSCA
 * 3. Full path validation via {@link CertificateChainValidationEngine}
 */
export async function verifyCscaDscChain(
  paths: Pick<PidMrtdFixturePaths, "cscaCertPath" | "dscCertPath">,
): Promise<boolean> {
  initPkijsCryptoEngine();

  const checkDate = new Date();
  const csca = readCertificateFromPem(paths.cscaCertPath);
  const dsc = readCertificateFromPem(paths.dscCertPath);

  if (!(await assertCscaTrustAnchor(csca, checkDate))) {
    return false;
  }

  if (!(await assertDscEndEntity(dsc, csca, checkDate))) {
    return false;
  }

  const chainEngine = new CertificateChainValidationEngine({
    certs: [dsc],
    checkDate,
    trustedCerts: [csca],
  });
  const chainResult = await chainEngine.verify();

  return chainResult.result;
}

async function assertCscaTrustAnchor(
  csca: Certificate,
  checkDate: Date,
): Promise<boolean> {
  if (!csca.issuer.isEqual(csca.subject)) {
    return false;
  }

  if (!(await csca.verify(csca))) {
    return false;
  }

  if (!isCertificateValidAt(csca, checkDate)) {
    return false;
  }

  if (readBasicConstraintsCa(csca) !== true) {
    return false;
  }

  const hasKeyUsage = (csca.extensions ?? []).some(
    (extension) => extension.extnID === OID_KEY_USAGE,
  );
  if (hasKeyUsage && !keyUsageIncludesFlag(csca, KEY_USAGE_KEY_CERT_SIGN)) {
    return false;
  }

  return true;
}

async function assertDscEndEntity(
  dsc: Certificate,
  csca: Certificate,
  checkDate: Date,
): Promise<boolean> {
  if (!isCertificateValidAt(dsc, checkDate)) {
    return false;
  }

  if (!dsc.issuer.isEqual(csca.subject)) {
    return false;
  }

  if (readBasicConstraintsCa(dsc) === true) {
    return false;
  }

  if (keyUsageIncludesFlag(dsc, KEY_USAGE_KEY_CERT_SIGN)) {
    return false;
  }

  if (!(await dsc.verify(csca))) {
    return false;
  }

  return true;
}

function isCertificateValidAt(cert: Certificate, at: Date): boolean {
  const notBefore = cert.notBefore.value;
  const notAfter = cert.notAfter.value;
  const atMs = at.getTime();

  return notBefore.getTime() <= atMs && atMs <= notAfter.getTime();
}

function keyUsageIncludesFlag(cert: Certificate, flag: number): boolean {
  for (const extension of cert.extensions ?? []) {
    if (
      extension.extnID !== OID_KEY_USAGE ||
      !(extension.parsedValue instanceof asn1js.BitString)
    ) {
      continue;
    }

    const bits = new Uint8Array(extension.parsedValue.valueBlock.valueHexView);
    const firstByte = bits[0];
    if (firstByte === undefined) {
      return false;
    }

    // eslint-disable-next-line no-bitwise -- RFC 5280 KeyUsage is a bit string; matches PKIjs chain checks
    return (firstByte & flag) === flag;
  }

  return false;
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

function readBasicConstraintsCa(cert: Certificate): boolean | undefined {
  for (const extension of cert.extensions ?? []) {
    if (
      extension.extnID === OID_BASIC_CONSTRAINTS &&
      extension.parsedValue instanceof BasicConstraints
    ) {
      return extension.parsedValue.cA === true;
    }
  }

  return undefined;
}

function readCertificateFromPem(pemPath: string): Certificate {
  const pem = readFileSync(pemPath, "utf-8");
  const asn1 = pemToArrayBuffer(pem);
  return Certificate.fromBER(asn1);
}
