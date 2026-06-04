import * as x509 from "@peculiar/x509";
import { readFileSync } from "node:fs";

import type { PidMrtdFixturePaths } from "@/logic/pid-mrtd/fixture-paths";

import { hasX509CertificateExpired } from "@/logic/pem";

/**
 * Validates mock ICAO CSCA → DSC fixtures (REQ-02 / FR-21) using
 * `@peculiar/x509` (already used for fixture generation and TA/CI certs).
 *
 * Checks: CSCA self-signed trust anchor, CA/key-usage constraints, DSC end-entity,
 * signature chain CSCA → DSC.
 *
 * PKIjs is deferred to REQ-03 ({@link cms.ts} / SignedData), where CMS is required.
 */
export async function verifyCscaDscChain(
  paths: Pick<PidMrtdFixturePaths, "cscaCertPath" | "dscCertPath">,
): Promise<boolean> {
  const checkDate = new Date();
  const csca = readCertificateFromPem(paths.cscaCertPath);
  const dsc = readCertificateFromPem(paths.dscCertPath);

  if (!(await assertCscaTrustAnchor(csca, checkDate))) {
    return false;
  }

  return assertDscEndEntity(dsc, csca, checkDate);
}

async function assertCscaTrustAnchor(
  csca: x509.X509Certificate,
  checkDate: Date,
): Promise<boolean> {
  if (normalizeDn(csca.issuer) !== normalizeDn(csca.subject)) {
    return false;
  }

  if (!isCertificateValidAt(csca, checkDate)) {
    return false;
  }

  const basicConstraints = csca.getExtension(x509.BasicConstraintsExtension);
  if (basicConstraints?.ca !== true) {
    return false;
  }

  const keyUsage = csca.getExtension(x509.KeyUsagesExtension);
  if (
    keyUsage != null &&
    // eslint-disable-next-line no-bitwise -- KeyUsageFlags is a bit field
    (keyUsage.usages & x509.KeyUsageFlags.keyCertSign) !==
      x509.KeyUsageFlags.keyCertSign
  ) {
    return false;
  }

  const cscaPublicKey = await csca.publicKey.export();
  return csca.verify({ publicKey: cscaPublicKey });
}

async function assertDscEndEntity(
  dsc: x509.X509Certificate,
  csca: x509.X509Certificate,
  checkDate: Date,
): Promise<boolean> {
  if (!isCertificateValidAt(dsc, checkDate)) {
    return false;
  }

  if (normalizeDn(dsc.issuer) !== normalizeDn(csca.subject)) {
    return false;
  }

  const basicConstraints = dsc.getExtension(x509.BasicConstraintsExtension);
  if (basicConstraints?.ca === true) {
    return false;
  }

  const keyUsage = dsc.getExtension(x509.KeyUsagesExtension);
  if (
    keyUsage != null &&
    // eslint-disable-next-line no-bitwise -- KeyUsageFlags is a bit field
    (keyUsage.usages & x509.KeyUsageFlags.keyCertSign) ===
      x509.KeyUsageFlags.keyCertSign
  ) {
    return false;
  }

  const cscaPublicKey = await csca.publicKey.export();
  return dsc.verify({ publicKey: cscaPublicKey });
}

function isCertificateValidAt(cert: x509.X509Certificate, at: Date): boolean {
  if (hasX509CertificateExpired(cert)) {
    return false;
  }

  const atMs = at.getTime();
  return cert.notBefore.getTime() <= atMs && atMs <= cert.notAfter.getTime();
}

/** @peculiar/x509 may insert spaces after RDN commas; compare canonically. */
function normalizeDn(dn: string): string {
  return dn.replace(/\s+/g, "").toUpperCase();
}

function readCertificateFromPem(pemPath: string): x509.X509Certificate {
  const pem = readFileSync(pemPath, "utf-8");
  return new x509.X509Certificate(pem);
}
