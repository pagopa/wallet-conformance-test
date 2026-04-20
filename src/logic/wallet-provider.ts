import * as x509 from "@peculiar/x509";
import { writeFileSync } from "node:fs";

import { LOCAL_WP_HOST } from "@/servers/wp-server";
import { LOCAL_TA_HOST } from "@/trust-anchor/trust-anchor-resolver";
import { Config, KeyPair } from "@/types";

import { CertificateBuilder } from "./pem";
import { buildJwksPath, CA_VALIDITY_MS, loadJwks } from "./utils";

/**
 * Loads (or lazily generates and caches on disk) an X.509 certificate chain for the
 * wallet provider key pair, suitable for use in
 * WalletAttestationOptionsV1_3.signer.x5c.
 *
 * Follows the same lazy-cache pattern as loadCertificate /
 * loadTAJwksWithSelfSignedX5c.
 *
 * @param wallet - The wallet configuration section from Config
 * @param unitKeyPair - The unit key pair loaded from backup_storage_path
 * @param providerKeyPair - The provider key pair loaded from backup_storage_path
 * @returns A non-empty tuple of base64-DER certificate strings: [leaf, ...chain]
 */
export async function loadWalletProviderCertificateChain(
  wallet: Config["wallet"],
  unitKeyPair: KeyPair,
  providerKeyPair: KeyPair,
  trust: Config["trust"],
): Promise<[string, ...string[]]> {
  const wpHostname = new URL(LOCAL_WP_HOST).hostname;
  const wpSanExtension = buildWpSanExtension(wpHostname);

  const certWpSelfIssuedResult = await new CertificateBuilder()
    .withSubject(`CN=${wpHostname}`)
    .withKeyPair(unitKeyPair)
    .selfIssued(providerKeyPair)
    .withExtensions([wpSanExtension])
    .loadOrCreate(wallet.backup_storage_path, "wallet_unit_self_issued_cert");

  const wpCertDer = await loadWPCertificateChain(
    wallet,
    providerKeyPair,
    trust,
  );

  return [certWpSelfIssuedResult.certDerBase64, wpCertDer];
}

/**
 * Loads (or creates) the Wallet Unit JWKS and its self-issued certificate.
 * Embeds the certificate DER in publicKey.x5c and saves the updated JWKS to disk.
 */
export async function loadWalletUnitJwksWithCert(
  wallet: Config["wallet"],
  providerKeyPair: KeyPair,
): Promise<KeyPair> {
  const wpHostname = new URL(LOCAL_WP_HOST).hostname;
  const wpSanExtension = buildWpSanExtension(wpHostname);

  const unitKeyPair = await loadJwks(
    wallet.backup_storage_path,
    buildJwksPath("wallet_unit"),
  );

  const certResult = await new CertificateBuilder()
    .withSubject(`CN=${wpHostname}`)
    .withKeyPair(unitKeyPair)
    .selfIssued(providerKeyPair)
    .withExtensions([wpSanExtension])
    .loadOrCreate(wallet.backup_storage_path, "wallet_unit_self_issued_cert");

  unitKeyPair.publicKey.x5c = [certResult.certDerBase64];
  writeFileSync(
    `${wallet.backup_storage_path}/${buildJwksPath("wallet_unit")}`,
    JSON.stringify(unitKeyPair),
  );

  return unitKeyPair;
}

/**
 * Loads (or lazily generates and caches on disk) the TA CA cert and the WP cert
 * signed by the TA. Returns the WP cert DER base64.
 */
export async function loadWPCertificateChain(
  wallet: Config["wallet"],
  providerKeyPair: KeyPair,
  trust: Config["trust"],
): Promise<string> {
  const wpHostname = new URL(LOCAL_WP_HOST).hostname;
  const wpSanExtension = buildWpSanExtension(wpHostname);

  const taJwks = await loadJwks(
    trust.federation_trust_anchors_jwks_path,
    "trust_anchor",
  );
  const certTAResult = await new CertificateBuilder()
    .withSubject(`CN=${LOCAL_TA_HOST}`)
    .withKeyPair(taJwks)
    .selfIssued()
    .withCaCapability(0)
    .withValidity(CA_VALIDITY_MS)
    .loadOrCreate(trust.ca_cert_path, "trust_anchor_cert");

  const certWpResult = await new CertificateBuilder()
    .withSubject(`CN=${wpHostname}`)
    .withKeyPair(providerKeyPair)
    .signedBy(certTAResult.certificate, taJwks)
    .withExtensions([wpSanExtension])
    .loadOrCreate(wallet.backup_storage_path, "wallet_provider_cert");

  return certWpResult.certDerBase64;
}

function buildWpSanExtension(
  wpHostname: string,
): x509.SubjectAlternativeNameExtension {
  return new x509.SubjectAlternativeNameExtension(
    [
      { type: "url", value: LOCAL_WP_HOST },
      { type: "dns", value: wpHostname },
    ],
    false,
  );
}
