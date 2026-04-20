import * as x509 from "@peculiar/x509";
import { writeFileSync } from "node:fs";

import { LOCAL_WP_HOST } from "@/servers/wp-server";
import { LOCAL_TA_HOST } from "@/trust-anchor/trust-anchor-resolver";
import { Config, KeyPair } from "@/types";

import { CertificateBuilder, CertificateResult } from "./pem";
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
  providerKeyPair: KeyPair,
  trust: Config["trust"],
): Promise<[string, ...string[]]> {
  const wpSanExtension = buildWpSanExtension(LOCAL_WP_HOST);

  const wpCertResult = await loadWPCertificateChain(wallet, trust);

  const certWpSelfIssuedResult = await new CertificateBuilder()
    .withSubject(`CN=${LOCAL_WP_HOST}`)
    .withKeyPair(providerKeyPair)
    .selfIssued(wpCertResult.keyPair)
    .withExtensions([wpSanExtension])
    .loadOrCreate(wallet.backup_storage_path, "wallet_unit_self_issued_cert");

  return [certWpSelfIssuedResult.certDerBase64, wpCertResult.certDerBase64];
}

/**
 * Loads (or creates) the Wallet Unit JWKS and its self-issued certificate.
 * Embeds the certificate DER in publicKey.x5c and saves the updated JWKS to disk.
 */
export async function loadWalletUnitJwksWithCert(
  wallet: Config["wallet"],
  providerKeyPair: KeyPair,
): Promise<KeyPair> {
  const wpSanExtension = buildWpSanExtension(LOCAL_WP_HOST);

  const unitKeyPair = await loadJwks(
    wallet.backup_storage_path,
    buildJwksPath("wallet_unit"),
  );

  const certResult = await new CertificateBuilder()
    .withSubject(`CN=${LOCAL_WP_HOST}`)
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
 * Loads the Wallet Provider cert signed by the TA which contains keys to sign self-issued certs that contains wallet provider keys.
 */
export async function loadWPCertificateChain(
  wallet: Config["wallet"],
  trust: Config["trust"],
): Promise<CertificateResult> {
  const wpSanExtension = buildWpSanExtension(LOCAL_WP_HOST);

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

  const wpCertJwks = await loadJwks(
    wallet.backup_storage_path,
    buildJwksPath("wallet_provider_cert"),
  );

  const certWpResult = await new CertificateBuilder()
    .withSubject(`CN=${LOCAL_WP_HOST}`)
    .withKeyPair(wpCertJwks)
    .signedBy(certTAResult.certificate, taJwks)
    .withExtensions([wpSanExtension])
    .loadOrCreate(wallet.backup_storage_path, "wallet_provider_cert");

  return certWpResult;
}

function buildWpSanExtension(
  wpHostname: string,
): x509.SubjectAlternativeNameExtension {
  return new x509.SubjectAlternativeNameExtension(
    [
      { type: "url", value: `https://${wpHostname}` },
      { type: "dns", value: wpHostname },
    ],
    false,
  );
}
