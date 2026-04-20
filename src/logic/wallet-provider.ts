import * as x509 from "@peculiar/x509";

import { LOCAL_WP_HOST } from "@/servers/wp-server";
import { LOCAL_TA_HOST } from "@/trust-anchor/trust-anchor-resolver";
import { Config, KeyPair } from "@/types";

import { CertificateBuilder } from "./pem";
import { loadJwks } from "./utils";

/**
 * Loads (or lazily generates and caches on disk) an X.509 certificate for the
 * wallet provider key pair, suitable for use in
 * WalletAttestationOptionsV1_3.signer.x5c.
 *
 * Follows the same lazy-cache pattern as loadCertificate /
 * loadTAJwksWithSelfSignedX5c.
 *
 * @param wallet - The wallet configuration section from Config
 * @param providerKeyPair - The provider key pair loaded from backup_storage_path
 * @returns A non-empty tuple of base64-DER certificate strings: [leaf, ...chain]
 */
export async function loadWalletProviderCertificateChain(
  wallet: Config["wallet"],
  providerKeyPair: KeyPair,
  trust: Config["trust"],
): Promise<[string, ...string[]]> {
  const wpHostname = new URL(LOCAL_WP_HOST).hostname;
  const wpSanExtension = new x509.SubjectAlternativeNameExtension(
    [
      { type: "url", value: LOCAL_WP_HOST },
      { type: "dns", value: wpHostname },
    ],
    false,
  );

  const certWpSelfSignedResult = await new CertificateBuilder()
    .withSubject(`CN=${wpHostname}`)
    .withKeyPair(providerKeyPair)
    .selfSigned()
    .withExtensions([wpSanExtension])
    .loadOrCreate(
      wallet.backup_storage_path,
      "wallet_provider_self_signed_cert",
    );

  const taJwks = await loadJwks(
    trust.federation_trust_anchors_jwks_path,
    "trust_anchor",
  );
  const certTAResult = await new CertificateBuilder()
    .withSubject(`CN=${LOCAL_TA_HOST}`)
    .withKeyPair(taJwks)
    .selfSigned()
    .withCaCapability(0)
    .loadOrCreate(trust.ca_cert_path, "trust_anchor_cert");

  const certWpResult = await new CertificateBuilder()
    .withSubject(`CN=${wpHostname}`)
    .withKeyPair(providerKeyPair)
    .signedBy(certTAResult.certificate, taJwks)
    .withExtensions([wpSanExtension])
    .loadOrCreate(
      wallet.backup_storage_path,
      "wallet_provider_cert",
    );
  return [
    certWpSelfSignedResult.certDerBase64,
    certWpResult.certDerBase64,
    certTAResult.certDerBase64,
  ];
}
