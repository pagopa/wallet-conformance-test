import { Jwk } from "@pagopa/io-wallet-oauth2";
import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { decodeJwt, importJWK, jwtVerify } from "jose";
import { readFileSync, rmSync } from "node:fs";
import { describe, expect, test } from "vitest";

import type { KeyPair } from "@/types";

import { loadAttestation } from "@/functions";
import { buildAttestationPath, loadConfigWithHierarchy } from "@/logic";
import { resolveTrustAnchorBaseUrl } from "@/trust-anchor/trust-anchor-resolver";

describe("Wallet Attestation Unit Test", () => {
  const config = loadConfigWithHierarchy();

  test("Generate New Wallet Attestation with Trust Chain", async () => {
    const attestationPath = buildAttestationPath(
      config.wallet,
      config.trust_anchor.external_ta_url,
    );

    // Remove existing attestation to force new generation
    rmSync(attestationPath, { force: true });

    const response = await loadAttestation({
      network: config.network,
      trust: config.trust,
      trustAnchor: config.trust_anchor,
      wallet: config.wallet,
    });

    // Verify attestation was created
    expect(response.attestation).toBeDefined();

    const providerKeyPair = readFileSync(
      `${config.wallet.backup_storage_path}/wallet_provider_jwks`,
      "utf-8",
    );
    const unitKeyPair = readFileSync(
      `${config.wallet.backup_storage_path}/wallet_unit_jwks`,
      "utf-8",
    );
    const providerJWK = (JSON.parse(providerKeyPair) as KeyPair).publicKey;
    const unitJWK: Jwk = JSON.parse(unitKeyPair).publicKey;
    const providerKey = await importJWK(providerJWK, "ES256");

    // Verify wallet attestation JWT
    const jwt = await jwtVerify(response.attestation, providerKey);

    expect(jwt.protectedHeader.typ).toBe("oauth-client-attestation+jwt");
    expect(jwt.protectedHeader.alg).toBe("ES256");
    expect(jwt.protectedHeader.kid).toBe(providerJWK.kid);

    // Verify trust chain exists and has correct structure
    const trustChain = jwt.protectedHeader.trust_chain as string[] | undefined;
    expect(trustChain).toBeDefined();
    expect(Array.isArray(trustChain)).toBe(true);
    expect(trustChain?.length).toBe(2);

    // Verify payload claims
    expect((jwt.payload.cnf as { jwk: Jwk }).jwk).toStrictEqual(unitJWK);
    expect(jwt.payload.iss).toBe(config.wallet.wallet_provider_base_url);
    expect(jwt.payload.sub).toBe(unitJWK.kid);
    expect(jwt.payload.wallet_link).toBe(
      `${config.wallet.wallet_provider_base_url}/wallet`,
    );
    expect(jwt.payload.wallet_name).toBe(config.wallet.wallet_name);

    // Verify trust chain structure
    const [wpEntityConfig, taEntityStatement] = trustChain ?? [];

    // Verify Wallet Provider Entity Configuration
    const wpDecoded = decodeJwt(wpEntityConfig ?? "");
    expect(wpDecoded.iss).toBe(config.wallet.wallet_provider_base_url);
    expect(wpDecoded.sub).toBe(config.wallet.wallet_provider_base_url);
    expect(wpDecoded.metadata).toBeDefined();
    // V1_3 uses wallet_solution; V1_0 uses wallet_provider
    const metadata = wpDecoded.metadata as Record<string, unknown>;
    expect(
      metadata["wallet_provider"] ?? metadata["wallet_solution"],
    ).toBeDefined();

    // Verify Trust Anchor Entity Statement (about Wallet Provider)
    const taDecoded = decodeJwt(taEntityStatement ?? "");
    expect(taDecoded.iss).toBe(resolveTrustAnchorBaseUrl(config.trust_anchor)); // Trust Anchor
    expect(taDecoded.sub).toBe(config.wallet.wallet_provider_base_url); // About Wallet Provider
  });

  test("Load Existing Wallet Attestation", async () => {
    const response = await loadAttestation({
      network: config.network,
      trust: config.trust,
      trustAnchor: config.trust_anchor,
      wallet: config.wallet,
    });

    const attestation = readFileSync(
      buildAttestationPath(config.wallet, config.trust_anchor.external_ta_url),
      "utf-8",
    );
    expect(response.attestation).toBe(attestation);

    const providerKeyPair = readFileSync(
      `${config.wallet.backup_storage_path}/wallet_provider_jwks`,
      "utf-8",
    );
    const unitKeyPair = readFileSync(
      `${config.wallet.backup_storage_path}/wallet_unit_jwks`,
      "utf-8",
    );
    const providerJWK = (JSON.parse(providerKeyPair) as KeyPair).publicKey;
    const unitJWK: Jwk = JSON.parse(unitKeyPair).publicKey;
    const providerKey = await importJWK(providerJWK, "ES256");
    const jwt = await jwtVerify(attestation, providerKey);

    expect(providerJWK.kid).toBe(jwt.protectedHeader.kid);
    expect(unitJWK).toStrictEqual((jwt.payload.cnf as { jwk: Jwk }).jwk);
    expect(unitJWK.kid).toBe(jwt.payload.sub);

    // Verify trust chain is present
    const trustChain = jwt.protectedHeader.trust_chain as string[] | undefined;
    expect(trustChain).toBeDefined();
    expect(Array.isArray(trustChain)).toBe(true);
    expect(trustChain?.length).toBe(2);
  });
});

describe("Wallet Attestation V1_3 Unit Test", () => {
  const config = loadConfigWithHierarchy();
  const walletV1_3 = {
    ...config.wallet,
    wallet_version: ItWalletSpecsVersion.V1_3,
  };

  test("Generate New Wallet Attestation V1_3 with x5c", async () => {
    const attestationPath = buildAttestationPath(walletV1_3);

    // Remove existing attestation to force new generation
    rmSync(attestationPath, { force: true });

    const response = await loadAttestation({
      network: config.network,
      trust: config.trust,
      trustAnchor: config.trust_anchor,
      wallet: walletV1_3,
    });

    expect(response.attestation).toBeDefined();
    expect(response.created).toBe(true);

    const providerKeyPair = readFileSync(
      `${walletV1_3.backup_storage_path}/wallet_provider_jwks`,
      "utf-8",
    );
    const unitKeyPair = readFileSync(
      `${walletV1_3.backup_storage_path}/wallet_unit_jwks`,
      "utf-8",
    );
    const providerJWK = (JSON.parse(providerKeyPair) as KeyPair).publicKey;
    const unitJWK: Jwk = JSON.parse(unitKeyPair).publicKey;
    const providerKey = await importJWK(providerJWK, "ES256");

    const jwt = await jwtVerify(response.attestation, providerKey);

    // Verify standard header fields
    expect(jwt.protectedHeader.typ).toBe("oauth-client-attestation+jwt");
    expect(jwt.protectedHeader.alg).toBe("ES256");
    expect(jwt.protectedHeader.kid).toBe(providerJWK.kid);

    // V1_3: x5c MUST be present as a non-empty array of base64-DER strings
    const x5c = jwt.protectedHeader.x5c as string[] | undefined;
    expect(x5c).toBeDefined();
    expect(Array.isArray(x5c)).toBe(true);
    expect((x5c ?? []).length).toBeGreaterThan(0);
    // Each entry must be a base64 string (no PEM headers)
    for (const entry of x5c ?? []) {
      expect(typeof entry).toBe("string");
      expect(entry).not.toContain("-----BEGIN");
    }

    // V1_3: aal / authenticatorAssuranceLevel MUST NOT be in payload
    expect((jwt.payload as Record<string, unknown>).aal).toBeUndefined();

    // Verify payload claims
    expect((jwt.payload.cnf as { jwk: Jwk }).jwk).toStrictEqual(unitJWK);
    expect(jwt.payload.iss).toBe(walletV1_3.wallet_provider_base_url);
    expect(jwt.payload.sub).toBe(unitJWK.kid);
    expect(jwt.payload.wallet_link).toBe(
      `${walletV1_3.wallet_provider_base_url}/wallet`,
    );
    expect(jwt.payload.wallet_name).toBe(walletV1_3.wallet_name);
  });

  test("Load Existing Wallet Attestation V1_3", async () => {
    const response = await loadAttestation({
      network: config.network,
      trust: config.trust,
      trustAnchor: config.trust_anchor,
      wallet: walletV1_3,
    });

    // Should load from disk (not create a new one)
    expect(response.created).toBe(false);

    const attestation = readFileSync(buildAttestationPath(walletV1_3), "utf-8");
    expect(response.attestation).toBe(attestation);

    const providerKeyPair = readFileSync(
      `${walletV1_3.backup_storage_path}/wallet_provider_jwks`,
      "utf-8",
    );
    const unitKeyPair = readFileSync(
      `${walletV1_3.backup_storage_path}/wallet_unit_jwks`,
      "utf-8",
    );
    const providerJWK = (JSON.parse(providerKeyPair) as KeyPair).publicKey;
    const unitJWK: Jwk = JSON.parse(unitKeyPair).publicKey;
    const providerKey = await importJWK(providerJWK, "ES256");
    const jwt = await jwtVerify(attestation, providerKey);

    expect(providerJWK.kid).toBe(jwt.protectedHeader.kid);
    expect(unitJWK).toStrictEqual((jwt.payload.cnf as { jwk: Jwk }).jwk);
    expect(unitJWK.kid).toBe(jwt.payload.sub);

    // Verify x5c still present and valid
    const x5c = jwt.protectedHeader.x5c as string[] | undefined;
    expect(x5c).toBeDefined();
    expect(Array.isArray(x5c)).toBe(true);
    expect((x5c ?? []).length).toBeGreaterThan(0);
  });
});
