import { Jwk } from "@pagopa/io-wallet-oauth2";
import { decodeJwt, importJWK, jwtVerify } from "jose";
import { readFileSync, rmSync } from "node:fs";
import { describe, expect, test } from "vitest";

import type { KeyPair } from "@/types";

import { loadAttestation } from "@/functions";
import { loadConfig } from "@/logic";

describe("Wallet Attestation Unit Test", () => {
  const config = loadConfig("./config.ini");
  const trustAnchorBaseUrl = `https://127.0.0.1:${config.server.port}`;

  test("Generate New Wallet Attestation with Trust Chain", async () => {
    const attestationPath = `${config.wallet.wallet_attestations_storage_path}/${config.wallet.wallet_id}`;

    // Remove existing attestation to force new generation
    rmSync(attestationPath, { force: true });

    const response = await loadAttestation({
      trustAnchorBaseUrl,
      trustAnchorJwksPath: config.trust.federation_trust_anchors_jwks_path,
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
    expect(
      (wpDecoded.metadata as { wallet_provider: unknown }).wallet_provider,
    ).toBeDefined();

    // Verify Trust Anchor Entity Statement (about Wallet Provider)
    const taDecoded = decodeJwt(taEntityStatement ?? "");
    expect(taDecoded.iss).toBe("https://127.0.0.1:3001"); // Trust Anchor
    expect(taDecoded.sub).toBe(config.wallet.wallet_provider_base_url); // About Wallet Provider
  });

  test("Load Existing Wallet Attestation", async () => {
    const response = await loadAttestation({
      trustAnchorBaseUrl,
      trustAnchorJwksPath: config.trust.federation_trust_anchors_jwks_path,
      wallet: config.wallet,
    });

    const attestation = readFileSync(
      `${config.wallet.wallet_attestations_storage_path}/${config.wallet.wallet_id}`,
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
