import { importJWK, jwtVerify } from "jose";
import { readFileSync, rmSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { Jwk } from "@pagopa/io-wallet-oauth2";

import type { KeyPair } from "@/types";

import { loadAttestation } from "@/functions";

describe("Wallet Attestation Unit Test", () => {
  const walletId = "wallet_cli_instance";
  const walletName = "CEN TC Wallet CLI";
  const issuer = "https://wallet-provider.example.it";
  const storage = "data/wallet_attestations";
  const credentials = "data/credentials";
  const backup = "data/backup";
  const attestationPath = `${storage}/${walletId}`;

  test("New Wallet Attestation", async () => {
    rmSync(attestationPath, { force: true });

    const response = await loadAttestation({
      backup_storage_path: backup,
      credentials_storage_path: credentials,
      wallet_attestations_storage_path: storage,
      wallet_id: walletId,
      wallet_name: walletName,
      wallet_provider_base_url: issuer,
    });

    expect(readFileSync(attestationPath, "utf-8")).toBe(response.attestation);

    const providerKeyPair = readFileSync(
      `${backup}/wallet_provider_jwks`,
      "utf-8",
    );
    const unitKeyPair = readFileSync(`${backup}/wallet_unit_jwks`, "utf-8");
    const providerJWK = (JSON.parse(providerKeyPair) as KeyPair).publicKey;
    const unitJWK: Jwk = JSON.parse(unitKeyPair).publicKey;
    const providerKey = await importJWK(providerJWK, "ES256");
    const jwt = await jwtVerify(response.attestation, providerKey);

    expect(jwt.protectedHeader.typ).toBe("oauth-client-attestation+jwt");
    expect(jwt.protectedHeader.alg).toBe("ES256");
    expect(jwt.protectedHeader.kid).toBe(providerJWK.kid);

    expect((jwt.payload.cnf as { jwk: Jwk }).jwk).toStrictEqual(unitJWK);
    expect(jwt.payload.iss).toBe(issuer);
    expect(jwt.payload.sub).toBe(unitJWK.kid);
    expect(jwt.payload.wallet_link).toBe(`${issuer}/wallet`);
    expect(jwt.payload.wallet_name).toBe(walletName);
  });

  test("Load Wallet Attestation", async () => {
    const attestation = readFileSync(`tests/${attestationPath}`, "utf-8");

    const response = await loadAttestation({
      backup_storage_path: `tests/${backup}`,
      credentials_storage_path: `tests/${credentials}`,
      wallet_attestations_storage_path: `tests/${storage}`,
      wallet_id: walletId,
      wallet_name: walletName,
      wallet_provider_base_url: issuer,
    });
    expect(response.attestation).toBe(attestation);

    const providerKeyPair = readFileSync(
      `tests/${backup}/wallet_provider_jwks`,
      "utf-8",
    );
    const unitKeyPair = readFileSync(
      `tests/${backup}/wallet_unit_jwks`,
      "utf-8",
    );
    const providerJWK = (JSON.parse(providerKeyPair) as KeyPair).publicKey;
    const unitJWK: Jwk = JSON.parse(unitKeyPair).publicKey;
    const providerKey = await importJWK(providerJWK, "ES256");
    const jwt = await jwtVerify(attestation, providerKey);

    expect(providerJWK.kid).toBe(jwt.protectedHeader.kid);
    expect(unitJWK).toStrictEqual((jwt.payload.cnf as { jwk: Jwk }).jwk);
    expect(unitJWK.kid).toBe(jwt.payload.sub);
  });
});
