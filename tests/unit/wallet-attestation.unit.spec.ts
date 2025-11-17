import { Jwk } from "@pagopa/io-wallet-oauth2";
import { importJWK, jwtVerify } from "jose";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import type { KeyPair } from "@/types";

import { loadAttestation } from "@/functions";
import { loadConfig } from "@/logic/utils";

describe("Wallet Attestation Unit Test", () => {
  const config = loadConfig("./config.ini");

  test("Load Wallet Attestation", async () => {
    const response = await loadAttestation({
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
  });
});
