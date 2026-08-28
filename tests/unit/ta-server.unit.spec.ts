import { decodeJwt } from "jose";
import * as http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { createSubordinateWalletUnitMetadata } from "@/logic/federation-metadata";
import { buildJwksPath, loadJwks } from "@/logic/utils";
import { createServer } from "@/servers/ta-server";

describe("Trust Anchor Wallet Provider fetch endpoint", () => {
  const walletProviderBaseUrl =
    "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider";
  const baseConfig = loadConfigWithHierarchy();
  const config = {
    ...baseConfig,
    wallet: {
      ...baseConfig.wallet,
      wallet_provider_base_url: walletProviderBaseUrl,
    },
  };
  const server = http.createServer(createServer(config));

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("recognizes the configured Wallet Provider subject and returns a matching statement", async () => {
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Trust Anchor test server is not listening");
    }

    const [providerJwks, unitJwks] = await Promise.all([
      loadJwks(
        config.wallet.backup_storage_path,
        buildJwksPath("wallet_provider"),
      ),
      loadJwks(config.wallet.backup_storage_path, buildJwksPath("wallet_unit")),
    ]);
    const response = await fetch(
      `http://127.0.0.1:${address.port}/fetch?sub=${encodeURIComponent(walletProviderBaseUrl)}`,
    );

    expect(response.status).toBe(200);
    const decodedStatement = decodeJwt(await response.text());
    expect(decodedStatement.sub).toBe(walletProviderBaseUrl);
    expect(decodedStatement.jwks).toEqual(
      expect.objectContaining({
        keys: expect.arrayContaining([providerJwks.publicKey]),
      }),
    );
    expect(decodedStatement.jwks).not.toEqual(
      expect.objectContaining({
        keys: expect.arrayContaining([unitJwks.publicKey]),
      }),
    );
  });

  it("keeps subordinate Wallet Unit metadata on Wallet Unit keys", async () => {
    const [unitJwks, providerJwks] = await Promise.all([
      loadJwks(config.wallet.backup_storage_path, buildJwksPath("wallet_unit")),
      loadJwks(
        config.wallet.backup_storage_path,
        buildJwksPath("wallet_provider"),
      ),
    ]);

    const statement = await createSubordinateWalletUnitMetadata({
      sub: "https://wallet-unit.example",
      trustAnchor: config.trust,
      trustAnchorBaseUrl: "https://trust-anchor.example",
      walletBackupStoragePath: config.wallet.backup_storage_path,
    });

    const decodedStatement = decodeJwt(statement);
    expect(decodedStatement.jwks).toEqual(
      expect.objectContaining({
        keys: expect.arrayContaining([unitJwks.publicKey]),
      }),
    );
    expect(decodedStatement.jwks).not.toEqual(
      expect.objectContaining({
        keys: expect.arrayContaining([providerJwks.publicKey]),
      }),
    );
  });
});
