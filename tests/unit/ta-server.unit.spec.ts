import { decodeJwt } from "jose";
import * as http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { createServer } from "@/servers/ta-server";

describe("Trust Anchor Wallet Provider fetch endpoint", () => {
  const walletProviderBaseUrl =
    "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider";
  const config = {
    ...loadConfigWithHierarchy(),
    wallet: {
      ...loadConfigWithHierarchy().wallet,
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

    const response = await fetch(
      `http://127.0.0.1:${address.port}/fetch?sub=${encodeURIComponent(walletProviderBaseUrl)}`,
    );

    expect(response.status).toBe(200);
    expect(decodeJwt(await response.text()).sub).toBe(walletProviderBaseUrl);
  });
});
