import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";

import { buildWpEntityConfiguration } from "@/functions";
import { createKeys, loadConfigWithHierarchy } from "@/logic";
import {
  appendWalletProviderPath,
  resolveNormalizedWalletProviderBaseUrl,
  resolveWalletProviderEntityIdentifier,
} from "@/logic/wallet-provider-url";
import { resolveTrustAnchorBaseUrl } from "@/trust-anchor/trust-anchor-resolver";

interface WalletProviderMetadataClaims {
  wallet_solution?: {
    wallet_metadata?: {
      authorization_endpoint?: unknown;
      credential_offer_endpoint?: unknown;
    };
  };
}

describe("Wallet Provider URL resolution", () => {
  it.each([
    {
      configuredIdentifier:
        "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider/",
      expectedNormalizedBaseUrl:
        "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider",
    },
    {
      configuredIdentifier:
        "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider",
      expectedNormalizedBaseUrl:
        "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider",
    },
  ])(
    "separates identity and endpoint base URL for $configuredIdentifier",
    ({ configuredIdentifier, expectedNormalizedBaseUrl }) => {
      const wallet = {
        port: 3002,
        wallet_provider_base_url: configuredIdentifier,
      };

      expect(resolveWalletProviderEntityIdentifier(wallet)).toBe(
        configuredIdentifier,
      );
      expect(resolveNormalizedWalletProviderBaseUrl(wallet)).toBe(
        expectedNormalizedBaseUrl,
      );
      expect(
        appendWalletProviderPath(configuredIdentifier, "/status-list"),
      ).toBe(`${expectedNormalizedBaseUrl}/status-list`);
    },
  );

  it("preserves federation identity while normalizing metadata endpoints", async () => {
    const config = loadConfigWithHierarchy();
    const configuredIdentifier =
      "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider/";
    const normalizedBaseUrl =
      "https://dev.eid.wallet.ipzs.it/1-3/test-wallet-provider";
    const wallet = {
      ...config.wallet,
      wallet_provider_base_url: configuredIdentifier,
      wallet_version: ItWalletSpecsVersion.V1_3,
    };

    const statement = await buildWpEntityConfiguration(
      config.trust,
      wallet,
      await createKeys(),
      resolveTrustAnchorBaseUrl(config.trust_anchor),
    );
    const decoded = decodeJwt(statement);

    expect(decoded.iss).toBe(configuredIdentifier);
    expect(decoded.sub).toBe(configuredIdentifier);

    const metadata = decoded.metadata as WalletProviderMetadataClaims;
    expect(
      metadata.wallet_solution?.wallet_metadata?.authorization_endpoint,
    ).toBe(`${normalizedBaseUrl}/authorize`);
    expect(
      metadata.wallet_solution?.wallet_metadata?.credential_offer_endpoint,
    ).toBe(`${normalizedBaseUrl}/credential_offer`);
  });
});
