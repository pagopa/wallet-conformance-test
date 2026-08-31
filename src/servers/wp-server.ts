import express from "express";
import * as https from "node:https";

import { buildWpEntityConfiguration } from "@/functions/load-attestation";
import { isMainModule } from "@/logic/entrypoint";
import { createStatusListToken } from "@/logic/status-list";
import {
  buildJwksPath,
  loadConfigWithHierarchy,
  loadJwks,
  loadOrCreateServerCertificate,
} from "@/logic/utils";
import { loadWalletProviderCertificate } from "@/logic/wallet-provider";
import {
  appendWalletProviderPath,
  getWalletProviderBasePath,
  getWalletProviderCertificateSubject,
  resolveNormalizedWalletProviderBaseUrl,
  resolveWalletProviderEntityIdentifier,
} from "@/logic/wallet-provider-url";
import { resolveTrustAnchorBaseUrl } from "@/trust-anchor/trust-anchor-resolver";
import { Config } from "@/types";

export { getLocalWpBaseUrl, LOCAL_WP_HOST } from "@/logic/wallet-provider-url";

export const createServer = (config: Config): express.Express => {
  const app = express();
  app.use(express.json());

  const wpBaseUrl = resolveNormalizedWalletProviderBaseUrl(config.wallet);
  const walletProviderEntityIdentifier = resolveWalletProviderEntityIdentifier(
    config.wallet,
  );
  const walletProviderRouter = express.Router();

  walletProviderRouter.get(
    "/.well-known/openid-federation",
    async (_req, res) => {
      try {
        const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(
          config.trust_anchor,
        );
        const providerKeyPair = await loadJwks(
          config.wallet.backup_storage_path,
          buildJwksPath("wallet_provider"),
        );
        const jwt = await buildWpEntityConfiguration(
          config.trust,
          config.wallet,
          providerKeyPair,
          trustAnchorBaseUrl,
        );
        res.type("application/entity-statement+jwt").send(jwt);
      } catch (err) {
        console.error(
          "Failed to build wallet provider entity configuration",
          err,
        );
        res.status(500).json({ error: "internal_server_error" });
      }
    },
  );

  walletProviderRouter.get("/status-list", async (_req, res) => {
    try {
      const providerKeyPair = await loadJwks(
        config.wallet.backup_storage_path,
        buildJwksPath("wallet_provider"),
      );
      await loadWalletProviderCertificate(
        config.wallet,
        config.trust,
        providerKeyPair,
      );
      const jwt = await createStatusListToken({
        certFilename: "wallet_provider_cert",
        certSubject: getWalletProviderCertificateSubject(
          walletProviderEntityIdentifier,
        ),
        iss: walletProviderEntityIdentifier,
        jwksFilename: "wallet_provider_jwks",
        jwksPath: config.wallet.backup_storage_path,
        keyPair: providerKeyPair,
        statusListEndpointUrl: appendWalletProviderPath(
          wpBaseUrl,
          "status-list",
        ),
      });
      res.type("application/statuslist+jwt").send(jwt);
    } catch (err) {
      console.error("Failed to create wallet status list token", err);
      res.status(500).json({ error: "internal_server_error" });
    }
  });

  app.use(getWalletProviderBasePath(wpBaseUrl), walletProviderRouter);

  return app;
};

if (isMainModule(import.meta.url)) {
  const config = loadConfigWithHierarchy();
  const app = createServer(config);
  loadOrCreateServerCertificate(config)
    .then(({ certPem, keyPem }) =>
      https.createServer({ cert: certPem, key: keyPem }, app),
    )
    .then((server) =>
      server.listen(config.wallet.port, config.network.bind_address, () => {
        const wpBaseUrl = resolveNormalizedWalletProviderBaseUrl(config.wallet);
        const walletProviderEntityIdentifier =
          resolveWalletProviderEntityIdentifier(config.wallet);
        console.log(
          `[Wallet Provider] ${walletProviderEntityIdentifier} Server started
      PID: ${process.pid}
      URL: https://localhost:${config.wallet.port}

      Endpoints:   
      GET  ${appendWalletProviderPath(wpBaseUrl, ".well-known/openid-federation")}
      GET  ${appendWalletProviderPath(wpBaseUrl, "status-list")}

      Started: ${new Date().toISOString()}`,
        );
      }),
    );
}
