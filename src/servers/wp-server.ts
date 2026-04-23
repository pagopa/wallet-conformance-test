import express from "express";
import * as https from "node:https";

import { buildWpEntityConfiguration } from "@/functions/load-attestation";
import {
  buildJwksPath,
  loadConfigWithHierarchy,
  loadJwks,
  loadOrCreateServerCertificate,
} from "@/logic";
import { createStatusListToken } from "@/logic/status-list";
import { resolveTrustAnchorBaseUrl } from "@/trust-anchor/trust-anchor-resolver";
import { Config } from "@/types";

export const LOCAL_WP_HOST = "wallet-provider.wct.example.org";
export const getLocalWpBaseUrl = (port: number): string =>
  `https://${LOCAL_WP_HOST}:${port}`;

export const createServer = (config: Config): express.Express => {
  const app = express();
  app.use(express.json());

  const wpBaseUrl = getLocalWpBaseUrl(config.wallet.port);

  app.get("/.well-known/openid-federation", async (_req, res) => {
    try {
      const trustAnchorBaseUrl = resolveTrustAnchorBaseUrl(config.trust_anchor);
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
  });

  app.get("/status-list", async (_req, res) => {
    try {
      const jwt = await createStatusListToken({
        certFilename: "wallet_provider_cert",
        certSubject: `CN=${LOCAL_WP_HOST}`,
        iss: wpBaseUrl,
        jwksFilename: "wallet_provider_jwks",
        jwksPath: config.wallet.backup_storage_path,
        statusListEndpointUrl: `${wpBaseUrl}/status-list`,
      });
      res.type("application/statuslist+jwt").send(jwt);
    } catch (err) {
      console.error("Failed to create wallet status list token", err);
      res.status(500).json({ error: "internal_server_error" });
    }
  });

  return app;
};

if (require.main === module) {
  const config = loadConfigWithHierarchy();
  const app = createServer(config);
  loadOrCreateServerCertificate(config)
    .then(({ certPem, keyPem }) =>
      https.createServer({ cert: certPem, key: keyPem }, app),
    )
    .then((server) =>
      server.listen(config.wallet.port, "0.0.0.0", () => {
        const wpBaseUrl = getLocalWpBaseUrl(config.wallet.port);
        console.log(
          `[Wallet Provider] ${wpBaseUrl} Server started
      PID: ${process.pid}
      URL: https://localhost:${config.wallet.port}

      Endpoints:   
      GET  /.well-known/openid-federation
      GET  /status-list

      Started: ${new Date().toISOString()}`,
        );
      }),
    );
}
