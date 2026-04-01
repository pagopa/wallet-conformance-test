import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import express from "express";
import * as https from "node:https";

import { buildIssuerEntityConfiguration_V1_0 } from "@/functions/V1_0/mock-credentials";
import { buildIssuerEntityConfiguration_V1_3 } from "@/functions/V1_3/mock-credentials";
import {
  buildJwksPath,
  createStatusListToken,
  loadConfigWithHierarchy,
  loadJwks,
  loadOrCreateServerCertificate,
} from "@/logic";
import { Config } from "@/types";

export const LOCAL_CI_HOST = "credential-issuer.wct.it";
export const getLocalCiBaseUrl = (port: number): string =>
  `https://${LOCAL_CI_HOST}:${port}`;

export const createServer = (config: Config): express.Express => {
  const app = express();
  app.use(express.json());

  const ciBaseUrl = getLocalCiBaseUrl(config.issuer.port);

  app.get("/.well-known/openid-federation", async (_req, res) => {
    try {
      const keyPair = await loadJwks(
        config.wallet.backup_storage_path,
        buildJwksPath("issuer_pid_mocked"),
      );
      const metadata = {
        iss: ciBaseUrl,
        trust: config.trust,
        trustAnchor: config.trust_anchor,
      };

      let jwt: string;
      switch (config.wallet.wallet_version) {
        case ItWalletSpecsVersion.V1_0:
          jwt = await buildIssuerEntityConfiguration_V1_0(metadata, keyPair);
          break;
        case ItWalletSpecsVersion.V1_3:
          jwt = await buildIssuerEntityConfiguration_V1_3(metadata, keyPair);
          break;
        default:
          throw new Error(
            `unimplemented wallet_version: ${config.wallet.wallet_version}`,
          );
      }
      res.type("application/entity-statement+jwt").send(jwt);
    } catch (err) {
      console.error("Failed to build mocked issuer entity configuration", err);
      res.status(500).json({ error: "internal_server_error" });
    }
  });

  app.get("/status-list", async (_req, res) => {
    try {
      const jwt = await createStatusListToken({
        certFilename: "issuer_cert",
        certSubject: "CN=test_issuer",
        iss: ciBaseUrl,
        jwksFilename: buildJwksPath("issuer_pid_mocked"),
        jwksPath: config.wallet.backup_storage_path,
        statusListEndpointUrl: `${ciBaseUrl}/status-list`,
      });
      res.type("application/statuslist+jwt").send(jwt);
    } catch (err) {
      console.error("Failed to create credentials status list token", err);
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
      server.listen(config.issuer.port, () => {
        const ciBaseUrl = getLocalCiBaseUrl(config.issuer.port);

        console.log(
          `[Credential Issuer] ${ciBaseUrl} Server started
        PID: ${process.pid}
        URL: https://localhost:${config.issuer.port}

        Endpoints:
        GET  /.well-known/openid-federation
        GET  /status-list

        Started: ${new Date().toISOString()}`,
        );
      }),
    );
}
