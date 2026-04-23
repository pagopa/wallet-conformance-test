import express from "express";
import * as https from "node:https";

import {
  createSubordinateCredentialIssuerMetadata,
  createSubordinateWalletUnitMetadata,
  createTrustAnchorMetadata,
} from "@/logic/federation-metadata";
import {
  loadConfigWithHierarchy,
  loadOrCreateServerCertificate,
} from "@/logic/utils";
import { getLocalCiBaseUrl } from "@/servers/ci-server";
import { getLocalWpBaseUrl } from "@/servers/wp-server";
import { LOCAL_TA_BASE_URL } from "@/trust-anchor/trust-anchor-resolver";
import { Config } from "@/types";

export const createServer = (config: Config): express.Express => {
  const app = express();
  app.use(express.json());

  const trustAnchorBaseUrl = `${LOCAL_TA_BASE_URL}:${config.trust_anchor.port}`;
  const wpBaseUrl = getLocalWpBaseUrl(config.wallet.port);
  const ciBaseUrl = getLocalCiBaseUrl(config.issuer.port);

  // federation metadata
  app.get("/.well-known/openid-federation", async (_req, res) => {
    try {
      const jwt = await createTrustAnchorMetadata({
        trustAnchor: config.trust,
        trustAnchorBaseUrl,
        walletVersion: config.wallet.wallet_version,
      });
      res.type("application/entity-statement+jwt").send(jwt);
    } catch (err) {
      console.error("Failed to create trust anchor metadata", err);
      res.status(500).json({ error: "internal_server_error" });
    }
  });

  // fetch subordinate statement
  app.get("/fetch", async (req, res) => {
    try {
      const sub = req.query.sub as string | undefined;

      if (!sub) {
        return res.status(400).json({ error: "sub_parameter_required" });
      }

      let subordinateStatement: string;

      if (sub === wpBaseUrl) {
        subordinateStatement = await createSubordinateWalletUnitMetadata({
          sub,
          trustAnchor: config.trust,
          trustAnchorBaseUrl,
          walletBackupStoragePath: config.wallet.backup_storage_path,
        });
      } else if (sub === ciBaseUrl) {
        subordinateStatement = await createSubordinateCredentialIssuerMetadata({
          sub,
          trustAnchor: config.trust,
          trustAnchorBaseUrl,
          walletBackupStoragePath: config.wallet.backup_storage_path,
        });
      } else {
        return res.status(404).json({ error: "not_found" });
      }

      res.type("application/entity-statement+jwt").send(subordinateStatement);
    } catch (err) {
      console.error("Failed to create subordinate statement", err);
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
      server.listen(config.trust_anchor.port, config.network.bind_address, () => {
        console.log(
          `[Trust Anchor] Server started
        PID: ${process.pid}
        URL: https://localhost:${config.trust_anchor.port}

      Endpoints:
      GET  /.well-known/openid-federation
      GET  /fetch?sub=<subordinate-url>

      Started: ${new Date().toISOString()}`,
        );
      }),
    );
}
