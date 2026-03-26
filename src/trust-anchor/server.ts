import * as x509 from "@peculiar/x509";
import express from "express";
import * as https from "node:https";

import { loadOrCreateCertificateWithKey } from "@/logic";
import {
  createSubordinateWalletUnitMetadata,
  createTrustAnchorMetadata,
} from "@/logic/federation-metadata";
import { Config } from "@/types";

import { loadConfigWithHierarchy } from "../logic/utils";
import { LOCAL_TA_BASE_URL, LOCAL_TA_HOST } from "./trust-anchor-resolver";

export const createServer = (config: Config) => {
  const app = express();
  app.use(express.json());

  const trustAnchorBaseUrl = `${LOCAL_TA_BASE_URL}:${config.trust_anchor.port}`;

  // federation metadata
  app.get("/.well-known/openid-federation", async (_req, res) => {
    try {
      const jwt = await createTrustAnchorMetadata({
        trustAnchor: config.trust,
        trustAnchorBaseUrl,
        walletVersion: config.wallet.wallet_version,
      });
      res.type("application/jwt").send(jwt);
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

      // Check if the subject matches the wallet provider base URL
      if (sub !== config.wallet.wallet_provider_base_url) {
        return res.status(404).json({ error: "subordinate_not_found" });
      }

      // Create the subordinate statement
      const subordinateStatement = await createSubordinateWalletUnitMetadata({
        sub,
        trustAnchor: config.trust,
        trustAnchorBaseUrl,
        walletBackupStoragePath: config.wallet.backup_storage_path,
      });

      res.type("application/entity-statement+jwt").send(subordinateStatement);
    } catch (err) {
      console.error("Failed to create subordinate statement", err);
      res.status(500).json({ error: "internal_server_error" });
    }
  });

  return app;
};

export const startServer = async (
  app: express.Express,
  config: Config,
): Promise<{
  certPath: string;
  certPem: string;
  port: number;
  server: https.Server;
}> => {
  const port = config.trust_anchor.port;
  const certDir = config.trust_anchor.tls_cert_dir ?? "./data/backup";

  const { certPath, certPem, keyPem } = await loadOrCreateCertificateWithKey(
    certDir,
    "server",
    `CN=${LOCAL_TA_HOST}`,
    [
      new x509.SubjectAlternativeNameExtension(
        [
          { type: "dns", value: "localhost" },
          { type: "dns", value: LOCAL_TA_HOST },
          { type: "ip", value: "127.0.0.1" },
        ],
        false,
      ),
    ],
  );

  const server = https.createServer({ cert: certPem, key: keyPem }, app);
  return { certPath, certPem, port, server };
};

if (require.main === module) {
  const config = loadConfigWithHierarchy();
  const app = createServer(config);
  startServer(app, config).then(({ certPath, port, server }) => {
    server.listen(port, () => {
      console.log(
        `Local Server started
      PID: ${process.pid}
      URL: https://localhost:${port}
      Cert: ${certPath}

      Endpoints:
      [Trust Anchor]
      GET  /.well-known/openid-federation
      GET  /fetch?sub=<subordinate-url>

      Started: ${new Date().toISOString()}`,
      );
    });
  });
}
