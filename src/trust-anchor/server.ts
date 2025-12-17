import express from "express";

import {
  createSubordinateWalletUnitMetadata,
  createTrustAnchorMetadata,
} from "@/logic/federation-metadata";

import { loadConfig } from "../logic/utils";

export const createServer = () => {
  const app = express();
  app.use(express.json());

  const config = loadConfig("./config.ini");
  const trustAnchorBaseUrl = `https://127.0.0.1:${config.server.port}`;

  // federation metadata
  app.get("/.well-known/openid-federation", async (_req, res) => {
    try {
      const jwt = await createTrustAnchorMetadata({
        federationTrustAnchorsJwksPath:
          config.trust.federation_trust_anchors_jwks_path,
        trustAnchorBaseUrl,
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
        federationTrustAnchorsJwksPath:
          config.trust.federation_trust_anchors_jwks_path,
        sub,
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

if (require.main === module) {
  const port = 3001;
  const app = createServer();
  app.listen(port, () => {
    console.log(
      `[Trust Anchor] Server started
      PID: ${process.pid}
      URL: http://localhost:${port}
      Endpoints:
      GET  /.well-known/openid-federation
      GET  /fetch?sub=<subordinate-url>
      Started: ${new Date().toISOString()}`,
    );
  });
}
