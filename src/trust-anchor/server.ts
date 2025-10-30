
import express from "express";
import { loadConfig } from "../logic/utils";
import { createTrustAnchorMetadata } from "@/logic/federation-metadata";

export const createServer = () => {
  const app = express();
  app.use(express.json());

  const config = loadConfig("./config.ini");

  // federation metadata
  app.get("/.well-known/openid-federation", async (_req, res) => {
    try {
      const jwt = await createTrustAnchorMetadata({
        federationTrustAnchorsJwksPath: config.trust.federation_trust_anchors_jwks_path,
      });
      res.type("application/jwt").send(jwt);
    } catch (err) {
      console.error("Failed to create trust anchor metadata", err);
      res.status(500).json({ error: "internal_server_error" });
    }
  });

  return app;
}

if (require.main === module) {
  const port = 3001;
  const app = createServer();
  app.listen(port, () => {
    console.log(
        `[Trust Anchor] Server started
      PID: ${process.pid}
      Environment: ${process.env.NODE_ENV || "development"}
      URL: http://localhost:${port}
      Endpoints:
      GET  /.well-known/openid-federation
      GET  /list
      GET  /fetch
      POST /status
      GET  /historical-jwks
      GET  /federation_subordinate_events_endpoint
      Started: ${new Date().toISOString()}`
      );
    });
}
