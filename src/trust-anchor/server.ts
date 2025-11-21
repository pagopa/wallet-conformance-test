import express from "express";

import { createTrustAnchorMetadata, loadConfig } from "@/logic";

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
      Started: ${new Date().toISOString()}`,
    );
  });
}
