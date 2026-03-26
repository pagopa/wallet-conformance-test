import * as https from "node:https";
import * as tls from "node:tls";

import { createLogger } from "@/logic/logs";
import { loadConfigWithHierarchy } from "@/logic/utils";
import { registerWithExternalTrustAnchor } from "@/trust-anchor/external-ta-registration";
import { createServer, startServer } from "@/trust-anchor/server";

let trustAnchorServer: https.Server;

export default async function setup() {
  const config = loadConfigWithHierarchy();
  const baseLog = createLogger().withTag("globalSetup");

  const trustAnchorApp = createServer(config);
  const {
    certPath,
    certPem,
    port,
    server: trustAnchorHttpsServer,
  } = await startServer(trustAnchorApp, config);

  // Store cert for worker threads — setup-tls.ts reads this in each worker
  process.env["TRUST_ANCHOR_CERT_PEM"] = certPem;
  tls.setDefaultCACertificates([...tls.getCACertificates("bundled"), certPem]);

  trustAnchorServer = trustAnchorHttpsServer.listen(port, () => {
    baseLog.info(
      `Trust anchor server running at https://localhost:${port} (cert: ${certPath})`,
    );
  });

  await registerWithExternalTrustAnchor(config);

  // teardown
  return async () => {
    await new Promise<void>((resolve) => {
      trustAnchorServer.close(() => {
        baseLog.info("Trust anchor stopped");
        resolve();
      });
    });
  };
}
