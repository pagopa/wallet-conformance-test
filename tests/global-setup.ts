import * as https from "node:https";
import * as tls from "node:tls";

import { createLogger } from "@/logic/logs";
import { loadConfigWithHierarchy } from "@/logic/utils";
import { registerWithExternalTrustAnchor } from "@/trust-anchor/external-ta-registration";
import { startServer } from "@/trust-anchor/server";

let server: https.Server;

export default async function setup() {
  const config = loadConfigWithHierarchy();
  const baseLog = createLogger().withTag("globalSetup");

  const {
    certPath,
    certPem,
    port,
    server: httpsServer,
  } = await startServer(config);

  // Store cert for worker threads — setup-tls.ts reads this in each worker
  process.env["TRUST_ANCHOR_CERT_PEM"] = certPem;
  tls.setDefaultCACertificates([...tls.getCACertificates("system"), certPem]);

  server = httpsServer.listen(port, () => {
    baseLog.info(
      `Trust anchor server running at https://localhost:${port} (cert: ${certPath})`,
    );
  });

  await registerWithExternalTrustAnchor(config);

  // teardown
  return async () => {
    await new Promise<void>((resolve) => {
      server.close(() => {
        baseLog.info("Trust anchor stopped");
        resolve();
      });
    });
  };
}
