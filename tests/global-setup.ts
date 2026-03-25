import * as x509 from "@peculiar/x509";
import * as https from "node:https";
import * as tls from "node:tls";

import { loadOrCreateCertificateWithKey } from "@/logic";
import { createLogger } from "@/logic/logs";
import { loadConfigWithHierarchy } from "@/logic/utils";
import { registerWithExternalTrustAnchor } from "@/trust-anchor/external-ta-registration";

import { createServer } from "../src/trust-anchor/server";

let server: https.Server;

export default async function setup() {
  const config = loadConfigWithHierarchy();
  const port = config.server.port;
  const app = createServer(config);
  const baseLog = createLogger().withTag("globalSetup");

  const certDir = config.trust_anchor.tls_cert_dir ?? "./data/backup";
  const { certPath, certPem, keyPem } = await loadOrCreateCertificateWithKey(
    certDir,
    "server",
    `CN=localhost`,
    [
      new x509.SubjectAlternativeNameExtension(
        [
          { type: "dns", value: "localhost" },
          { type: "ip", value: "127.0.0.1" },
        ],
        false,
      ),
    ],
  );

  // Store cert for worker threads — setup-tls.ts reads this in each worker
  process.env["TRUST_ANCHOR_CERT_PEM"] = certPem;
  tls.setDefaultCACertificates([...tls.getCACertificates("system"), certPem]);

  const httpsServer = https.createServer({ cert: certPem, key: keyPem }, app);

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
