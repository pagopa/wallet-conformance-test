import * as https from "node:https";
import * as tls from "node:tls";

import { createLogger } from "@/logic/logs";
import {
  loadConfigWithHierarchy,
  loadOrCreateServerCertificate,
} from "@/logic/utils";
import { createServer as createMockIssuerServer } from "@/servers/ci-server";
import { createServer } from "@/servers/ta-server";
import { createServer as createWalletProviderServer } from "@/servers/wp-server";

let trustAnchorServer: https.Server;
let walletProviderServer: https.Server;
let mockIssuerServer: https.Server;

export default async function setup() {
  const config = loadConfigWithHierarchy();
  const baseLog = createLogger().withTag("globalSetup");

  const trustAnchorApp = createServer(config);
  const taPort = config.trust_anchor.port;
  const { certPath, certPem, keyPem } =
    await loadOrCreateServerCertificate(config);
  const trustAnchorHttpsServer = https.createServer(
    { cert: certPem, key: keyPem },
    trustAnchorApp,
  );

  const walletProviderApp = createWalletProviderServer(config);
  const wpPort = config.wallet.port;
  const wpHttpsServer = https.createServer(
    { cert: certPem, key: keyPem },
    walletProviderApp,
  );

  const mockIssuerApp = createMockIssuerServer(config);
  const miPort = config.issuer.port;
  const miHttpsServer = https.createServer(
    { cert: certPem, key: keyPem },
    mockIssuerApp,
  );

  // Store cert for worker threads — setup-tls.ts reads this in each worker
  process.env["TRUST_ANCHOR_CERT_PEM"] = certPem;
  tls.setDefaultCACertificates([
    ...tls.getCACertificates("bundled"),
    ...tls.getCACertificates("system"),
    certPem,
  ]);

  const bindAddress = config.network.bind_address;

  trustAnchorServer = trustAnchorHttpsServer.listen(taPort, bindAddress, () => {
    baseLog.info(
      `Trust anchor server running at https://localhost:${taPort} (cert: ${certPath})`,
    );
  });

  walletProviderServer = wpHttpsServer.listen(wpPort, bindAddress, () => {
    baseLog.info(
      `Wallet provider server running at https://localhost:${wpPort}`,
    );
  });

  mockIssuerServer = miHttpsServer.listen(miPort, bindAddress, () => {
    baseLog.info(
      `Credential Issuer server running at https://localhost:${miPort}`,
    );
  });

  // teardown
  return async () => {
    const closeServer = (server: https.Server, name: string) =>
      new Promise<void>((resolve) => {
        server.close(() => {
          baseLog.info(`${name} stopped`);
          resolve();
        });
      });

    await Promise.all([
      closeServer(trustAnchorServer, "Trust anchor"),
      closeServer(walletProviderServer, "Wallet provider"),
      closeServer(mockIssuerServer, "Credential Issuer"),
    ]);
  };
}
