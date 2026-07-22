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

  try {
    await startServer(trustAnchorHttpsServer, taPort, bindAddress);
    baseLog.info(
      `Trust anchor server running at https://${bindAddress}:${taPort} (cert: ${certPath})`,
    );

    await startServer(wpHttpsServer, wpPort, bindAddress);
    baseLog.info(
      `Wallet provider server running at https://${bindAddress}:${wpPort}`,
    );

    await startServer(miHttpsServer, miPort, bindAddress);
    baseLog.info(
      `Credential Issuer server running at https://${bindAddress}:${miPort}`,
    );
  } catch (error) {
    await Promise.allSettled([
      closeServer(trustAnchorHttpsServer),
      closeServer(wpHttpsServer),
      closeServer(miHttpsServer),
    ]);
    throw error;
  }

  trustAnchorServer = trustAnchorHttpsServer;
  walletProviderServer = wpHttpsServer;
  mockIssuerServer = miHttpsServer;

  // teardown
  return async () => {
    await Promise.all([
      closeServer(trustAnchorServer).then(() =>
        baseLog.info("Trust anchor stopped"),
      ),
      closeServer(walletProviderServer).then(() =>
        baseLog.info("Wallet provider stopped"),
      ),
      closeServer(mockIssuerServer).then(() =>
        baseLog.info("Credential Issuer stopped"),
      ),
    ]);
  };
}

function closeServer(server: https.Server): Promise<void> {
  if (!server.listening) {
    return Promise.resolve();
  }

  const { promise, reject, resolve } = Promise.withResolvers<undefined>();
  server.close((error) => {
    if (error) {
      reject(error);
      return;
    }

    resolve(undefined);
  });

  return promise;
}

function startServer(
  server: https.Server,
  port: number,
  bindAddress: string,
): Promise<void> {
  const { promise, reject, resolve } = Promise.withResolvers<undefined>();
  const rejectStart = (error: Error) => reject(error);

  server.once("error", rejectStart);

  try {
    server.listen(port, bindAddress, () => {
      server.off("error", rejectStart);
      resolve(undefined);
    });
  } catch (error) {
    server.off("error", rejectStart);
    reject(error);
  }

  return promise;
}
