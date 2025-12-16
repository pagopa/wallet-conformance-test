import type { Server } from "http";

import { createLogger } from "@/logic/logs";
import { loadConfigWithHierarchy } from "@/logic/utils";

import { createServer } from "../src/trust-anchor/server";

let server: Server;

export default async function setup() {
  const config = loadConfigWithHierarchy();
  const port = config.server.port;
  const app = createServer();
  const baseLog = createLogger().withTag("globalSetup");

  server = app.listen(port, () => {
    baseLog.info(`Trust anchor server running at http://localhost:${port}`);
  });

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
