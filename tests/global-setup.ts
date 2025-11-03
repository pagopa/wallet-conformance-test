import type { Server } from "http";

import { createLogger } from "@/logic/logs";

import { createServer } from "../src/trust-anchor/server";

let server: Server;

export default async function setup() {
  const port = 3001;
  const app = createServer();
  const baseLog = createLogger();

  server = app.listen(port, () => {
    baseLog.info(
      `[globalSetup] Trust anchor server running at http://localhost:${port}`,
    );
  });

  // teardown
  return new Promise<void>((resolve) => {
    server.close(() => {
      baseLog.info("[globalSetup] Trust anchor stopped");
      resolve();
    });
  });
}
