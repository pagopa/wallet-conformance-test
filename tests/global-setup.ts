import { createLogger } from "@/logic/logs";
import { createServer } from "../src/trust-anchor/server";
import type { Server } from "http";

let server: Server;

export default async function setup() {
  const port = 3001;
  const app = createServer();
  const baseLog = createLogger();

  server = app.listen(port, () => {
    baseLog.info(`[globalSetup] Trust anchor server running at http://localhost:${port}`);
  });

  // teardown
  return async () => {
    server.close(() => {
      baseLog.info("[globalSetup] Trust anchor stopped");
    });
  };
}
