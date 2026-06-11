import { openDb, resolveDbPath } from "@/report/db";
import { listSessions } from "@/report/session-store";

const RUN_ID_WIDTH = 36;
const STARTED_AT_WIDTH = 24;
const CLOSED_AT_WIDTH = 24;
const STATUS_WIDTH = 10;

export function reportList(): void {
  const db = openDb(resolveDbPath());

  try {
    const sessions = listSessions(db);
    if (sessions.length === 0) {
      console.log("No conformance runs found.");
      return;
    }

    const header = [
      "RUN ID".padEnd(RUN_ID_WIDTH),
      "STARTED AT".padEnd(STARTED_AT_WIDTH),
      "CLOSED AT".padEnd(CLOSED_AT_WIDTH),
      "STATUS".padEnd(STATUS_WIDTH),
      "CHECKS",
    ].join(" ");

    const rows = sessions.map((session) =>
      [
        session.runId.padEnd(RUN_ID_WIDTH),
        session.startedAt.padEnd(STARTED_AT_WIDTH),
        (session.closedAt ?? "-").padEnd(CLOSED_AT_WIDTH),
        session.status.padEnd(STATUS_WIDTH),
        String(session.checksPerformed),
      ].join(" "),
    );

    console.log(header);
    for (const row of rows) {
      console.log(row);
    }
  } finally {
    db.close();
  }
}
