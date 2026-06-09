import { describe, expect, it } from "vitest";

import { openDb } from "@/report/db";
import {
  appendCheck,
  closeSession,
  createSession,
  getSession,
  listSessions,
} from "@/report/session-store";

describe("session-store", () => {
  it("createSession + appendCheck + getSession round-trip", () => {
    const db = openDb(":memory:");

    createSession(db, {
      id: "run-1",
      phase: "ISSUANCE",
      sessionId: "run-1",
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "OPEN",
    });

    appendCheck(db, "run-1", {
      description: "PAR request is valid",
      httpStatus: 201,
      phase: "ISSUANCE",
      requirementId: "CI_001",
      result: "PASS",
      step: "PAR",
      timestamp: "2026-03-11T10:00:01.000Z",
    });

    appendCheck(db, "run-1", {
      description: "Token response is valid",
      errorMessage: "invalid token",
      phase: "ISSUANCE",
      requirementId: "CI_002",
      result: "FAIL",
      step: "TOKEN",
      timestamp: "2026-03-11T10:00:02.000Z",
    });

    const session = getSession(db, "run-1");

    expect(session).toBeDefined();
    expect(session?.id).toBe("run-1");
    expect(session?.status).toBe("OPEN");
    expect(session?.checks).toHaveLength(2);
    expect(session?.checks[0]?.requirementId).toBe("CI_001");
    expect(session?.checks[1]?.result).toBe("FAIL");
    expect(session?.checks[1]?.errorMessage).toBe("invalid token");
  });

  it("closeSession updates status and closedAt", () => {
    const db = openDb(":memory:");

    createSession(db, {
      id: "run-2",
      phase: "ISSUANCE",
      sessionId: "run-2",
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "OPEN",
    });

    closeSession(db, "run-2", "FAILED", "2026-03-11T10:01:00.000Z");

    const session = getSession(db, "run-2");
    expect(session?.status).toBe("FAILED");
    expect(session?.closedAt).toBe("2026-03-11T10:01:00.000Z");
  });

  it("listSessions returns startedAt DESC with check counts", () => {
    const db = openDb(":memory:");

    createSession(db, {
      id: "run-older",
      phase: "ISSUANCE",
      sessionId: "run-older",
      startedAt: "2026-03-11T09:00:00.000Z",
      status: "OPEN",
    });

    createSession(db, {
      id: "run-newer",
      phase: "ISSUANCE",
      sessionId: "run-newer",
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "OPEN",
    });

    appendCheck(db, "run-newer", {
      description: "Nonce is returned",
      phase: "ISSUANCE",
      requirementId: "CI_010",
      result: "PASS",
      step: "NONCE",
      timestamp: "2026-03-11T10:00:10.000Z",
    });

    const sessions = listSessions(db);
    expect(sessions.map((session) => session.runId)).toEqual([
      "run-newer",
      "run-older",
    ]);
    expect(sessions[0]?.checksPerformed).toBe(1);
    expect(sessions[0]?.checksTotal).toBe(1);
    expect(sessions[1]?.checksPerformed).toBe(0);
    expect(sessions[1]?.checksTotal).toBe(0);
  });
});
