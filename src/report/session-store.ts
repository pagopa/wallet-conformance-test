import type { DatabaseSync } from "node:sqlite";

import { randomUUID } from "node:crypto";

import type { ConformanceCheck, ConformanceSession } from "@/report/types";

export interface SessionSummary {
  checksPerformed: number;
  checksTotal: number;
  closedAt?: string;
  runId: string;
  startedAt: string;
  status: "FAILED" | "INCOMPLETE" | "OPEN" | "PASSED";
}

interface CheckRow {
  description: string;
  error_message: null | string;
  http_status: null | number;
  phase: ConformanceCheck["phase"];
  requirement_id: string;
  result: ConformanceCheck["result"];
  step: ConformanceCheck["step"];
  timestamp: string;
}

interface SessionRow {
  closed_at: null | string;
  id: string;
  session_id: string;
  started_at: string;
  status: "FAILED" | "INCOMPLETE" | "OPEN" | "PASSED";
}

export function appendCheck(
  db: DatabaseSync,
  sessionId: string,
  check: ConformanceCheck,
): void {
  db.prepare(
    `
      INSERT INTO checks (
        id,
        session_id,
        requirement_id,
        description,
        step,
        phase,
        result,
        timestamp,
        http_status,
        error_message
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
  ).run(
    randomUUID(),
    sessionId,
    check.requirementId,
    check.description,
    check.step,
    check.phase,
    check.result,
    check.timestamp,
    check.httpStatus ?? null,
    check.errorMessage ?? null,
  );
}

export function closeSession(
  db: DatabaseSync,
  sessionId: string,
  status: "FAILED" | "INCOMPLETE" | "PASSED",
  closedAt: string,
): void {
  db.prepare(
    `
      UPDATE sessions
      SET status = ?, closed_at = ?
      WHERE id = ?
    `,
  ).run(status, closedAt, sessionId);
}

export function createSession(
  db: DatabaseSync,
  session: Omit<ConformanceSession, "checks">,
): void {
  db.prepare(
    `
      INSERT INTO sessions (id, session_id, started_at, closed_at, status)
      VALUES (?, ?, ?, ?, ?)
    `,
  ).run(
    session.id,
    session.sessionId,
    session.startedAt,
    session.closedAt ?? null,
    session.status,
  );
}

export function getSession(
  db: DatabaseSync,
  sessionId: string,
): ConformanceSession | undefined {
  const sessionRow = db
    .prepare(
      `
        SELECT id, session_id, started_at, closed_at, status
        FROM sessions
        WHERE id = ?
      `,
    )
    .get(sessionId) as SessionRow | undefined;

  if (!sessionRow) {
    return undefined;
  }

  const checksRows = db
    .prepare(
      `
        SELECT
          requirement_id,
          description,
          step,
          phase,
          result,
          timestamp,
          http_status,
          error_message
        FROM checks
        WHERE session_id = ?
        ORDER BY timestamp ASC
      `,
    )
    .all(sessionId) as unknown as CheckRow[];

  return {
    checks: checksRows.map((check) => ({
      description: check.description,
      errorMessage: check.error_message ?? undefined,
      httpStatus: check.http_status ?? undefined,
      phase: check.phase,
      requirementId: check.requirement_id,
      result: check.result,
      step: check.step,
      timestamp: check.timestamp,
    })),
    closedAt: sessionRow.closed_at ?? undefined,
    id: sessionRow.id,
    sessionId: sessionRow.session_id,
    startedAt: sessionRow.started_at,
    status: sessionRow.status,
  };
}

export function listSessions(db: DatabaseSync): SessionSummary[] {
  const rows = db
    .prepare(
      `
        SELECT
          s.id,
          s.started_at,
          s.closed_at,
          s.status,
          COUNT(c.id) AS checks_performed
        FROM sessions s
        LEFT JOIN checks c ON c.session_id = s.id
        GROUP BY s.id, s.started_at, s.closed_at, s.status
        ORDER BY s.started_at DESC
      `,
    )
    .all() as {
    checks_performed: number;
    closed_at: null | string;
    id: string;
    started_at: string;
    status: "FAILED" | "INCOMPLETE" | "OPEN" | "PASSED";
  }[];

  return rows.map((row) => ({
    checksPerformed: row.checks_performed,
    checksTotal: row.checks_performed,
    closedAt: row.closed_at ?? undefined,
    runId: row.id,
    startedAt: row.started_at,
    status: row.status,
  }));
}
