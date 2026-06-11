import type { DatabaseSync } from "node:sqlite";

import { randomUUID } from "node:crypto";

import type {
  ConformanceCheck,
  ConformanceSession,
  Phase,
} from "@/report/types";

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
  phase: ConformanceCheck["phase"];
  requirement_id: string;
  result: ConformanceCheck["result"];
  timestamp: string;
}

interface SessionRow {
  closed_at: null | string;
  id: string;
  phase: Phase;
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
        phase,
        result,
        timestamp,
        error_message
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
  ).run(
    randomUUID(),
    sessionId,
    check.requirementId,
    check.description,
    check.phase,
    check.result,
    check.timestamp,
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
      INSERT INTO sessions (id, started_at, closed_at, phase, status)
      VALUES (?, ?, ?, ?, ?)
    `,
  ).run(
    session.id,
    session.startedAt,
    session.closedAt ?? null,
    session.phase,
    session.status,
  );
}

export function getLatestSessionId(db: DatabaseSync): string | undefined {
  const row = db
    .prepare(
      `
        SELECT id
        FROM sessions
        ORDER BY started_at DESC, id DESC
        LIMIT 1
      `,
    )
    .get() as undefined | { id: string };

  return row?.id;
}

export function getSession(
  db: DatabaseSync,
  sessionId: string,
): ConformanceSession | undefined {
  const sessionRow = db
    .prepare(
      `
        SELECT id, started_at, closed_at, phase, status
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
          phase,
          result,
          timestamp,
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
      phase: check.phase,
      requirementId: check.requirement_id,
      result: check.result,
      timestamp: check.timestamp,
    })),
    closedAt: sessionRow.closed_at ?? undefined,
    id: sessionRow.id,
    phase: sessionRow.phase,
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
