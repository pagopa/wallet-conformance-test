import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { reportCreate } from "@/commands/report-create";
import { reportList } from "@/commands/report-list";
import { openDb, resolveDbPath } from "@/report/db";
import { appendCheck, createSession } from "@/report/session-store";

const originalCwd = process.cwd();
let tempDirs: string[] = [];

beforeEach(() => {
  const dir = mkdtempSync(path.join(tmpdir(), "wct-report-commands-"));
  tempDirs.push(dir);
  process.chdir(dir);
});

afterEach(() => {
  vi.restoreAllMocks();
  process.chdir(originalCwd);

  for (const dir of tempDirs) {
    rmSync(dir, { force: true, recursive: true });
  }
  tempDirs = [];
});

describe("report commands", () => {
  it("reportList prints informative message when no runs exist", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    reportList();

    expect(logSpy).toHaveBeenCalledWith("No conformance runs found.");
  });

  it("reportList prints fixed-width table for seeded runs", () => {
    const db = openDb(resolveDbPath());
    createSession(db, {
      closedAt: "2026-03-11T10:01:23.456Z",
      id: "550e8400-e29b-41d4-a716-446655440000",
      sessionId: "550e8400-e29b-41d4-a716-446655440000",
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "PASSED",
    });
    appendCheck(db, "550e8400-e29b-41d4-a716-446655440000", {
      description: "PAR valid",
      phase: "ISSUANCE",
      requirementId: "CI_001",
      result: "PASS",
      step: "PAR",
      timestamp: "2026-03-11T10:00:10.000Z",
    });

    createSession(db, {
      closedAt: "2026-03-11T09:30:05.123Z",
      id: "a1b2c3d4-0000-1111-2222-333344445555",
      sessionId: "a1b2c3d4-0000-1111-2222-333344445555",
      startedAt: "2026-03-11T09:30:00.000Z",
      status: "FAILED",
    });
    db.close();

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    reportList();

    const output = logSpy.mock.calls.map(([value]) => String(value));
    expect(output[0]).toBe(
      "RUN ID                               STARTED AT               CLOSED AT                STATUS     CHECKS",
    );
    expect(output[1]).toBe(
      "550e8400-e29b-41d4-a716-446655440000 2026-03-11T10:00:00.000Z 2026-03-11T10:01:23.456Z PASSED     1/1",
    );
    expect(output[2]).toBe(
      "a1b2c3d4-0000-1111-2222-333344445555 2026-03-11T09:30:00.000Z 2026-03-11T09:30:05.123Z FAILED     0/0",
    );
  });

  it("reportCreate writes html report for existing run", async () => {
    const runId = "550e8400-e29b-41d4-a716-446655440000";
    const db = openDb(resolveDbPath());
    createSession(db, {
      closedAt: "2026-03-11T10:01:23.456Z",
      id: runId,
      sessionId: runId,
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "PASSED",
    });
    appendCheck(db, runId, {
      description: "PAR valid",
      httpStatus: 201,
      phase: "ISSUANCE",
      requirementId: "CI_001",
      result: "PASS",
      step: "PAR",
      timestamp: "2026-03-11T10:00:10.000Z",
    });
    db.close();

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await reportCreate(runId, "html");

    const filePath = path.resolve(
      process.cwd(),
      `conformance-report-${runId}.html`,
    );
    expect(existsSync(filePath)).toBe(true);

    const content = readFileSync(filePath, "utf8");
    expect(content.includes("IT-Wallet Conformance Report")).toBe(true);
    expect(content.includes(runId)).toBe(true);
    expect(content.includes("SUPERATO")).toBe(true);
    expect(content.includes("CI_001")).toBe(true);

    expect(logSpy).toHaveBeenCalledWith(filePath);
  });

  it("reportCreate exits non-zero when run is not found", async () => {
    const db = openDb(resolveDbPath());
    db.close();

    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((
      code?: null | number | string,
    ) => {
      throw new Error(`process.exit:${code ?? "undefined"}`);
    }) as never);

    await expect(reportCreate("missing-run", "html")).rejects.toThrow(
      "process.exit:1",
    );

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(
      "Conformance run not found: missing-run",
    );
  });
});
