/* eslint-disable max-lines-per-function */
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

  it("reportCreate --view both renders screen switcher and print tab bars", async () => {
    const runId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const db = openDb(resolveDbPath());
    createSession(db, {
      id: runId,
      sessionId: runId,
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "PASSED",
    });
    appendCheck(db, runId, {
      description: "CI_001: PAR",
      phase: "ISSUANCE",
      requirementId: "CI_001",
      result: "PASS",
      step: "PAR",
      timestamp: "2026-03-11T10:00:01.000Z",
    });
    db.close();

    vi.spyOn(console, "log").mockImplementation(() => {});
    await reportCreate(runId, "html", "both");

    const content = readFileSync(
      path.resolve(process.cwd(), `conformance-report-${runId}.html`),
      "utf8",
    );

    expect(
      content.includes('class="view-switcher"'),
      "screen switcher present",
    ).toBe(true);
    expect(
      content.includes('class="print-tab-bar"'),
      "print tab bars present",
    ).toBe(true);
    expect(
      content.includes('id="view-executive"'),
      "executive panel present",
    ).toBe(true);
    expect(
      content.includes('id="view-technical"'),
      "technical panel present",
    ).toBe(true);
    expect(
      content.includes('href="#view-executive"'),
      "link to executive present",
    ).toBe(true);
    expect(
      content.includes('href="#view-technical"'),
      "link to technical present",
    ).toBe(true);
  });

  it("reportCreate --view executive renders only executive view", async () => {
    const runId = "11111111-2222-3333-4444-555555555555";
    const db = openDb(resolveDbPath());
    createSession(db, {
      id: runId,
      sessionId: runId,
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "FAILED",
    });
    appendCheck(db, runId, {
      description: "CI_001: PAR",
      errorMessage: "missing",
      phase: "ISSUANCE",
      requirementId: "CI_001",
      result: "FAIL",
      step: "PAR",
      timestamp: "2026-03-11T10:00:01.000Z",
    });
    db.close();

    vi.spyOn(console, "log").mockImplementation(() => {});
    await reportCreate(runId, "html", "executive");

    const content = readFileSync(
      path.resolve(process.cwd(), `conformance-report-${runId}.html`),
      "utf8",
    );

    expect(
      content.includes('class="view-switcher"'),
      "no screen switcher",
    ).toBe(false);
    expect(content.includes('class="print-tab-bar"'), "no print tab bar").toBe(
      false,
    );
    expect(
      content.includes("Sintesi Esecutiva"),
      "executive content present",
    ).toBe(true);
    expect(
      content.includes('class="check-card'),
      "no technical check cards",
    ).toBe(false);
  });

  it("reportCreate --view technical renders only technical view", async () => {
    const runId = "66666666-7777-8888-9999-000000000000";
    const db = openDb(resolveDbPath());
    createSession(db, {
      id: runId,
      sessionId: runId,
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "PASSED",
    });
    appendCheck(db, runId, {
      description: "CI_001: PAR",
      phase: "ISSUANCE",
      requirementId: "CI_001",
      result: "PASS",
      step: "PAR",
      timestamp: "2026-03-11T10:00:01.000Z",
    });
    db.close();

    vi.spyOn(console, "log").mockImplementation(() => {});
    await reportCreate(runId, "html", "technical");

    const content = readFileSync(
      path.resolve(process.cwd(), `conformance-report-${runId}.html`),
      "utf8",
    );

    expect(
      content.includes('class="view-switcher"'),
      "no screen switcher",
    ).toBe(false);
    expect(content.includes('class="print-tab-bar"'), "no print tab bar").toBe(
      false,
    );
    expect(
      content.includes('class="check-card'),
      "technical check cards present",
    ).toBe(true);
    expect(content.includes("Sintesi Esecutiva"), "no executive content").toBe(
      false,
    );
  });

  it("reportCreate rejects invalid view values", async () => {
    await expect(
      reportCreate("any-id", "html", "invalid-view"),
    ).rejects.toThrow("Invalid report view: invalid-view");
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
