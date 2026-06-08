import { afterEach, describe, expect, it, vi } from "vitest";

import type { ConformanceSession } from "@/report/types";

import { serializeToVitestJson } from "@/report/serializer";

afterEach(() => {
  vi.useRealTimers();
});

function buildSession(
  overrides: Partial<ConformanceSession> = {},
): ConformanceSession {
  return {
    checks: [],
    id: "run-1",
    sessionId: "run-1",
    startedAt: "2026-03-11T10:00:00.000Z",
    status: "OPEN",
    ...overrides,
  };
}

describe("serializeToVitestJson", () => {
  it("computes counters for all-pass checks", () => {
    const session = buildSession({
      checks: [
        {
          description: "PAR valid",
          httpStatus: 201,
          phase: "ISSUANCE",
          requirementId: "CI_001",
          result: "PASS",
          step: "PAR",
          timestamp: "2026-03-11T10:00:01.000Z",
        },
        {
          description: "Token valid",
          phase: "ISSUANCE",
          requirementId: "CI_002",
          result: "PASS",
          step: "TOKEN",
          timestamp: "2026-03-11T10:00:02.000Z",
        },
      ],
      status: "PASSED",
    });

    const report = serializeToVitestJson(session, 24);

    expect(report.status).toBe("PASSED");
    expect(report.success).toBe(true);
    expect(report.numTotalTests).toBe(2);
    expect(report.numPassedTests).toBe(2);
    expect(report.numFailedTests).toBe(0);
    expect(report.numPendingTests).toBe(0);
    expect(report.numTotalTestSuites).toBe(2);
    expect(report.numPassedTestSuites).toBe(2);
    expect(report.numFailedTestSuites).toBe(0);
    expect(report.numPendingTestSuites).toBe(0);
  });

  it("computes counters for mixed pass fail not-reached", () => {
    const session = buildSession({
      checks: [
        {
          description: "PAR valid",
          phase: "ISSUANCE",
          requirementId: "CI_001",
          result: "PASS",
          step: "PAR",
          timestamp: "2026-03-11T10:00:01.000Z",
        },
        {
          description: "Authorize fails",
          errorMessage: "bad request",
          phase: "ISSUANCE",
          requirementId: "CI_002",
          result: "FAIL",
          step: "AUTHORIZE",
          timestamp: "2026-03-11T10:00:02.000Z",
        },
        {
          description: "Token not reached",
          phase: "ISSUANCE",
          requirementId: "CI_003",
          result: "NOT_REACHED",
          step: "TOKEN",
          timestamp: "2026-03-11T10:00:03.000Z",
        },
      ],
      status: "FAILED",
    });

    const report = serializeToVitestJson(session, 24);

    expect(report.status).toBe("FAILED");
    expect(report.success).toBe(false);
    expect(report.numTotalTests).toBe(3);
    expect(report.numPassedTests).toBe(1);
    expect(report.numFailedTests).toBe(1);
    expect(report.numPendingTests).toBe(1);
    expect(report.numTotalTestSuites).toBe(3);
    expect(report.numPassedTestSuites).toBe(1);
    expect(report.numFailedTestSuites).toBe(1);
    expect(report.numPendingTestSuites).toBe(1);
  });

  it("keeps OPEN within TTL", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-11T10:30:00.000Z"));

    const session = buildSession({
      checks: [
        {
          description: "PAR valid",
          phase: "ISSUANCE",
          requirementId: "CI_001",
          result: "PASS",
          step: "PAR",
          timestamp: "2026-03-11T10:00:01.000Z",
        },
      ],
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "OPEN",
    });

    const report = serializeToVitestJson(session, 1);

    expect(report.status).toBe("OPEN");
    expect(session.status).toBe("OPEN");
  });

  it("serializes OPEN past TTL as INCOMPLETE without mutating session", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-11T12:00:00.000Z"));

    const session = buildSession({
      checks: [
        {
          description: "PAR valid",
          phase: "ISSUANCE",
          requirementId: "CI_001",
          result: "NOT_REACHED",
          step: "PAR",
          timestamp: "2026-03-11T10:00:01.000Z",
        },
      ],
      startedAt: "2026-03-11T10:00:00.000Z",
      status: "OPEN",
    });

    const report = serializeToVitestJson(session, 1);

    expect(report.status).toBe("INCOMPLETE");
    expect(report.success).toBe(false);
    expect(session.status).toBe("OPEN");
  });
});
