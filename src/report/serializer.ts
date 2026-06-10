import type {
  ConformanceCheck,
  ConformanceSession,
  VitestAssertionResult,
  VitestJsonReport,
  VitestTestSuite,
} from "@/report/types";

type SerializedStatus = "FAILED" | "INCOMPLETE" | "OPEN" | "PASSED";

export function serializeToVitestJson(
  session: ConformanceSession,
  ttlHours: number,
): VitestJsonReport {
  const testResults: VitestTestSuite[] = [
    toSuite(session.phase, session.checks),
  ];

  let numPassedTests = 0;
  let numFailedTests = 0;
  let numPendingTests = 0;
  let numTodoTests = 0;

  for (const suite of testResults) {
    for (const assertion of suite.assertionResults) {
      if (assertion.status === "passed") {
        numPassedTests += 1;
        continue;
      }

      if (assertion.status === "failed") {
        numFailedTests += 1;
        continue;
      }

      if (assertion.status === "todo") {
        numTodoTests += 1;
        continue;
      }

      numPendingTests += 1;
    }
  }

  let numPassedTestSuites = 0;
  let numFailedTestSuites = 0;
  let numPendingTestSuites = 0;

  for (const suite of testResults) {
    if (suite.status === "passed") {
      numPassedTestSuites += 1;
      continue;
    }

    if (suite.status === "failed") {
      numFailedTestSuites += 1;
      continue;
    }

    numPendingTestSuites += 1;
  }

  const status = computeSerializedStatus(session, ttlHours);

  return {
    numFailedTests,
    numFailedTestSuites,
    numPassedTests,
    numPassedTestSuites,
    numPendingTests,
    numPendingTestSuites,
    numTodoTests,
    numTotalTests:
      numPassedTests + numFailedTests + numPendingTests + numTodoTests,
    numTotalTestSuites: testResults.length,
    startTime: Date.parse(session.startedAt),
    status,
    success: status === "PASSED",
    testResults,
  };
}

function computeSerializedStatus(
  session: ConformanceSession,
  ttlHours: number,
): SerializedStatus {
  if (session.status !== "OPEN") {
    return session.status;
  }

  const startedAt = Date.parse(session.startedAt);
  if (Number.isNaN(startedAt)) {
    return session.status;
  }

  const ageMs = Date.now() - startedAt;
  if (ageMs > ttlHours * 60 * 60 * 1000) {
    return "INCOMPLETE";
  }

  return session.status;
}

function toSuite(name: string, checks: ConformanceCheck[]): VitestTestSuite {
  const orderedChecks = [...checks].sort(
    (left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp),
  );

  const assertionResults: VitestAssertionResult[] = orderedChecks.map(
    (check) => ({
      ancestorTitles: [name],
      duration: 0,
      failureMessages:
        check.result === "FAIL"
          ? [check.errorMessage ?? `Requirement ${check.requirementId} failed`]
          : [],
      fullName: `${name} ${check.requirementId} ${check.description}`,
      location: {
        column: 0,
        line: 0,
      },
      meta: {
        httpStatus: check.httpStatus,
        requirementId: check.requirementId,
      },
      status:
        check.result === "PASS"
          ? "passed"
          : check.result === "FAIL"
            ? "failed"
            : "pending",
      title: check.description,
    }),
  );

  return {
    assertionResults,
    endTime: Date.parse(
      orderedChecks.at(-1)?.timestamp ?? "1970-01-01T00:00:00.000Z",
    ),
    message: "",
    name,
    startTime: Date.parse(
      orderedChecks[0]?.timestamp ?? "1970-01-01T00:00:00.000Z",
    ),
    status: toSuiteStatus(assertionResults),
  };
}

function toSuiteStatus(
  assertions: VitestAssertionResult[],
): "failed" | "passed" | "pending" {
  let hasPending = false;

  for (const assertion of assertions) {
    if (assertion.status === "failed") {
      return "failed";
    }

    if (assertion.status === "pending" || assertion.status === "todo") {
      hasPending = true;
    }
  }

  return hasPending ? "pending" : "passed";
}
