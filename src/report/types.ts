export interface ConformanceCheck {
  description: string;
  errorMessage?: string;
  httpStatus?: number;
  phase: "ISSUANCE" | "PRESENTATION";
  requirementId: string;
  result: "FAIL" | "NOT_REACHED" | "PASS";
  step: ConformanceStep;
  timestamp: string;
}

export interface ConformanceSession {
  checks: ConformanceCheck[];
  closedAt?: string;
  id: string;
  sessionId: string;
  startedAt: string;
  status: "FAILED" | "INCOMPLETE" | "OPEN" | "PASSED";
}

export type ConformanceStep =
  | "AUTHORIZATION_CODE"
  | "AUTHORIZE"
  | "CREDENTIAL"
  | "NONCE"
  | "PAR"
  | "PRESENTATION_RESPONSE"
  | "TOKEN";

export interface VitestAssertionResult {
  ancestorTitles: string[];
  duration: number;
  failureMessages: string[];
  fullName: string;
  location: {
    column: number;
    line: number;
  };
  meta: {
    httpStatus?: number;
    requirementId: string;
  };
  status: "failed" | "passed" | "pending" | "todo";
  title: string;
}

export interface VitestJsonReport {
  numFailedTests: number;
  numFailedTestSuites: number;
  numPassedTests: number;
  numPassedTestSuites: number;
  numPendingTests: number;
  numPendingTestSuites: number;
  numTodoTests: number;
  numTotalTests: number;
  numTotalTestSuites: number;
  startTime: number;
  status: "FAILED" | "INCOMPLETE" | "OPEN" | "PASSED";
  success: boolean;
  testResults: VitestTestSuite[];
}

export interface VitestTestSuite {
  assertionResults: VitestAssertionResult[];
  endTime: number;
  message: string;
  name: string;
  startTime: number;
  status: string;
}
