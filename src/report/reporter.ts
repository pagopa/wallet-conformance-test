import type { DatabaseSync } from "node:sqlite";
import type { Reporter } from "vitest/reporters";

import { randomUUID } from "node:crypto";
import { TestResult } from "vitest/node.js";

import type { ConformanceCheck, ConformanceStep } from "@/report/types";

import { openDb, resolveDbPath } from "@/report/db";
import {
  appendCheck,
  closeSession,
  createSession,
} from "@/report/session-store";

type CheckResult = ConformanceCheck["result"];
interface KeywordStep {
  keyword: string;
  step: ConformanceStep;
}

type ReporterTestCase = Parameters<
  NonNullable<Reporter["onTestCaseResult"]>
>[0];

type SessionStatus = "FAILED" | "INCOMPLETE" | "PASSED";
type TestType = "issuance" | "presentation";

const REQUIREMENT_ID_PATTERN = /^([A-Z]+[-_]\d+\w*)\s*:/;

const STEP_KEYWORDS: readonly KeywordStep[] = [
  { keyword: "authorization code", step: "AUTHORIZATION_CODE" },
  { keyword: "authorize", step: "AUTHORIZE" },
  { keyword: "authorization", step: "AUTHORIZE" },
  { keyword: "presentation response", step: "PRESENTATION_RESPONSE" },
  { keyword: "response_uri", step: "PRESENTATION_RESPONSE" },
  { keyword: "response", step: "PRESENTATION_RESPONSE" },
  { keyword: "token", step: "TOKEN" },
  { keyword: "nonce", step: "NONCE" },
  { keyword: "par", step: "PAR" },
  { keyword: "credential", step: "CREDENTIAL" },
];

export class ConformanceReporter implements Reporter {
  private checkResults: CheckResult[] = [];
  private db: DatabaseSync | undefined;
  private sessionId: string | undefined;
  private readonly testType: TestType;

  constructor(testType: TestType = "issuance") {
    this.testType = testType;
  }

  onTestCaseResult(testCase: ReporterTestCase): void {
    if (!this.db || !this.sessionId) {
      return;
    }

    const title = testCase.name;
    const phase = this.resolvePhase();
    const result = this.mapResult(testCase.result().state);
    const check: ConformanceCheck = {
      description: this.parseTestCaseName(title),
      phase,
      requirementId: this.parseRequirementId(title),
      result,
      step: this.resolveStep(testCase),
      timestamp: new Date().toISOString(),
    };

    const meta = testCase.meta();
    const httpStatus = this.readHttpStatus(meta);

    if (httpStatus !== undefined) {
      check.httpStatus = httpStatus;
    }

    if (result === "FAIL") {
      check.errorMessage = this.extractFailureMessage(testCase);
    }

    appendCheck(this.db, this.sessionId, check);
    this.checkResults.push(result);
  }

  onTestRunEnd(): void {
    if (!this.db || !this.sessionId) {
      return;
    }

    const status = this.resolveFinalStatus(this.checkResults);
    closeSession(this.db, this.sessionId, status, new Date().toISOString());
    this.db.close();

    console.log(`Conformance session ID: ${this.sessionId}`);
  }

  onTestRunStart(): void {
    this.db = openDb(resolveDbPath());
    this.sessionId = randomUUID();
    this.checkResults = [];

    createSession(this.db, {
      id: this.sessionId,
      phase: this.testType === "presentation" ? "PRESENTATION" : "ISSUANCE",
      sessionId: this.sessionId,
      startedAt: new Date().toISOString(),
      status: "OPEN",
    });
  }

  private collectAncestorTitles(testCase: ReporterTestCase): string[] {
    const titles: string[] = [];
    let currentParent: unknown = testCase.parent;

    while (currentParent && typeof currentParent === "object") {
      const parentType = (currentParent as { type?: unknown }).type;
      if (parentType !== "suite") {
        break;
      }

      const name = (currentParent as { name?: unknown }).name;
      if (typeof name === "string") {
        titles.push(name);
      }

      currentParent = (currentParent as { parent?: unknown }).parent;
    }

    return titles;
  }

  private extractFailureMessage(testCase: ReporterTestCase): string {
    const firstError = testCase.result().errors?.[0];

    if (!firstError) {
      return "Test failed without error details";
    }

    if (typeof firstError === "string") {
      return firstError;
    }

    if (typeof firstError === "object" && "message" in firstError) {
      const message = (firstError as { message?: unknown }).message;
      if (typeof message === "string" && message.length > 0) {
        return message;
      }
    }

    return String(firstError);
  }

  private mapResult(state: TestResult["state"]): CheckResult {
    if (state === "passed") {
      return "PASS";
    }

    if (state === "failed") {
      return "FAIL";
    }

    return "NOT_REACHED";
  }

  private parseRequirementId(title: string): string {
    const requirement = REQUIREMENT_ID_PATTERN.exec(title)?.[1];
    return requirement ?? title;
  }

  private parseTestCaseName(name: string): string {
    return name.replace(REQUIREMENT_ID_PATTERN, "");
  }

  private readHttpStatus(meta: unknown): number | undefined {
    if (!meta || typeof meta !== "object") {
      return undefined;
    }

    const value = (meta as { httpStatus?: unknown }).httpStatus;
    return typeof value === "number" ? value : undefined;
  }

  private resolveFinalStatus(results: readonly CheckResult[]): SessionStatus {
    if (results.includes("FAIL")) {
      return "FAILED";
    }

    if (results.includes("NOT_REACHED")) {
      return "INCOMPLETE";
    }

    return "PASSED";
  }

  private resolvePhase(): "ISSUANCE" | "PRESENTATION" {
    return this.testType === "presentation" ? "PRESENTATION" : "ISSUANCE";
  }

  private resolveStep(testCase: ReporterTestCase): ConformanceStep {
    const titles = this.collectAncestorTitles(testCase);

    for (const title of titles) {
      const lowerTitle = title.toLowerCase();

      for (const mapping of STEP_KEYWORDS) {
        if (lowerTitle.includes(mapping.keyword)) {
          return mapping.step;
        }
      }
    }

    return "CREDENTIAL";
  }
}
