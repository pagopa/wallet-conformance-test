import type { DatabaseSync } from "node:sqlite";
import type { Reporter } from "vitest/reporters";

import { randomUUID } from "node:crypto";
import { basename } from "node:path";
import { TestResult } from "vitest/node.js";

import type { ConformanceCheck } from "@/report/types";
import type { Logger } from "@/types";

import { createLogger, loadConfigWithHierarchy } from "@/logic";
import { openDb, resolveDbPath } from "@/report/db";
import {
  appendCheck,
  closeSession,
  createSession,
} from "@/report/session-store";

type CheckResult = ConformanceCheck["result"];

type ReporterTestCase = Parameters<
  NonNullable<Reporter["onTestCaseResult"]>
>[0];

type ReporterTestEntity = ReporterTestCase["parent"];

type SessionStatus = "FAILED" | "INCOMPLETE" | "PASSED";
type TestType = "issuance" | "presentation";

// Example IT Wallet Test Matrix IDs -> CI_002 or RPR-001
const REQUIREMENT_ID_PATTERN = /^([A-Z]+[-_]\d+\w*)\s*:/;
const DEFAULT_ENTITY_NAME = "-";
// Suite titles are declared as `[<suite name>] <human readable description>`
const SUITE_TAG_PATTERN = /^\[([^\]]+)\]/;

export class ConformanceReporter implements Reporter {
  private checkResults: CheckResult[] = [];
  private db: DatabaseSync | undefined;
  private log: Logger | undefined;
  private sessionId: string | undefined;
  private readonly testType: TestType;

  constructor(testType: TestType) {
    this.testType = testType;
  }

  onTestCaseResult(testCase: ReporterTestCase): void {
    // Tests that never ran cannot log their own outcome, so the reporter
    // writes their result line to the log file on their behalf.
    if (testCase.result().state === "skipped") {
      this.logNotExecuted(testCase);
    }

    if (!this.db || !this.sessionId) {
      return;
    }

    const title = testCase.name;
    const result = this.mapResult(testCase.result().state);
    const check: ConformanceCheck = {
      description: this.parseTestCaseName(title),
      phase: this.testType,
      requirementId: this.parseRequirementId(title),
      result,
      timestamp: new Date().toISOString(),
    };

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
    this.log = this.createFileLogger();
    this.db = openDb(resolveDbPath());
    this.sessionId = randomUUID();
    this.checkResults = [];

    createSession(this.db, {
      entityName: DEFAULT_ENTITY_NAME,
      id: this.sessionId,
      phase: this.testType,
      startedAt: new Date().toISOString(),
      status: "OPEN",
    });
  }

  /**
   * Builds a logger that writes to the configured log file only, so the
   * reporter can append result lines without duplicating console output.
   *
   * @returns A file-only `Logger`, or `undefined` when logging is unavailable.
   */
  private createFileLogger(): Logger | undefined {
    try {
      const { logging } = loadConfigWithHierarchy();

      if (!logging.log_file) {
        return undefined;
      }

      const log = createLogger();
      log.setLogOptions({
        fileFormat: logging.log_file_format,
        level: logging.log_level,
        path: logging.log_file,
      });

      return log;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn(`Conformance reporter: file logging disabled (${message})`);
      return undefined;
    }
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

  /**
   * Walks the suite chain looking for the error that prevented the test from
   * running (typically a `beforeAll` failure).
   *
   * @param testCase The skipped test case reported by Vitest.
   * @returns The first suite error message found, if any.
   */
  private findSuiteError(testCase: ReporterTestCase): string | undefined {
    let entity: ReporterTestEntity = testCase.parent;

    for (;;) {
      const error = entity.errors()[0];

      if (error?.message) {
        return error.message;
      }

      if (entity.type === "module") {
        return undefined;
      }

      entity = entity.parent;
    }
  }

  /**
   * Appends a result line for a test that never executed, tagged exactly like
   * the line the test itself would have written (e.g. `[Suite - profile|CI_010]`).
   *
   * @param testCase The skipped test case reported by Vitest.
   */
  private logNotExecuted(testCase: ReporterTestCase): void {
    if (!this.log) {
      return;
    }

    const title = testCase.name;
    const requirementId = REQUIREMENT_ID_PATTERN.exec(title)?.[1];
    const suiteTag = this.resolveSuiteTag(testCase);
    const tag = requirementId ? `${suiteTag}|${requirementId}` : suiteTag;

    this.log
      .withTag(tag)
      .testSkipped(
        this.parseTestCaseName(title),
        this.resolveSkipReason(testCase),
      );
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
    return name.replace(REQUIREMENT_ID_PATTERN, "").trim();
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

  /**
   * Explains why a test did not run: an explicit `ctx.skip(note)`, a `skip` /
   * `todo` option, or a failure in the enclosing suite setup.
   *
   * @param testCase The skipped test case reported by Vitest.
   * @returns A short human-readable reason.
   */
  private resolveSkipReason(testCase: ReporterTestCase): string {
    const result = testCase.result();

    if (result.state === "skipped" && result.note) {
      return result.note;
    }

    const { mode } = testCase.options;
    if (mode === "skip" || mode === "todo") {
      return `skipped by test options: ${mode}`;
    }

    const suiteError = this.findSuiteError(testCase);

    return suiteError ? `suite setup failed: ${suiteError}` : "not reached";
  }

  /**
   * Resolves the log tag of the suite owning the test, so that reporter lines
   * are tagged like the ones written by the orchestrator logger.
   *
   * @param testCase The test case reported by Vitest.
   * @returns The suite tag, falling back to the spec file name.
   */
  private resolveSuiteTag(testCase: ReporterTestCase): string {
    let entity: ReporterTestEntity = testCase.parent;

    while (entity.type === "suite") {
      const suiteTag = SUITE_TAG_PATTERN.exec(entity.name)?.[1];

      if (suiteTag) {
        return suiteTag;
      }

      entity = entity.parent;
    }

    return basename(entity.moduleId);
  }
}
