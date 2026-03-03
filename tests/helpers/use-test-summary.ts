import { afterAll, afterEach } from "vitest";

import type { Logger } from "@/types";

/**
 * Registers `afterEach` / `afterAll` hooks that track per-test pass/fail state
 * and print a `testSummary` box at the end of the enclosing `describe` block.
 *
 * Call this once at the top of any `describe` callback — no boilerplate needed
 * in individual test specs.
 *
 * @example
 * describe("My Suite", () => {
 *   useTestSummary(log, "My Suite");
 *   // … tests …
 * });
 *
 * @param log       Logger instance used to render the summary box.
 * @param suiteName Human-readable name shown in the summary row.
 */
export function useTestSummary(log: Logger, suiteName: string): void {
  let passedCount = 0;
  let failedCount = 0;
  const suiteStartTime = Date.now();

  afterEach((ctx) => {
    if (ctx.task.result?.state === "pass") passedCount++;
    else failedCount++;
  });

  afterAll(() => {
    log.testSummary([
      {
        durationMs: Date.now() - suiteStartTime,
        failed: failedCount,
        name: suiteName,
        passed: passedCount,
      },
    ]);
  });
}
