import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { createLogger } from "@/logic";
import { Config } from "@/types";

export interface StepResponse {
  durationMs?: number;
  error?: Error;
  success: boolean;
}

export abstract class StepFlow {
  protected config: Config;
  protected ioWalletSdkConfig: IoWalletSdkConfig<ItWalletSpecsVersion>;

  protected log: ReturnType<typeof createLogger>;

  constructor(config: Config, logger: ReturnType<typeof createLogger>) {
    this.config = config;
    this.log = logger.withTag(this.tag());
    this.ioWalletSdkConfig = new IoWalletSdkConfig({
      itWalletSpecsVersion: this.config.wallet.wallet_version,
    });
  }

  abstract run(...args: unknown[]): Promise<StepResponse>;

  abstract tag(): string;

  protected async execute<T>(
    action: () => Promise<T>,
  ): Promise<StepResponse & { response?: T }> {
    const start = Date.now();
    try {
      const response = await action();
      const durationMs = Date.now() - start;
      this.log.debug(`step succeeded ✅`);
      return { durationMs, response, success: true };
    } catch (error: unknown) {
      const durationMs = Date.now() - start;
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.log.error(`step failed: ${errorMessage}`);
      return {
        durationMs,
        error: error instanceof Error ? error : new Error(String(error)),
        success: false,
      };
    }
  }
}

/**
 * Asserts that a step result indicates success.
 *
 * Throws with a descriptive message when `result.success` is `false`, so the
 * orchestrator `catch` block can record a partial response and return
 * `{ success: false }`.  Using this helper after every `.run()` call ensures
 * that no step failure can silently propagate to a `success: true` return.
 *
 * @param result   - The `StepResponse` (or any extension of it) to check.
 * @param stepName - Human-readable step name used in the error message.
 * @returns The same `result` object, narrowed to `success: true`, so callers
 *          can use it inline without an extra variable.
 */
export function assertStepSuccess<T extends StepResponse>(
  result: T,
  stepName: string,
): asserts result is T & { success: true } {
  if (!result.success) {
    const cause = result.error?.message ?? "unknown error";
    throw result.error ?? new Error(`${stepName} step failed: ${cause}`);
  }
}
