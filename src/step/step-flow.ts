import { createLogger } from "@/logic";
import { Config } from "@/types";

export interface StepResponse {
  durationMs?: number;
  error?: Error;
  success: boolean;
}

export abstract class StepFlow {
  abstract tag: string;
  protected config: Config;

  protected log: ReturnType<typeof createLogger>;

  constructor(config: Config, logger: ReturnType<typeof createLogger>) {
    this.config = config;
    this.log = logger;
  }

  abstract run(...args: unknown[]): Promise<StepResponse>;

  protected async execute<T>(
    action: () => Promise<T>,
  ): Promise<StepResponse & { response?: T }> {
    const start = Date.now();
    try {
      const response = await action();
      const durationMs = Date.now() - start;
      this.log.withTag(this.tag).debug(`${this.tag} step succeeded ✅`);
      return { durationMs, response, success: true };
    } catch (error: unknown) {
      const durationMs = Date.now() - start;
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.log
        .withTag(this.tag)
        .debug(`${this.tag} step failed: ${errorMessage}`);
      return {
        durationMs,
        error: error instanceof Error ? error : new Error(String(error)),
        success: false,
      };
    }
  }
}
