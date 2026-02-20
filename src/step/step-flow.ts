import { createLogger } from "@/logic";
import { Config } from "@/types";

export interface StepResponse {
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
    try {
      const response = await action();
      this.log.withTag(this.tag).info(`${this.tag} step succeeded ✅`);
      return { response, success: true };
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.log
        .withTag(this.tag)
        .error(`${this.tag} step failed ❌: ${errorMessage}`);
      return {
        error: error instanceof Error ? error : new Error(String(error)),
        success: false,
      };
    }
  }
}
