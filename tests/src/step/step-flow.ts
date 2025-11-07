import { createLogger } from "@/logic/logs";
import { Config } from "@/types/Config";

export type StepResult = {
  success: boolean;
  error?: Error;
};

export abstract class StepFlow {
  protected log: ReturnType<typeof createLogger>;
  protected config: Config;

  constructor(config: Config, logger: ReturnType<typeof createLogger>) {
    this.config = config;
    this.log = logger;
  }

  abstract tag: string;
  abstract run(...args: any[]): Promise<StepResult>;

  protected async execute<T>(
    action: () => Promise<T>,
  ): Promise<StepResult & { response?: T }> {
    try {
      const response = await action();
      this.log.withTag(this.tag).success(`${this.tag} step succeeded ✅`);
      return { success: true, response };
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.log
        .withTag(this.tag)
        .error(`${this.tag} step failed ❌: ${errorMessage}`);
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }
}
