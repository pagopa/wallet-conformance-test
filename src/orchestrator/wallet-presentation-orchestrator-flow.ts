import { PresentationTestConfiguration } from "tests/config/presentation-test-configuration";

import { createLogger } from "@/logic/logs";
import { loadConfig } from "@/logic/utils";
import { Config } from "@/types";

export class WalletPresentationOrchestratorFlow {
  private config: Config;
  private log = createLogger();

  private presentationConfig: PresentationTestConfiguration;

  constructor(presentationConfig: PresentationTestConfiguration) {
    this.presentationConfig = presentationConfig;
    this.log = this.log.withTag(this.presentationConfig.name);

    this.config = loadConfig("./config.ini");

    this.log.setLogOptions({
      format: this.config.logging.log_format,
      level: this.config.logging.log_level,
      path: this.config.logging.log_file,
    });

    this.log.info("Setting Up Wallet conformance Tests - Presentation Flow");
    this.log.info("Configuration Loaded from config.ini");

    this.log.info(
      "Configuration Loaded:\n",
      JSON.stringify({
        credentialsDir: this.config.wallet.credentials_storage_path,
        maxRetries: this.config.network.max_retries,
        timeout: `${this.config.network.timeout}s`,
        userAgent: this.config.network.user_agent,
      }),
    );
  }

  getLog(): typeof this.log {
    return this.log;
  }

  async presentation(): Promise<{}> {
    try {
      this.log.info("Starting Test Presentation Flow...");

      return {};
    } catch (e) {
      this.log.error("Error in Presentation Flow Tests!", e);
      throw e;
    }
  }
}
