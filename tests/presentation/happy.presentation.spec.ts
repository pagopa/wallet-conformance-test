import { beforeAll, describe } from "vitest";

// Import test configuration - this will register all configurations
import "../test.config";

import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";

import { presentationRegistry } from "../config/test-registry";
import { HAPPY_FLOW_PRESENTATION_NAME } from "../test.config";

// Get the test configuration from the registry
// The configuration must be registered before running the tests
presentationRegistry.get(HAPPY_FLOW_PRESENTATION_NAME).forEach((testConfig) => {
  describe(`[${testConfig.name}] Credential Presentation Tests`, async () => {
    const orchestrator: WalletPresentationOrchestratorFlow =
      new WalletPresentationOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    beforeAll(async () => {
      ({} = await orchestrator.presentation());
    });
  });
});
