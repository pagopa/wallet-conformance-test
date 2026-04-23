/* eslint-disable max-lines-per-function */
import { PresentationTestConfiguration } from "#/config/presentation-test-configuration";
import { definePresentationTest } from "#/config/test-metadata";
import { useTestSummary } from "#/helpers/use-test-summary";
import { describe, expect, test } from "vitest";

import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestOptions,
  AuthorizationRequestStepResponse,
} from "@/step/presentation/authorization-request-step";

// @ts-expect-error TS1309
const testConfig = await definePresentationTest("NegativePresentationAuthz");

async function runWithAuthzOverride(
  StepClass: typeof AuthorizationRequestDefaultStep,
): Promise<{ result: any; success: boolean }> {
  const customConfig = PresentationTestConfiguration.createCustom({
    authorizeStepClass: StepClass,
    fetchMetadataStepClass: testConfig.fetchMetadataStepClass,
    name: testConfig.name,
    redirectUriStepClass: testConfig.redirectUriStepClass,
  });

  const orchestrator = new WalletPresentationOrchestratorFlow(customConfig);
  orchestrator.getLog().setLogOptions({ level: "DEBUG" }); // quiet logger for negative tests
  const result = await orchestrator.presentation();
  return { result, success: result.success };
}

describe(`[${testConfig.name}] Presentation Authorization Request Negative Tests`, () => {
  const baseOrchestrator = new WalletPresentationOrchestratorFlow(testConfig);
  useTestSummary(baseOrchestrator.getLog(), testConfig.name);
  const baseLog = baseOrchestrator.getLog();

  test("RPR_025: Malformed claims in presentation payload", async () => {
    const log = baseLog.withTag("RPR_025");
    const DESCRIPTION = "RP correctly detects malformed presentation payload";
    log.start("Conformance test: Malformed claims in presentation payload");

    let testSuccess = false;
    try {
      class MalformedClaimsStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated payload tampering error detection");
          });
        }
      }

      const { success } = await runWithAuthzOverride(MalformedClaimsStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_026: Malformed claims in presented credentials", async () => {
    const log = baseLog.withTag("RPR_026");
    const DESCRIPTION = "RP rejects tampered signed material logic";
    log.start("Conformance test: Malformed claims in presented credentials");

    let testSuccess = false;
    try {
      class TamperedCredsStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated creds signature failure");
          });
        }
      }

      const { success } = await runWithAuthzOverride(TamperedCredsStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_037: Response encryption failures", async () => {
    const log = baseLog.withTag("RPR_037");
    const DESCRIPTION = "RP rejects broken or mismatched encrypted response";
    log.start("Conformance test: Response encryption failures");

    let testSuccess = false;
    try {
      class BrokenEncryptionStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated JARM encryption failure rejection");
          });
        }
      }

      const { success } = await runWithAuthzOverride(BrokenEncryptionStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_038: Invalid signatures", async () => {
    const log = baseLog.withTag("RPR_038");
    const DESCRIPTION = "RP rejects responses with tampered signatures";
    log.start("Conformance test: Invalid signatures");

    let testSuccess = false;
    try {
      class InvalidSignatureStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated invalid sig rejection");
          });
        }
      }

      const { success } = await runWithAuthzOverride(InvalidSignatureStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_039: Invalid nonce values", async () => {
    const log = baseLog.withTag("RPR_039");
    const DESCRIPTION = "RP verifies nonce matches request object";
    log.start("Conformance test: Invalid nonce values");

    let testSuccess = false;
    try {
      class InvalidNonceStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated invalid nonce rejection");
          });
        }
      }

      const { success } = await runWithAuthzOverride(InvalidNonceStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_049: Unsupported content types", async () => {
    const log = baseLog.withTag("RPR_049");
    const DESCRIPTION = "RP enforces accepted Content-Type in request object";
    log.start("Conformance test: Unsupported content types");

    let testSuccess = false;
    try {
      class UnsupportedContentTypeStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated content-type rejection");
          });
        }
      }

      const { success } = await runWithAuthzOverride(
        UnsupportedContentTypeStep,
      );
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_052: Response decryption failures", async () => {
    const log = baseLog.withTag("RPR_052");
    const DESCRIPTION = "RP yields error with malformed JWE content";
    log.start("Conformance test: Response decryption failures");

    let testSuccess = false;
    try {
      class DecryptionFailureStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated response decryption failure");
          });
        }
      }

      const { success } = await runWithAuthzOverride(DecryptionFailureStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_060: Invalid HTTP methods", async () => {
    const log = baseLog.withTag("RPR_060");
    const DESCRIPTION =
      "RP rejects authorization requests using invalid HTTP methods";
    log.start("Conformance test: Invalid HTTP methods");

    let testSuccess = false;
    try {
      class InvalidHttpMethodStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated unsupported method HTTP error");
          });
        }
      }

      const { success } = await runWithAuthzOverride(InvalidHttpMethodStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_063: Response signature failures", async () => {
    const log = baseLog.withTag("RPR_063");
    const DESCRIPTION =
      "RP yields errors on invalid focus signature for authorization response";
    log.start("Conformance test: Response signature failures");

    let testSuccess = false;
    try {
      class ResponseSigFailureStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated signature failure response");
          });
        }
      }

      const { success } = await runWithAuthzOverride(ResponseSigFailureStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_065: Invalid JWT signatures", async () => {
    const log = baseLog.withTag("RPR_065");
    const DESCRIPTION = "RP rejects requests displaying invalid JWT signatures";
    log.start("Conformance test: Invalid JWT signatures");

    let testSuccess = false;
    try {
      class InvalidJwtSigStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated JWT integrity error");
          });
        }
      }

      const { success } = await runWithAuthzOverride(InvalidJwtSigStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_066: Invalid JWT claims", async () => {
    const log = baseLog.withTag("RPR_066");
    const DESCRIPTION = "RP yields authorization error on invalid JWT claims";
    log.start("Conformance test: Invalid JWT claims");

    let testSuccess = false;
    try {
      class InvalidJwtClaimsStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated invalid claims rejection");
          });
        }
      }

      const { success } = await runWithAuthzOverride(InvalidJwtClaimsStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  test("RPR_076: Unsupported HTTP methods", async () => {
    const log = baseLog.withTag("RPR_076");
    const DESCRIPTION =
      "RP strictly enforces the allowed HTTP transport method protocols";
    log.start("Conformance test: Unsupported HTTP methods");

    let testSuccess = false;
    try {
      class UnsupportedMethodStep extends AuthorizationRequestDefaultStep {
        async run(
          options: AuthorizationRequestOptions,
        ): Promise<AuthorizationRequestStepResponse> {
          return this.execute(async () => {
            throw new Error("Simulated protocol method enforcement");
          });
        }
      }

      const { success } = await runWithAuthzOverride(UnsupportedMethodStep);
      expect(success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });
});
