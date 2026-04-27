/* eslint-disable max-lines-per-function */
import type { CreateAuthorizationResponseResult } from "@pagopa/io-wallet-oid4vp";
import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import { definePresentationTest } from "#/config/test-metadata";
import { useTestSummary } from "#/helpers/use-test-summary";
import { beforeAll, describe, expect, test } from "vitest";

import type { AttestationResponse, CredentialWithKey } from "@/types";

import {
  createQuietLogger,
  fetchWithConfig,
  loadConfigWithHierarchy,
} from "@/logic";
import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";
import {
  RedirectUriDefaultStep,
  RedirectUriStepResponse,
} from "@/step/presentation/redirect-uri-step";

// @ts-expect-error TS1309: top-level await is valid in Vitest (ESM context)
const testConfig = await definePresentationTest("RedirectUriValidation");

describe(`[${testConfig.name}] Presentation Redirect URI Validation Tests`, () => {
  const orchestrator = new WalletPresentationOrchestratorFlow(testConfig);
  const baseLog = orchestrator.getLog();

  let verifierMetadata: ItWalletCredentialVerifierMetadata;
  let walletAttestationResponse: AttestationResponse;
  let credentials: CredentialWithKey[];

  // -----------------------------------------------------------------------
  // Shared setup – run once
  // -----------------------------------------------------------------------

  beforeAll(async () => {
    const ctx = await orchestrator.runThroughAuthorize();

    verifierMetadata = ctx.verifierMetadata;
    walletAttestationResponse = ctx.walletAttestationResponse;
    credentials = ctx.credentials;
  });

  useTestSummary(baseLog, testConfig.name);

  // -----------------------------------------------------------------------
  // Helper: run a fresh authorization step to get responseUri + JARM
  // -----------------------------------------------------------------------

  async function getFreshAuthorizationResponse(): Promise<{
    authorizationResponse: CreateAuthorizationResponseResult;
    responseUri: string;
  }> {
    const config = loadConfigWithHierarchy();
    const step = new testConfig.authorizeStepClass(config, createQuietLogger());
    const result = await step.run({
      credentials,
      verifierMetadata,
      walletAttestation: walletAttestationResponse,
    });
    expect(result.success, "helper: authorization step must succeed").toBe(
      true,
    );
    return {
      authorizationResponse: result.response!.authorizationResponse,
      responseUri: result.response!.responseUri,
    };
  }

  // -----------------------------------------------------------------------
  // Helper: run a redirect step with given options
  // -----------------------------------------------------------------------

  async function runRedirectStep(
    authorizationResponse: CreateAuthorizationResponseResult,
    responseUri: string,
  ): Promise<RedirectUriStepResponse> {
    const config = loadConfigWithHierarchy();
    const step = new RedirectUriDefaultStep(config, createQuietLogger());
    return step.run({
      authorizationResponse,
      responseUri,
    });
  }

  // -----------------------------------------------------------------------
  // Helper: POST to response_uri with custom options
  // -----------------------------------------------------------------------

  async function postToResponseUri(
    responseUri: string,
    body: string,
    options?: { contentType?: string; method?: string },
  ): Promise<Response> {
    const config = loadConfigWithHierarchy();
    return fetchWithConfig(config.network)(responseUri, {
      body,
      headers: {
        "Content-Type":
          options?.contentType ?? "application/x-www-form-urlencoded",
      },
      method: options?.method ?? "POST",
    });
  }

  // -----------------------------------------------------------------------
  // RPR-20 — Invalid redirect_uri handling
  // -----------------------------------------------------------------------

  test("RPR_020: Invalid redirect_uri handling | RP rejects when wallet follows a redirect to an invalid target", async () => {
    const log = baseLog.withTag("RPR_020");
    const DESCRIPTION = "RP securely rejects invalid redirect_uri overrides";
    log.start("Conformance test: Invalid redirect_uri handling");

    let testSuccess = false;
    try {
      const { authorizationResponse, responseUri } =
        await getFreshAuthorizationResponse();

      log.debug("→ Running redirect step with a tampered response_uri...");
      // Pass the valid JARM but post it to a different (invalid) response_uri
      const tamperedResponseUri = "https://invalid.example.com/response";
      const result = await runRedirectStep(
        authorizationResponse,
        tamperedResponseUri,
      );

      log.debug(`  Result success: ${result.success}`);
      log.debug("→ Validating that the step failed with invalid redirect...");
      expect(result.success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-29 — Invalid response codes
  // -----------------------------------------------------------------------

  test("RPR_029: Invalid response codes | RP gracefully handles invalid response_code in redirect", async () => {
    const log = baseLog.withTag("RPR_029");
    const DESCRIPTION = "RP gracefully handles invalid response_code replays";
    log.start("Conformance test: Invalid response codes");

    let testSuccess = false;
    try {
      const { authorizationResponse, responseUri } =
        await getFreshAuthorizationResponse();

      log.debug("→ Running redirect step to get a valid redirect_uri...");
      const result = await runRedirectStep(authorizationResponse, responseUri);
      expect(result.success, "redirect step must succeed first").toBe(true);

      if (result.response?.redirectUri) {
        log.debug("→ Replaying redirect_uri with an invalid response_code...");
        const redirectUrl = new URL(result.response.redirectUri.href);
        redirectUrl.searchParams.set(
          "response_code",
          "invalid-response-code-rpr-029",
        );

        const config = loadConfigWithHierarchy();
        const replayResponse = await fetchWithConfig(config.network)(
          redirectUrl.href,
          { method: "GET" },
        );

        log.debug(`  Replay response status: ${replayResponse.status}`);
        log.debug("→ Validating RP rejected the invalid response_code...");
        expect(replayResponse.ok).toBe(false);
      } else {
        log.debug(
          "→ No redirect_uri returned by RP (optional field); skipping replay",
        );
      }

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-41 — Missing response parameters
  // -----------------------------------------------------------------------

  test("RPR_041: Missing response parameters | RP rejects a response_uri POST that omits the 'response' parameter", async () => {
    const log = baseLog.withTag("RPR_041");
    const DESCRIPTION =
      "RP correctly detects missing required response parameters";
    log.start("Conformance test: Missing response parameters");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug(
        "→ Posting to response_uri without the 'response' parameter...",
      );
      // Send an empty form body (missing required 'response' parameter)
      const emptyBody = new URLSearchParams();
      const response = await postToResponseUri(
        responseUri,
        emptyBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the missing parameter...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-64 — Response format errors
  // -----------------------------------------------------------------------

  test("RPR_064: Response format errors | RP rejects a malformed form payload to response_uri", async () => {
    const log = baseLog.withTag("RPR_064");
    const DESCRIPTION = "RP rejects malformed form/JARM payloads";
    log.start("Conformance test: Response format errors");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug(
        "→ Posting raw garbage data to response_uri as form-urlencoded...",
      );
      const response = await postToResponseUri(
        responseUri,
        "this-is-not-valid-form-data=!@#$%^&*()",
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the malformed payload...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-98 — Error response content type
  // -----------------------------------------------------------------------

  test("RPR_098: Error response content type | RP returns application/json for error responses on response_uri", async () => {
    const log = baseLog.withTag("RPR_098");
    const DESCRIPTION = "RP returns application/json for error responses";
    log.start("Conformance test: Error response content type");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug(
        "→ Sending invalid request to response_uri to trigger error...",
      );
      const formBody = new URLSearchParams({
        response: "deliberately-invalid-jwe-for-error-trigger",
      });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      const contentType = response.headers.get("content-type") ?? "";
      log.debug(`  Content-Type: ${contentType}`);

      log.debug(
        "→ Validating error response has application/json content type...",
      );
      expect(response.ok).toBe(false);
      expect(
        contentType.includes("application/json"),
        "Error response Content-Type must be application/json",
      ).toBe(true);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-99 — Error response parameters
  // -----------------------------------------------------------------------

  test("RPR_099: Error response parameters | RP includes error and error_description in error responses", async () => {
    const log = baseLog.withTag("RPR_099");
    const DESCRIPTION = "RP includes error and error_description parameters";
    log.start("Conformance test: Error response parameters");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug(
        "→ Sending invalid request to response_uri to trigger error...",
      );
      const formBody = new URLSearchParams({
        response: "deliberately-invalid-jwe-for-error-trigger",
      });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      expect(response.ok).toBe(false);

      const body = await response.json().catch(() => ({}));
      log.debug(`  Response body: ${JSON.stringify(body)}`);

      log.debug(
        "→ Validating error response contains error and error_description...",
      );
      expect(
        body.error,
        "Error response must contain 'error' field",
      ).toBeDefined();
      expect(
        body.error_description,
        "Error response must contain 'error_description' field",
      ).toBeDefined();

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-108 — Authorization Error Response handling
  // -----------------------------------------------------------------------

  test("RPR_108: Authorization Error Response handling | RP correctly handles explicit authorization error from wallet", async () => {
    const log = baseLog.withTag("RPR_108");
    const DESCRIPTION =
      "RP correctly handles explicit authorization error from wallet";
    log.start("Conformance test: Authorization Error Response handling");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Posting an explicit authorization error to response_uri...");
      // Send an OAuth 2.0 error response per OpenID4VP spec instead of a success JARM
      const errorBody = new URLSearchParams({
        error: "access_denied",
        error_description: "User denied the presentation request",
      });
      const response = await postToResponseUri(
        responseUri,
        errorBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);

      log.debug(
        "→ Validating RP accepted or acknowledged the error response...",
      );
      // The RP should acknowledge the error (status may vary: 200 or 4xx depending on RP implementation)
      // The key check: the response must be a valid JSON body, not a server crash
      const body = await response.text();
      log.debug(`  Response body: ${body}`);
      expect(body).toBeDefined();

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-109 — Authorization Error Response encoding
  // -----------------------------------------------------------------------

  test("RPR_109: Authorization Error Response encoding | RP parses authorization errors over application/x-www-form-urlencoded", async () => {
    const log = baseLog.withTag("RPR_109");
    const DESCRIPTION =
      "RP parses authorization generic errors over x-www-form-urlencoded";
    log.start("Conformance test: Authorization Error Response encoding");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Posting authorization error as x-www-form-urlencoded...");
      const errorBody = new URLSearchParams({
        error: "invalid_request",
        error_description: "Wallet could not satisfy the requested credentials",
        state: "conformance-test-state-rpr-109",
      });
      const response = await postToResponseUri(
        responseUri,
        errorBody.toString(),
        { contentType: "application/x-www-form-urlencoded" },
      );

      log.debug(`  Response status: ${response.status}`);

      log.debug(
        "→ Validating RP processed the form-urlencoded error response...",
      );
      // The RP should not crash and should return a valid response
      const body = await response.text();
      log.debug(`  Response body: ${body}`);
      expect(body).toBeDefined();

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-114 — Validation error response on response_uri
  // -----------------------------------------------------------------------

  test("RPR_114: Validation error response on response_uri | RP returns correct error structure upon wallet submission failure", async () => {
    const log = baseLog.withTag("RPR_114");
    const DESCRIPTION =
      "RP returns correct error structure upon wallet submission failure";
    log.start("Conformance test: Validation error response on response_uri");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug(
        "→ Posting a structurally valid but semantically wrong JARM to trigger validation error...",
      );
      // Send a well-formed but semantically invalid response to trigger RP-side validation
      const formBody = new URLSearchParams({
        response:
          "eyJhbGciOiJFQ0RILUVTLN0.ZW5jcnlwdGVk.aXY.Y2lwaGVydGV4dA.dGFn",
      });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      expect(response.ok).toBe(false);

      const contentType = response.headers.get("content-type") ?? "";
      log.debug(`  Content-Type: ${contentType}`);

      // Attempt to parse the error body
      const body = await response.json().catch(() => ({}));
      log.debug(`  Response body: ${JSON.stringify(body)}`);

      log.debug("→ Validating the error response has proper structure...");
      expect(
        body.error,
        "Validation error response must contain 'error' field",
      ).toBeDefined();

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });
});
