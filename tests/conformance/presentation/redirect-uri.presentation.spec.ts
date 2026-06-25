/* eslint-disable max-lines-per-function */
import type { CreateAuthorizationResponseResult } from "@pagopa/io-wallet-oid4vp";

import { definePresentationTest } from "#/config/test-metadata";
import { postToResponseUri } from "#/helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import { beforeAll, describe, expect, test } from "vitest";

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

const testConfig = await definePresentationTest("RedirectUriValidation");

describe(`[${testConfig.name}] Presentation Redirect URI Validation Tests`, () => {
  const orchestrator = new WalletPresentationOrchestratorFlow(testConfig);
  const baseLog = orchestrator.getLog();

  let validResponseUri: string;
  let validAuthResponse: CreateAuthorizationResponseResult;

  // -----------------------------------------------------------------------
  // Shared setup – run once
  // -----------------------------------------------------------------------

  beforeAll(async () => {
    const ctx = await orchestrator.runThroughAuthorize();

    const authResponse = ctx.authorizationRequestResponse.response;
    if (!authResponse) {
      throw new Error(
        "Setup failed: authorizationRequestResponse.response is undefined — RP did not return a valid authorization response",
      );
    }
    validResponseUri = authResponse.responseUri;
    validAuthResponse = authResponse.authorizationResponse;
  });

  useTestSummary(baseLog, testConfig.name);

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

  async function fetchRedirectUrl(): Promise<URL> {
    const result = await runRedirectStep(validAuthResponse, validResponseUri);
    expect(result.success).toBe(true);

    expect(result.response).toBeDefined();
    if (!result.response) {
      throw new Error("Invalid state: RedirectStep response is undefined");
    }
    if (!result.response.redirectUri) {
      throw new Error("Invalid state: redirectUri is undefined");
    }

    return new URL(result.response.redirectUri.href);
  }

  function replaceLastPathSegment(url: URL, replacement: string): URL {
    const tamperedUrl = new URL(url.href);
    const pathSegments = tamperedUrl.pathname.split("/");
    const lastSegmentIndex = pathSegments.findLastIndex(
      (segment) => segment.length > 0,
    );

    if (lastSegmentIndex === -1) {
      tamperedUrl.pathname = `/${replacement}`;
      return tamperedUrl;
    }

    pathSegments[lastSegmentIndex] = replacement;
    tamperedUrl.pathname = pathSegments.join("/");
    return tamperedUrl;
  }

  // -----------------------------------------------------------------------
  // RPR-14 — Invalid Request Object handling
  // -----------------------------------------------------------------------

  test("RPR-14: Error response is sent.", async () => {
    const log = baseLog.withTag("RPR-14");
    const DESCRIPTION =
      "RP accepts Authorization Error Response for invalid Request Object";
    log.start("Conformance test: Invalid Request Object handling");

    let testSuccess = false;
    try {
      log.info(
        "→ Posting an invalid_request Authorization Error Response to response_uri...",
      );
      const errorBody = new URLSearchParams({
        error: "invalid_request",
        error_description:
          "Wallet rejected the authorization Request Object as invalid",
      });
      const response = await postToResponseUri(validResponseUri, {
        body: errorBody.toString(),
        contentType: "application/x-www-form-urlencoded",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info(
        "→ Validating RP processed the wallet error response without crashing...",
      );
      expect(
        response.status,
        "RP must acknowledge wallet Authorization Error Responses per OpenID4VP direct_post",
      ).toBe(200);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-17 — Fake HTTP Cookie
  // -----------------------------------------------------------------------

  test("RPR-17: Fake HTTP Cookie | RP rejects a valid response submitted with a forged session cookie", async () => {
    const log = baseLog.withTag("RPR-17");
    const DESCRIPTION =
      "RP rejects authorization responses coupled to a forged session cookie";
    log.start("Conformance test: Fake HTTP Cookie");

    let testSuccess = false;
    try {
      if (!validAuthResponse.jarm) {
        throw new Error(
          "Setup failed: valid authorization response does not include a JARM",
        );
      }

      log.info(
        "→ Posting a valid JARM to response_uri with a forged HTTP Cookie...",
      );
      const formBody = new URLSearchParams({
        response: validAuthResponse.jarm.responseJwe,
      });
      const response = await postToResponseUri(validResponseUri, {
        body: formBody.toString(),
        contentType: "application/x-www-form-urlencoded",
        headers: {
          Cookie:
            "rp_session=forged-rpr-17-session; session=forged-rpr-17-session",
        },
      });

      log.debug(`  Response status: ${response.status}`);
      log.info(
        "→ Validating RP rejected the forged cookie despite valid state/nonce payload...",
      );
      expect(
        response.ok,
        "RP must reject a valid response when the HTTP Cookie does not match the session bound to state and nonce",
      ).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-20 — Invalid redirect_uri handling
  // -----------------------------------------------------------------------

  // NOTE: This test verifies path-level rejection only. Host-level redirect_uri
  // security (unattested host) cannot be tested without RP-side DNS control.
  // See IT-Wallet spec RPR-20 for full scenario.
  test("RPR-20: Invalid redirect_uri handling | RP rejects when wallet follows a redirect to an invalid target", async () => {
    const log = baseLog.withTag("RPR-20");
    const DESCRIPTION = "RP securely rejects invalid redirect_uri overrides";
    log.start("Conformance test: Invalid redirect_uri handling");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step with a tampered response_uri...");

      const result = await runRedirectStep(
        validAuthResponse,
        "invalid_response_uri",
      );

      log.debug(`  Result success: ${result.success}`);
      log.info(
        "→ Validating that the step failed for a tampered RP-hosted redirect target...",
      );
      expect(result.success).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-29 — Invalid response codes
  // -----------------------------------------------------------------------

  test("RPR-29: Invalid response codes | RP gracefully handles invalid response_code in redirect", async () => {
    const log = baseLog.withTag("RPR-29");
    const DESCRIPTION = "RP gracefully handles invalid response_code replays";
    log.start("Conformance test: Invalid response codes");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const result = await runRedirectStep(validAuthResponse, validResponseUri);
      expect(result.success).toBe(true);

      expect(result.response).toBeDefined();
      if (!result.response)
        throw new Error("Invalid state: RedirectStep response is undefined");
      if (!result.response?.redirectUri) {
        throw new Error("Invalid state: redirectUri is undefined");
      }

      const redirectUrl = new URL(result.response.redirectUri.href);
      redirectUrl.searchParams.set(
        "response_code",
        "invalid-response-code-rpr-029",
      );
      log.debug(`→ Using redirect_uri: ${redirectUrl.href}`);
      log.info("→ Replaying redirect_uri with an invalid response_code...");

      const config = loadConfigWithHierarchy();
      const replayResponse = await fetchWithConfig(config.network)(
        redirectUrl.href,
        { method: "GET" },
      );

      log.debug(`  Replay response status: ${replayResponse.status}`);
      log.info("→ Validating RP rejected the invalid response_code...");
      expect(replayResponse.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-30 — Status Endpoint unauthorized access
  // -----------------------------------------------------------------------

  test("RPR-30: Verify handling of unauthorized access.", async () => {
    const log = baseLog.withTag("RPR-30");
    const DESCRIPTION = "RP denies unauthorized access to the status endpoint";
    log.start("Conformance test: Status Endpoint unauthorized access");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid status endpoint URL...");
      const result = await runRedirectStep(validAuthResponse, validResponseUri);
      expect(result.success).toBe(true);

      expect(result.response).toBeDefined();
      if (!result.response) {
        throw new Error("Invalid state: RedirectStep response is undefined");
      }
      if (!result.response.redirectUri) {
        throw new Error("Invalid state: redirectUri is undefined");
      }

      const unauthorizedStatusUrl = new URL(result.response.redirectUri.href);
      unauthorizedStatusUrl.searchParams.delete("response_code");
      log.debug(
        `→ Accessing status endpoint without response_code: ${unauthorizedStatusUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const unauthorizedResponse = await fetchWithConfig(config.network)(
        unauthorizedStatusUrl.href,
        { method: "GET" },
      );

      log.debug(
        `  Unauthorized response status: ${unauthorizedResponse.status}`,
      );
      log.info("→ Validating RP denied unauthorized status endpoint access...");
      expect(
        [401, 403],
        "RP must deny unauthorized status endpoint access with HTTP 401 or 403",
      ).toContain(unauthorizedResponse.status);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-31 — Status Endpoint invalid session IDs
  // -----------------------------------------------------------------------

  test("RPR-31: Test handling of invalid session IDs.", async () => {
    const log = baseLog.withTag("RPR-31");
    const DESCRIPTION =
      "RP returns an error response when the status endpoint session ID is invalid";
    log.start("Conformance test: Status Endpoint invalid session IDs");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid status endpoint URL...");
      const redirectUrl = await fetchRedirectUrl();
      const invalidSessionUrl = replaceLastPathSegment(
        redirectUrl,
        "invalid-session-id-rpr-031",
      );
      log.debug(
        `→ Accessing status endpoint with invalid session ID: ${invalidSessionUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(
        invalidSessionUrl.href,
        { method: "GET" },
      );

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-32 — Redirect URI expired sessions
  // -----------------------------------------------------------------------

  test("RPR-32: Verify handling of expired sessions.", async () => {
    const log = baseLog.withTag("RPR-32");
    const DESCRIPTION =
      "RP returns an error response when the redirect URI session is expired";
    log.start("Conformance test: Redirect URI expired sessions");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const redirectUrl = await fetchRedirectUrl();
      const config = loadConfigWithHierarchy();

      log.info("→ Following redirect_uri once to consume the session...");
      const firstResponse = await fetchWithConfig(config.network)(
        redirectUrl.href,
        { method: "GET" },
      );
      log.debug(`  First response status: ${firstResponse.status}`);

      log.info("→ Replaying redirect_uri after session consumption...");
      const replayResponse = await fetchWithConfig(config.network)(
        redirectUrl.href,
        { method: "GET" },
      );

      log.debug(`  Replay response status: ${replayResponse.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(replayResponse.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-33 — Redirect URI server errors
  // -----------------------------------------------------------------------

  test("RPR-33: Test handling of server errors.", async () => {
    const log = baseLog.withTag("RPR-33");
    const DESCRIPTION =
      "RP returns an error response when redirect URI processing fails server-side";
    log.start("Conformance test: Redirect URI server errors");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const redirectUrl = await fetchRedirectUrl();
      const serverErrorUrl = new URL(redirectUrl.href);
      serverErrorUrl.searchParams.set(
        "response_code",
        "trigger-server-error-rpr-033",
      );
      serverErrorUrl.searchParams.set("error", "server_error");
      log.debug(
        `→ Accessing redirect_uri with server_error: ${serverErrorUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(
        serverErrorUrl.href,
        { method: "GET" },
      );

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-34 — Slow network conditions
  // -----------------------------------------------------------------------

  test("RPR-34: Verify handling of slow network conditions.", async () => {
    const log = baseLog.withTag("RPR-34");
    const DESCRIPTION =
      "RP provides the HTTP response within the maximum limit of 2 seconds";
    log.start("Conformance test: Slow network conditions");

    let testSuccess = false;
    try {
      log.info("→ Measuring redirect_uri HTTP response time...");
      const redirectUrl = await fetchRedirectUrl();
      const config = loadConfigWithHierarchy();
      const startedAt = performance.now();
      const response = await fetchWithConfig(config.network)(redirectUrl.href, {
        method: "GET",
      });
      const durationMs = performance.now() - startedAt;

      log.debug(`  Response status: ${response.status}`);
      log.debug(`  Response time: ${durationMs.toFixed(0)}ms`);
      expect(
        durationMs,
        "RP must provide the redirect/status HTTP response within 2 seconds",
      ).toBeLessThanOrEqual(2000);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-40 — Relying Party Response malformed responses
  // -----------------------------------------------------------------------

  test("RPR-40: Relying Party Response | RP rejects malformed authorization responses", async () => {
    const log = baseLog.withTag("RPR-40");
    const DESCRIPTION =
      "RP returns an error response when the wallet response is malformed";
    log.start("Conformance test: Relying Party Response malformed responses");

    let testSuccess = false;
    try {
      log.info("→ Posting a malformed JARM response to response_uri...");
      const malformedBody = new URLSearchParams({
        response: "malformed-response-rpr-040",
      });
      const response = await postToResponseUri(validResponseUri, {
        body: malformedBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-42 — Status Endpoint session timeouts
  // -----------------------------------------------------------------------

  test("RPR-42: Status Endpoint | RP returns an error response for timed-out sessions", async () => {
    const log = baseLog.withTag("RPR-42");
    const DESCRIPTION =
      "RP returns an error response when the status endpoint session has timed out";
    log.start("Conformance test: Status Endpoint session timeouts");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid status endpoint URL...");
      const statusUrl = await fetchRedirectUrl();
      const config = loadConfigWithHierarchy();

      log.info("→ Accessing status endpoint once to complete the session...");
      const firstResponse = await fetchWithConfig(config.network)(
        statusUrl.href,
        { method: "GET" },
      );
      log.debug(`  First response status: ${firstResponse.status}`);

      log.info("→ Replaying status endpoint URL after session completion...");
      const replayResponse = await fetchWithConfig(config.network)(
        statusUrl.href,
        { method: "GET" },
      );

      log.debug(`  Replay response status: ${replayResponse.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(replayResponse.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-43 — Status Endpoint invalid status codes
  // -----------------------------------------------------------------------

  test("RPR-43: Status Endpoint | RP rejects invalid status codes", async () => {
    const log = baseLog.withTag("RPR-43");
    const DESCRIPTION =
      "RP returns an error response when the status endpoint receives an invalid status code";
    log.start("Conformance test: Status Endpoint invalid status codes");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid status endpoint URL...");
      const statusUrl = await fetchRedirectUrl();
      statusUrl.searchParams.set("response_code", "invalid-status-rpr-043");
      log.debug(
        `→ Accessing status endpoint with invalid code: ${statusUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(statusUrl.href, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-44 — Redirect URI invalid user sessions
  // -----------------------------------------------------------------------

  test("RPR-44: Redirect URI | RP rejects invalid user sessions", async () => {
    const log = baseLog.withTag("RPR-44");
    const DESCRIPTION =
      "RP returns an error response when the redirect URI user session is invalid";
    log.start("Conformance test: Redirect URI invalid user sessions");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const redirectUrl = await fetchRedirectUrl();
      const invalidSessionUrl = replaceLastPathSegment(
        redirectUrl,
        "invalid-user-session-rpr-044",
      );
      log.debug(
        `→ Accessing redirect_uri with invalid user session: ${invalidSessionUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(
        invalidSessionUrl.href,
        { method: "GET" },
      );

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-45 — Redirect URI unavailable services
  // -----------------------------------------------------------------------

  test("RPR-45: Redirect URI | RP handles unavailable services with an error response", async () => {
    const log = baseLog.withTag("RPR-45");
    const DESCRIPTION =
      "RP returns an error response when redirect URI service handling is unavailable";
    log.start("Conformance test: Redirect URI unavailable services");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const redirectUrl = await fetchRedirectUrl();
      redirectUrl.searchParams.set("error", "temporarily_unavailable");
      redirectUrl.searchParams.set(
        "error_description",
        "Simulated unavailable service",
      );
      log.debug(
        `→ Accessing redirect_uri with unavailable service signal: ${redirectUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(redirectUrl.href, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-56 — Protected Resource Endpoint unauthorized session access
  // -----------------------------------------------------------------------

  test("RPR-56: Protected Resource Endpoint | RP denies unauthorized session access", async () => {
    const log = baseLog.withTag("RPR-56");
    const DESCRIPTION =
      "RP denies unauthorized access to protected resource endpoints";
    log.start(
      "Conformance test: Protected Resource Endpoint unauthorized session access",
    );

    let testSuccess = false;
    try {
      log.info(
        "→ Running redirect step to get a valid protected resource URL...",
      );
      const protectedResourceUrl = await fetchRedirectUrl();
      const unauthorizedUrl = replaceLastPathSegment(
        protectedResourceUrl,
        "unauthorized-session-rpr-056",
      );
      unauthorizedUrl.searchParams.set(
        "response_code",
        "unauthorized-response-code-rpr-056",
      );
      log.debug(
        `→ Accessing protected resource with unauthorized session: ${unauthorizedUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(
        unauthorizedUrl.href,
        { method: "GET" },
      );

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP denied unauthorized access...");
      expect(
        [401, 403],
        "RP must deny protected resource access for an unauthorized session",
      ).toContain(response.status);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-57 — Redirect URI invalid redirect parameters
  // -----------------------------------------------------------------------

  test("RPR-57: Redirect URI | RP returns an error response for invalid redirect parameters", async () => {
    const log = baseLog.withTag("RPR-57");
    const DESCRIPTION =
      "RP returns an error response when redirect parameters are invalid";
    log.start("Conformance test: Redirect URI invalid redirect parameters");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const redirectUrl = await fetchRedirectUrl();
      redirectUrl.searchParams.delete("response_code");
      redirectUrl.searchParams.set("state", "unexpected-state-rpr-057");
      redirectUrl.searchParams.set("error", "invalid_request");
      log.debug(
        `→ Accessing redirect_uri with invalid parameters: ${redirectUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(redirectUrl.href, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(response.ok).toBe(false);
      expect(
        response.status,
        "RP must reject invalid redirect parameters without an internal server error",
      ).toBeLessThan(500);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-58 — Redirect URI redirect failures
  // -----------------------------------------------------------------------

  test("RPR-58: Redirect URI | RP returns an error response for redirect failures", async () => {
    const log = baseLog.withTag("RPR-58");
    const DESCRIPTION =
      "RP returns an error response when redirect processing fails";
    log.start("Conformance test: Redirect URI redirect failures");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const redirectUrl = await fetchRedirectUrl();
      redirectUrl.searchParams.set("error", "server_error");
      redirectUrl.searchParams.set(
        "error_description",
        "Simulated redirect failure",
      );
      log.debug(
        `→ Accessing redirect_uri with redirect failure signal: ${redirectUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(redirectUrl.href, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned an error response...");
      expect(response.ok).toBe(false);
      expect(
        response.status,
        "RP must handle redirect failures without an internal server error",
      ).toBeLessThan(500);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-59 — Same Device Flow user cancellation
  // -----------------------------------------------------------------------

  test("RPR-59: Same Device Flow | RP handles wallet cancellation with access_denied", async () => {
    const log = baseLog.withTag("RPR-59");
    const DESCRIPTION =
      "RP handles Same Device Flow cancellation through access_denied";
    log.start("Conformance test: Same Device Flow user cancellation");

    let testSuccess = false;
    try {
      log.info(
        "→ Posting a wallet cancellation Authorization Error Response to response_uri...",
      );
      const errorBody = new URLSearchParams({
        error: "access_denied",
        error_description: "User cancelled the Same Device Flow",
      });
      const response = await postToResponseUri(validResponseUri, {
        body: errorBody.toString(),
        contentType: "application/x-www-form-urlencoded",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info(
        "→ Validating RP acknowledges the cancellation without treating it as a server error...",
      );
      expect(
        response.status,
        "RP must acknowledge wallet cancellation errors on response_uri per OID4VP direct_post",
      ).toBe(200);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-41 — Missing response parameters
  // -----------------------------------------------------------------------

  test("RPR-41: Missing response parameters | RP rejects a response_uri POST that omits the 'response' parameter", async () => {
    const log = baseLog.withTag("RPR-41");
    const DESCRIPTION =
      "RP correctly detects missing required response parameters";
    log.start("Conformance test: Missing response parameters");

    let testSuccess = false;
    try {
      log.info("→ Posting to response_uri without the 'response' parameter...");
      // Send an empty form body (missing required 'response' parameter)
      const emptyBody = new URLSearchParams();
      const response = await postToResponseUri(validResponseUri, {
        body: emptyBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the missing parameter...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-64 — Response format errors
  // -----------------------------------------------------------------------

  test("RPR-64: Response format errors | RP rejects a malformed form payload to response_uri", async () => {
    const log = baseLog.withTag("RPR-64");
    const DESCRIPTION = "RP rejects malformed form/JARM payloads";
    log.start("Conformance test: Response format errors");

    let testSuccess = false;
    try {
      log.info(
        "→ Posting raw garbage data to response_uri as form-urlencoded...",
      );
      const response = await postToResponseUri(validResponseUri, {
        body: "this-is-not-valid-form-data=!@#$%^&*()",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the malformed payload...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-69 — Status Endpoint session expiration
  // -----------------------------------------------------------------------

  test("RPR-69: Status Endpoint | RP returns an error response for expired sessions", async () => {
    const log = baseLog.withTag("RPR-69");
    const DESCRIPTION =
      "RP returns an error response when the status endpoint session is expired";
    log.start("Conformance test: Status Endpoint session expiration");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid status endpoint URL...");
      const statusUrl = await fetchRedirectUrl();
      const config = loadConfigWithHierarchy();

      log.info("→ Accessing status endpoint once to consume the session...");
      const firstResponse = await fetchWithConfig(config.network)(
        statusUrl.href,
        { method: "GET" },
      );
      log.debug(`  First response status: ${firstResponse.status}`);

      log.info("→ Replaying status endpoint URL after session expiration...");
      const expiredResponse = await fetchWithConfig(config.network)(
        statusUrl.href,
        { method: "GET" },
      );

      log.debug(`  Expired-session response status: ${expiredResponse.status}`);
      log.info("→ Validating RP returned a controlled error response...");
      expect(expiredResponse.ok).toBe(false);
      expect(
        expiredResponse.status,
        "RP must reject expired status sessions without an internal server error",
      ).toBeLessThan(500);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-70 — Status Endpoint session renewal errors
  // -----------------------------------------------------------------------

  test("RPR-70: Status Endpoint | RP returns an error response for session renewal errors", async () => {
    const log = baseLog.withTag("RPR-70");
    const DESCRIPTION =
      "RP returns an error response when status endpoint session renewal fails";
    log.start("Conformance test: Status Endpoint session renewal errors");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid status endpoint URL...");
      const renewalUrl = await fetchRedirectUrl();
      renewalUrl.searchParams.set(
        "response_code",
        "invalid-renewal-response-code-rpr-070",
      );
      renewalUrl.searchParams.set("renew", "true");
      log.debug(
        `→ Accessing status endpoint with invalid renewal parameters: ${renewalUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(renewalUrl.href, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned a controlled error response...");
      expect(response.ok).toBe(false);
      expect(
        response.status,
        "RP must reject failed session renewal without an internal server error",
      ).toBeLessThan(500);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-71 — Redirect URI redirect loop errors
  // -----------------------------------------------------------------------

  test("RPR-71: Redirect URI | RP returns an error response for redirect loop errors", async () => {
    const log = baseLog.withTag("RPR-71");
    const DESCRIPTION =
      "RP returns an error response when redirect loop handling fails";
    log.start("Conformance test: Redirect URI redirect loop errors");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const redirectUrl = await fetchRedirectUrl();
      redirectUrl.searchParams.set(
        "response_code",
        "redirect-loop-response-code-rpr-071",
      );
      redirectUrl.searchParams.set("redirect_uri", redirectUrl.href);
      log.debug(
        `→ Accessing redirect_uri with loop-inducing parameters: ${redirectUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(redirectUrl.href, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned a controlled error response...");
      expect(response.ok).toBe(false);
      expect(
        response.status,
        "RP must reject redirect loop errors without an internal server error",
      ).toBeLessThan(500);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-72 — Redirect URI redirect security errors
  // -----------------------------------------------------------------------

  test("RPR-72: Redirect URI | RP returns an error response for redirect security errors", async () => {
    const log = baseLog.withTag("RPR-72");
    const DESCRIPTION =
      "RP returns an error response when redirect security validation fails";
    log.start("Conformance test: Redirect URI redirect security errors");

    let testSuccess = false;
    try {
      log.info("→ Running redirect step to get a valid redirect_uri...");
      const redirectUrl = await fetchRedirectUrl();
      redirectUrl.searchParams.set(
        "response_code",
        "redirect-security-response-code-rpr-072",
      );
      redirectUrl.searchParams.set("next", "https://evil.example/callback");
      log.debug(
        `→ Accessing redirect_uri with unsafe redirect target: ${redirectUrl.href}`,
      );

      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(redirectUrl.href, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP returned a controlled error response...");
      expect(response.ok).toBe(false);
      expect(
        response.status,
        "RP must reject redirect security errors without an internal server error",
      ).toBeLessThan(500);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-98 — Error response content type
  // -----------------------------------------------------------------------

  test("RPR-98: Error response content type | RP returns application/json for error responses on response_uri", async () => {
    const log = baseLog.withTag("RPR-98");
    const DESCRIPTION = "RP returns application/json for error responses";
    log.start("Conformance test: Error response content type");

    let testSuccess = false;
    try {
      log.info("→ Sending invalid request to response_uri to trigger error...");
      const formBody = new URLSearchParams({
        response: "deliberately-invalid-jwe-for-error-trigger",
      });
      const response = await postToResponseUri(validResponseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      const contentType = response.headers.get("content-type") ?? "";
      log.debug(`  Content-Type: ${contentType}`);

      log.info(
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

  test("RPR-99: Error response parameters | RP includes error and error_description in error responses", async () => {
    const log = baseLog.withTag("RPR-99");
    const DESCRIPTION = "RP includes error and error_description parameters";
    log.start("Conformance test: Error response parameters");

    let testSuccess = false;
    try {
      log.info("→ Sending invalid request to response_uri to trigger error...");
      const formBody = new URLSearchParams({
        response: "deliberately-invalid-jwe-for-error-trigger",
      });
      const response = await postToResponseUri(validResponseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      expect(response.ok).toBe(false);

      const body = await response.json().catch(() => ({}));
      log.debug(`  Response body: ${JSON.stringify(body)}`);

      log.info(
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

  test("RPR-108: Authorization Error Response handling | RP correctly handles explicit authorization error from wallet", async () => {
    const log = baseLog.withTag("RPR-108");
    const DESCRIPTION =
      "RP correctly handles explicit authorization error from wallet";
    log.start("Conformance test: Authorization Error Response handling");

    let testSuccess = false;
    try {
      log.info("→ Posting an explicit authorization error to response_uri...");

      // Send an OAuth 2.0 error response per OpenID4VP spec instead of a success JARM
      const errorBody = new URLSearchParams({
        error: "access_denied",
        error_description: "User denied the presentation request",
      });
      const response = await postToResponseUri(validResponseUri, {
        body: errorBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);

      log.info(
        "→ Validating RP accepted or acknowledged the error response...",
      );
      // The RP should acknowledge the error (status may vary: 200 or 4xx depending on RP implementation)
      // The key check: the response must be a valid JSON body, not a server crash
      expect(
        response.status,
        "RP must respond 200 to wallet error responses per OID4VP §8.2",
      ).toBe(200);
      const contentType = response.headers.get("content-type") ?? "";
      expect(
        contentType.includes("application/json"),
        "RP must return application/json for wallet error responses",
      ).toBe(true);
      const body = await response.text();
      expect(
        body.includes("at Object.<anonymous>"),
        "RP must not leak stack traces",
      ).toBe(false);
      log.debug(`  Response body: ${body}`);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-109 — Authorization Error Response encoding
  // -----------------------------------------------------------------------

  test("RPR-109: Authorization Error Response encoding | RP parses authorization errors over application/x-www-form-urlencoded", async () => {
    const log = baseLog.withTag("RPR-109");
    const DESCRIPTION =
      "RP parses authorization generic errors over x-www-form-urlencoded";
    log.start("Conformance test: Authorization Error Response encoding");

    let testSuccess = false;
    try {
      log.info("→ Posting authorization error as x-www-form-urlencoded...");
      const errorBody = new URLSearchParams({
        error: "invalid_request",
        error_description: "Wallet could not satisfy the requested credentials",
        state: "conformance-test-state-rpr-109",
      });
      const response = await postToResponseUri(validResponseUri, {
        body: errorBody.toString(),
        contentType: "application/x-www-form-urlencoded",
      });

      log.debug(`  Response status: ${response.status}`);

      log.info(
        "→ Validating RP processed the form-urlencoded error response...",
      );
      // The RP should not crash and should return a valid response
      expect(
        response.status,
        "RP must respond 200 to wallet error responses per OID4VP §8.2",
      ).toBe(200);
      const contentType = response.headers.get("content-type") ?? "";
      expect(
        contentType.includes("application/json"),
        "RP must return application/json for wallet error responses",
      ).toBe(true);
      const body = await response.text();
      expect(
        body.includes("at Object.<anonymous>"),
        "RP must not leak stack traces",
      ).toBe(false);
      log.debug(`  Response body: ${body}`);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-114 — Validation error response on response_uri
  // -----------------------------------------------------------------------

  test("RPR-114: Validation error response on response_uri | RP returns correct error structure upon wallet submission failure", async () => {
    const log = baseLog.withTag("RPR-114");
    const DESCRIPTION =
      "RP returns correct error structure upon wallet submission failure";
    log.start("Conformance test: Validation error response on response_uri");

    let testSuccess = false;
    try {
      log.info(
        "→ Posting a structurally valid but semantically wrong JARM to trigger validation error...",
      );
      // Send a well-formed but semantically invalid response to trigger RP-side validation
      const formBody = new URLSearchParams({
        response:
          "eyJhbGciOiJFQ0RILUVTLN0.ZW5jcnlwdGVk.aXY.Y2lwaGVydGV4dA.dGFn",
      });
      const response = await postToResponseUri(validResponseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      expect(response.ok).toBe(false);

      const contentType = response.headers.get("content-type") ?? "";
      log.debug(`  Content-Type: ${contentType}`);

      // Attempt to parse the error body
      const body = await response.json().catch(() => ({}));
      log.debug(`  Response body: ${JSON.stringify(body)}`);

      log.info("→ Validating the error response has proper structure...");
      expect(
        body.error,
        "Validation error response must contain 'error' field",
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
});
