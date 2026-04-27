/* eslint-disable max-lines-per-function */
import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import { definePresentationTest } from "#/config/test-metadata";
import { useTestSummary } from "#/helpers/use-test-summary";
import { createAuthorizationResponse } from "@pagopa/io-wallet-oid4vp";
import { CompactEncrypt, generateKeyPair } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

import type { AttestationResponse, CredentialWithKey } from "@/types";

import {
  createQuietLogger,
  fetchWithConfig,
  loadConfigWithHierarchy,
} from "@/logic";
import { getEncryptJweCallback } from "@/logic/jwt";
import { partialCallbacks } from "@/logic/utils";
import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestStepResponse,
} from "@/step/presentation/authorization-request-step";

// @ts-expect-error TS1309: top-level await is valid in Vitest (ESM context)
const testConfig = await definePresentationTest(
  "AuthorizationRequestValidation",
);

describe(`[${testConfig.name}] Presentation Authorization Request Validation`, () => {
  const orchestrator = new WalletPresentationOrchestratorFlow(testConfig);
  const baseLog = orchestrator.getLog();

  let verifierMetadata: ItWalletCredentialVerifierMetadata;
  let walletAttestationResponse: AttestationResponse;
  let credentials: CredentialWithKey[];
  let validResponseUri: string;
  let validJarmJwe: string;

  // -----------------------------------------------------------------------
  // Shared setup – run once
  // -----------------------------------------------------------------------

  beforeAll(async () => {
    const ctx = await orchestrator.runThroughAuthorize();

    verifierMetadata = ctx.verifierMetadata;
    walletAttestationResponse = ctx.walletAttestationResponse;
    credentials = ctx.credentials;

    // Run a fresh authorization step to capture a valid JARM + responseUri
    const authResult = await runAuthorizationStep(
      testConfig.authorizeStepClass,
    );
    expect(
      authResult.success,
      "beforeAll: authorization step must succeed",
    ).toBe(true);
    validResponseUri = authResult.response!.responseUri;
    validJarmJwe = authResult.response!.authorizationResponse.jarm.responseJwe;
  });

  useTestSummary(baseLog, testConfig.name);

  // -----------------------------------------------------------------------
  // Helper: run a fresh authorization step
  // -----------------------------------------------------------------------

  async function runAuthorizationStep(
    StepClass: typeof AuthorizationRequestDefaultStep,
    attestationOverride?: AttestationResponse,
  ): Promise<AuthorizationRequestStepResponse> {
    const config = loadConfigWithHierarchy();
    const step = new StepClass(config, createQuietLogger());
    return step.run({
      credentials,
      verifierMetadata,
      walletAttestation: attestationOverride ?? walletAttestationResponse,
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
  // Helper: get a fresh responseUri + JARM from a new authorization step
  // -----------------------------------------------------------------------

  async function getFreshAuthorizationResponse(): Promise<{
    jarmJwe: string;
    responseUri: string;
  }> {
    const result = await runAuthorizationStep(testConfig.authorizeStepClass);
    expect(result.success, "helper: authorization step must succeed").toBe(
      true,
    );
    return {
      jarmJwe: result.response!.authorizationResponse.jarm.responseJwe,
      responseUri: result.response!.responseUri,
    };
  }

  // -----------------------------------------------------------------------
  // RPR-25 — Malformed claims in presentation payload
  // -----------------------------------------------------------------------

  test("RPR_025: Malformed claims in presentation payload | RP rejects a response whose decrypted payload contains malformed claims", async () => {
    const log = baseLog.withTag("RPR_025");
    const DESCRIPTION = "RP correctly rejected response with malformed claims";
    log.start("Conformance test: Malformed claims in presentation payload");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Building JARM with malformed vp_token claims...");
      // Encrypt a malformed payload (invalid vp_token) with the RP's encryption key
      const encryptionKey = verifierMetadata.jwks.keys.find(
        (k) => k.use === "enc",
      );
      expect(encryptionKey, "RP must have an encryption key").toBeDefined();

      const malformedPayload = JSON.stringify({
        state: "invalid-state",
        vp_token: { invalid_credential_id: 12345 },
      });

      const encryptJwe = getEncryptJweCallback(encryptionKey!);
      const { jwe: tamperedJwe } = await encryptJwe(
        {
          alg:
            verifierMetadata.authorization_encrypted_response_alg || "ECDH-ES",
          enc:
            verifierMetadata.authorization_encrypted_response_enc ||
            "A128CBC-HS256",
          method: "jwk" as const,
          publicJwk: encryptionKey!,
        },
        malformedPayload,
      );

      log.debug("→ Posting tampered JARM to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
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
  // RPR-26 — Malformed claims in presented credentials
  // -----------------------------------------------------------------------

  test("RPR_026: Malformed claims in presented credentials | RP rejects a response whose credential claims are malformed", async () => {
    const log = baseLog.withTag("RPR_026");
    const DESCRIPTION =
      "RP correctly rejected response with malformed credential claims";
    log.start("Conformance test: Malformed claims in presented credentials");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Building JARM with malformed credential-level claims...");
      const encryptionKey = verifierMetadata.jwks.keys.find(
        (k) => k.use === "enc",
      );
      expect(encryptionKey).toBeDefined();

      // Send garbage credential data inside vp_token
      const malformedPayload = JSON.stringify({
        state: "some-state",
        vp_token: {
          credential_query_id: "not-a-valid-credential-jwt",
        },
      });

      const encryptJwe = getEncryptJweCallback(encryptionKey!);
      const { jwe: tamperedJwe } = await encryptJwe(
        {
          alg:
            verifierMetadata.authorization_encrypted_response_alg || "ECDH-ES",
          enc:
            verifierMetadata.authorization_encrypted_response_enc ||
            "A128CBC-HS256",
          method: "jwk" as const,
          publicJwk: encryptionKey!,
        },
        malformedPayload,
      );

      log.debug("→ Posting tampered JARM to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the malformed credentials...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-37 — Response encryption failures
  // -----------------------------------------------------------------------

  test("RPR_037: Response encryption failures | RP rejects a response encrypted with a wrong key", async () => {
    const log = baseLog.withTag("RPR_037");
    const DESCRIPTION =
      "RP correctly rejected response with wrong encryption key";
    log.start("Conformance test: Response encryption failures");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Generating a random EC key for wrong encryption...");
      const { publicKey } = await generateKeyPair("ECDH-ES");

      const plaintext = new TextEncoder().encode(
        JSON.stringify({ state: "bad", vp_token: {} }),
      );
      const wrongJwe = await new CompactEncrypt(plaintext)
        .setProtectedHeader({
          alg: "ECDH-ES",
          enc: "A128CBC-HS256",
          kid: "wrong-kid",
        })
        .encrypt(publicKey);

      log.debug("→ Posting wrongly-encrypted JARM to response_uri...");
      const formBody = new URLSearchParams({ response: wrongJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the response...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-38 — Invalid signatures
  // -----------------------------------------------------------------------

  test("RPR_038: Invalid signatures | RP rejects a response with tampered JARM integrity", async () => {
    const log = baseLog.withTag("RPR_038");
    const DESCRIPTION =
      "RP correctly rejected response with tampered signature";
    log.start("Conformance test: Invalid signatures");

    let testSuccess = false;
    try {
      const { jarmJwe, responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Tampering with the JARM JWE ciphertext...");
      // A JWE compact serialization has 5 base64url-encoded parts: header.ek.iv.ciphertext.tag
      const parts = jarmJwe.split(".");
      expect(parts.length).toBe(5);
      // Tamper with the authentication tag to invalidate integrity
      const tag = parts[4]!;
      const tamperedTag =
        tag.slice(0, -4) + (tag.endsWith("AAAA") ? "BBBB" : "AAAA");
      parts[4] = tamperedTag;
      const tamperedJwe = parts.join(".");

      log.debug("→ Posting tampered JARM to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the tampered content...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-39 — Invalid nonce values
  // -----------------------------------------------------------------------

  test("RPR_039: Invalid nonce values | RP rejects a response containing a nonce mismatch", async () => {
    const log = baseLog.withTag("RPR_039");
    const DESCRIPTION = "RP correctly rejected response with mismatched nonce";
    log.start("Conformance test: Invalid nonce values");

    let testSuccess = false;
    try {
      // Run a fresh auth step to get a valid request context
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);

      const { requestObject, responseUri } = authResult.response!;

      log.debug(
        "→ Building JARM with a wrong nonce via createAuthorizationResponse...",
      );

      const encryptionKey = verifierMetadata.jwks.keys.find(
        (k) => k.use === "enc",
      );
      expect(encryptionKey).toBeDefined();

      // Build a response with a deliberately wrong nonce by passing a tampered requestObject
      const tamperedRequestObject = {
        ...requestObject,
        nonce: "deliberately-wrong-nonce-value-for-rpr-039",
      };

      const metadata = {
        ...verifierMetadata,
        authorization_encrypted_response_alg:
          verifierMetadata.authorization_encrypted_response_alg || "ECDH-ES",
        authorization_encrypted_response_enc:
          verifierMetadata.authorization_encrypted_response_enc ||
          "A128CBC-HS256",
      };

      const tamperedAuthorizationResponse = await createAuthorizationResponse({
        authorization_encrypted_response_alg:
          metadata.authorization_encrypted_response_alg,
        authorization_encrypted_response_enc:
          metadata.authorization_encrypted_response_enc,
        callbacks: {
          ...partialCallbacks,
          encryptJwe: getEncryptJweCallback(encryptionKey!),
        },
        requestObject: tamperedRequestObject,
        rpJwks: { jwks: metadata.jwks },
        vp_token:
          authResult.response!.authorizationResponse
            .authorizationResponsePayload.vp_token,
      });

      log.debug("→ Posting JARM with wrong nonce to response_uri...");
      const formBody = new URLSearchParams({
        response: tamperedAuthorizationResponse.jarm.responseJwe,
      });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the nonce mismatch...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-49 — Unsupported content types
  // -----------------------------------------------------------------------

  test("RPR_049: Unsupported content types | RP rejects a response posted with an unsupported Content-Type", async () => {
    const log = baseLog.withTag("RPR_049");
    const DESCRIPTION =
      "RP correctly rejected response with unsupported Content-Type";
    log.start("Conformance test: Unsupported content types");

    let testSuccess = false;
    try {
      const { jarmJwe, responseUri } = await getFreshAuthorizationResponse();

      log.debug(
        "→ Posting JARM to response_uri with Content-Type: text/plain...",
      );
      const formBody = new URLSearchParams({ response: jarmJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
        { contentType: "text/plain" },
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the unsupported content type...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-52 — Response decryption failures
  // -----------------------------------------------------------------------

  test("RPR_052: Response decryption failures | RP rejects malformed JWE content", async () => {
    const log = baseLog.withTag("RPR_052");
    const DESCRIPTION = "RP correctly rejected response with malformed JWE";
    log.start("Conformance test: Response decryption failures");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Posting completely malformed JWE to response_uri...");
      const malformedJwe = "eyJhbGciOiJFQ0RILUVTLN0.bad.bad.bad.bad";
      const formBody = new URLSearchParams({ response: malformedJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the malformed JWE...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-60 — Invalid HTTP methods
  // -----------------------------------------------------------------------

  test("RPR_060: Invalid HTTP methods | RP rejects GET request to response_uri", async () => {
    const log = baseLog.withTag("RPR_060");
    const DESCRIPTION = "RP correctly rejected GET request to response_uri";
    log.start("Conformance test: Invalid HTTP methods (GET)");

    let testSuccess = false;
    try {
      const { jarmJwe, responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Sending GET request to response_uri...");
      const config = loadConfigWithHierarchy();
      const response = await fetchWithConfig(config.network)(responseUri, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the GET method...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-63 — Response signature failures
  // -----------------------------------------------------------------------

  test("RPR_063: Response signature failures | RP rejects a response whose JARM ciphertext has been corrupted", async () => {
    const log = baseLog.withTag("RPR_063");
    const DESCRIPTION =
      "RP correctly rejected response with corrupted ciphertext";
    log.start("Conformance test: Response signature failures");

    let testSuccess = false;
    try {
      const { jarmJwe, responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Corrupting the JARM JWE ciphertext segment...");
      const parts = jarmJwe.split(".");
      expect(parts.length).toBe(5);
      // Corrupt the ciphertext (4th part, index 3)
      const ciphertext = parts[3]!;
      parts[3] = ciphertext.slice(0, 4) + "TAMPERED" + ciphertext.slice(12);
      const corruptedJwe = parts.join(".");

      log.debug("→ Posting corrupted JARM to response_uri...");
      const formBody = new URLSearchParams({ response: corruptedJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the corrupted content...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-65 — Invalid JWT signatures
  // -----------------------------------------------------------------------

  test("RPR_065: Invalid JWT signatures | RP rejects a response whose JWT integrity is deliberately broken", async () => {
    const log = baseLog.withTag("RPR_065");
    const DESCRIPTION =
      "RP correctly rejected response with broken JWT integrity";
    log.start("Conformance test: Invalid JWT signatures");

    let testSuccess = false;
    try {
      const { jarmJwe, responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Appending garbage to the JARM JWE to break integrity...");
      const tamperedJwe = jarmJwe + "BROKEN";

      log.debug("→ Posting broken JARM to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the broken JWT...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-66 — Invalid JWT claims
  // -----------------------------------------------------------------------

  test("RPR_066: Invalid JWT claims | RP rejects a response with invalid claim sets inside the encrypted payload", async () => {
    const log = baseLog.withTag("RPR_066");
    const DESCRIPTION =
      "RP correctly rejected response with invalid JWT claims";
    log.start("Conformance test: Invalid JWT claims");

    let testSuccess = false;
    try {
      const { responseUri } = await getFreshAuthorizationResponse();

      log.debug("→ Building JARM with completely invalid claims...");
      const encryptionKey = verifierMetadata.jwks.keys.find(
        (k) => k.use === "enc",
      );
      expect(encryptionKey).toBeDefined();

      // Encrypt an invalid claim set (missing required fields, wrong types)
      const invalidPayload = JSON.stringify({
        exp: "not-a-number",
        iss: 12345,
        unexpected_field: true,
      });

      const encryptJwe = getEncryptJweCallback(encryptionKey!);
      const { jwe: tamperedJwe } = await encryptJwe(
        {
          alg:
            verifierMetadata.authorization_encrypted_response_alg || "ECDH-ES",
          enc:
            verifierMetadata.authorization_encrypted_response_enc ||
            "A128CBC-HS256",
          method: "jwk" as const,
          publicJwk: encryptionKey!,
        },
        invalidPayload,
      );

      log.debug("→ Posting JARM with invalid claims to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(
        responseUri,
        formBody.toString(),
      );

      log.debug(`  Response status: ${response.status}`);
      log.debug("→ Validating RP rejected the invalid claims...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-76 — Unsupported HTTP methods
  // -----------------------------------------------------------------------

  test("RPR_076: Unsupported HTTP methods | RP rejects PUT, DELETE, and PATCH requests to response_uri", async () => {
    const log = baseLog.withTag("RPR_076");
    const DESCRIPTION = "RP correctly rejected unsupported HTTP methods";
    log.start("Conformance test: Unsupported HTTP methods");

    let testSuccess = false;
    try {
      const { jarmJwe, responseUri } = await getFreshAuthorizationResponse();

      const unsupportedMethods = ["PUT", "DELETE", "PATCH"];
      for (const method of unsupportedMethods) {
        log.debug(`→ Sending ${method} request to response_uri...`);
        const formBody = new URLSearchParams({ response: jarmJwe });
        const response = await postToResponseUri(
          responseUri,
          formBody.toString(),
          { method },
        );

        log.debug(`  ${method} response status: ${response.status}`);
        expect(response.ok, `RP should reject ${method} on response_uri`).toBe(
          false,
        );
      }

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });
});
