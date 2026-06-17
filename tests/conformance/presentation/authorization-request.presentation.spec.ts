/* eslint-disable max-lines-per-function */
import type { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import { definePresentationTest } from "#/config/test-metadata";
import { postToResponseUri } from "#/helpers";
import { useTestSummary } from "#/helpers/use-test-summary";
import { Jwk } from "@pagopa/io-wallet-oauth2";
import {
  createAuthorizationResponse,
  type CreateAuthorizationResponseVersionedOptions,
} from "@pagopa/io-wallet-oid4vp";
import { IoWalletSdkConfig } from "@pagopa/io-wallet-utils";
import { CompactEncrypt, generateKeyPair } from "jose";
import { beforeAll, describe, expect, test } from "vitest";

import type { AttestationResponse, CredentialWithKey } from "@/types";

import { createQuietLogger, loadConfigWithHierarchy } from "@/logic";
import { getEncryptJweCallback } from "@/logic/jwt";
import { hasObjectProperties, partialCallbacks } from "@/logic/utils";
import { WalletPresentationOrchestratorFlow } from "@/orchestrator/wallet-presentation-orchestrator-flow";
import {
  AuthorizationRequestDefaultStep,
  AuthorizationRequestStepResponse,
} from "@/step/presentation/authorization-request-step";
import { assertStepSuccess } from "@/step/step-flow";

const testConfig = await definePresentationTest(
  "AuthorizationRequestValidation",
);

describe(`[${testConfig.name}] Presentation Authorization Request Validation`, () => {
  const orchestrator = new WalletPresentationOrchestratorFlow(testConfig);
  const baseLog = orchestrator.getLog();

  let verifierMetadata: ItWalletCredentialVerifierMetadata;
  let verifierEncryptionKey: Jwk;
  let walletAttestationResponse: AttestationResponse;
  let credentials: CredentialWithKey[];
  let ioWalletSdkConfig: IoWalletSdkConfig;

  // -----------------------------------------------------------------------
  // Shared setup – run once
  // -----------------------------------------------------------------------

  beforeAll(async () => {
    const ctx = await orchestrator.runThroughAuthorize();

    if (!ctx.verifierMetadata) {
      throw new Error(
        "Setup failed: verifierMetadata is undefined — RP did not return valid metadata",
      );
    }
    verifierMetadata = ctx.verifierMetadata;
    walletAttestationResponse = ctx.walletAttestationResponse;
    credentials = ctx.credentials;

    const key = verifierMetadata.jwks.keys.find((k) => k.use === "enc");
    if (!key) {
      throw new Error(
        "RP metadata does not contain an encryption key (use=enc) — " +
          "cannot build JARM for this test suite. Check RP JWKS endpoint.",
      );
    }
    verifierEncryptionKey = key;
    ioWalletSdkConfig = new IoWalletSdkConfig({
      itWalletSpecsVersion: loadConfigWithHierarchy().wallet.wallet_version,
    });
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
  // RPR-25 — Malformed claims in presentation payload
  // -----------------------------------------------------------------------

  test("RPR-25: Malformed claims in presentation payload | RP rejects a response whose decrypted payload contains malformed claims", async () => {
    const log = baseLog.withTag("RPR-25");
    const DESCRIPTION = "RP correctly rejected response with malformed claims";
    log.start("Conformance test: Malformed claims in presentation payload");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { responseUri } = authResult.response;

      log.info("→ Building JARM with malformed vp_token claims...");

      const malformedPayload = JSON.stringify({
        state: "invalid-state",
        vp_token: { invalid_credential_id: 12345 },
      });

      const encryptJwe = getEncryptJweCallback();
      const { jwe: tamperedJwe } = await encryptJwe(
        {
          alg:
            verifierMetadata.authorization_encrypted_response_alg || "ECDH-ES",
          enc:
            verifierMetadata.authorization_encrypted_response_enc ||
            "A128CBC-HS256",
          method: "jwk" as const,
          publicJwk: verifierEncryptionKey,
        },
        malformedPayload,
      );

      log.info("→ Posting tampered JARM to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
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
  // RPR-26 — Malformed claims in presented credentials
  // -----------------------------------------------------------------------

  test("RPR-26: Malformed claims in presented credentials | RP rejects a response whose credential claims are malformed", async () => {
    const log = baseLog.withTag("RPR-26");
    const DESCRIPTION =
      "RP correctly rejected response with malformed credential claims";
    log.start("Conformance test: Malformed claims in presented credentials");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { responseUri } = authResult.response;

      log.info("→ Building JARM with malformed credential-level claims...");
      // Send garbage credential data inside vp_token
      const malformedPayload = JSON.stringify({
        state: "some-state",
        vp_token: {
          credential_query_id: "not-a-valid-credential-jwt",
        },
      });

      const encryptJwe = getEncryptJweCallback();
      const { jwe: tamperedJwe } = await encryptJwe(
        {
          alg:
            verifierMetadata.authorization_encrypted_response_alg || "ECDH-ES",
          enc:
            verifierMetadata.authorization_encrypted_response_enc ||
            "A128CBC-HS256",
          method: "jwk" as const,
          publicJwk: verifierEncryptionKey,
        },
        malformedPayload,
      );

      log.info("→ Posting tampered JARM to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the malformed credentials...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-37 — Response encryption failures
  // -----------------------------------------------------------------------

  test("RPR-37: Response encryption failures | RP rejects a response encrypted with a wrong key", async () => {
    const log = baseLog.withTag("RPR-37");
    const DESCRIPTION =
      "RP correctly rejected response with wrong encryption key";
    log.start("Conformance test: Response encryption failures");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { responseUri } = authResult.response;

      log.info("→ Generating a random EC key for wrong encryption...");
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

      log.info("→ Posting wrongly-encrypted JARM to response_uri...");
      const formBody = new URLSearchParams({ response: wrongJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the response...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-38 — Invalid signatures
  // -----------------------------------------------------------------------

  test("RPR-38: Invalid signatures | RP rejects a response with tampered JARM integrity", async () => {
    const log = baseLog.withTag("RPR-38");
    const DESCRIPTION =
      "RP correctly rejected response with tampered signature";
    log.start("Conformance test: Invalid signatures");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { authorizationResponse, responseUri } = authResult.response;
      const jarmJwe = authorizationResponse.jarm.responseJwe;

      log.info("→ Tampering with the JARM JWE ciphertext...");
      // A JWE compact serialization has 5 base64url-encoded parts: header.ek.iv.ciphertext.tag
      const parts = jarmJwe.split(".");
      expect(parts.length).toBe(5);

      // Tamper with the authentication tag to invalidate integrity
      const tag = parts[4];
      if (!tag) throw new Error("received malformed jarm jwe");

      const tamperedTag =
        tag.slice(0, -4) + (tag.endsWith("AAAA") ? "BBBB" : "AAAA");
      parts[4] = tamperedTag;
      const tamperedJwe = parts.join(".");

      log.info("→ Posting tampered JARM to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the tampered content...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-39 — Invalid nonce values
  // -----------------------------------------------------------------------

  test("RPR-39: Invalid nonce values | RP rejects a response containing a nonce mismatch", async () => {
    const log = baseLog.withTag("RPR-39");
    const DESCRIPTION = "RP correctly rejected response with mismatched nonce";
    log.start("Conformance test: Invalid nonce values");

    let testSuccess = false;
    try {
      // Run a fresh auth step to get a valid request context
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      assertStepSuccess(authResult, AuthorizationRequestDefaultStep.tag);
      hasObjectProperties(authResult, ["response"]);

      if (!authResult.response)
        throw new Error("auth request was not successful");

      const { requestObject, responseUri } = authResult.response;

      log.info(
        "→ Building JARM with a wrong nonce via createAuthorizationResponse...",
      );

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
          encryptJwe: getEncryptJweCallback(),
        },
        config: ioWalletSdkConfig,
        requestObject: tamperedRequestObject,
        rpJwks: { jwks: metadata.jwks },
        vp_token:
          authResult.response.authorizationResponse.authorizationResponsePayload
            .vp_token,
      } as CreateAuthorizationResponseVersionedOptions);

      log.info("→ Posting JARM with wrong nonce to response_uri...");
      const formBody = new URLSearchParams({
        response: tamperedAuthorizationResponse.jarm.responseJwe,
      });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the nonce mismatch...");
      expect(response.ok).toBe(false);
      expect(
        response.status,
        "RP must return 403 for nonce mismatch per IT-Wallet spec",
      ).toBe(403);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-49 — Unsupported content types
  // -----------------------------------------------------------------------

  test("RPR-49: Unsupported content types | RP rejects a response posted with an unsupported Content-Type", async () => {
    const log = baseLog.withTag("RPR-49");
    const DESCRIPTION =
      "RP correctly rejected response with unsupported Content-Type";
    log.start("Conformance test: Unsupported content types");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { authorizationResponse, responseUri } = authResult.response;
      const jarmJwe = authorizationResponse.jarm.responseJwe;

      log.info(
        "→ Posting JARM to response_uri with Content-Type: text/plain...",
      );
      const formBody = new URLSearchParams({ response: jarmJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
        contentType: "text/plain",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the unsupported content type...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-52 — Response decryption failures
  // -----------------------------------------------------------------------

  test("RPR-52: Response decryption failures | RP rejects malformed JWE content", async () => {
    const log = baseLog.withTag("RPR-52");
    const DESCRIPTION = "RP correctly rejected response with malformed JWE";
    log.start("Conformance test: Response decryption failures");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { responseUri } = authResult.response;

      log.info("→ Posting completely malformed JWE to response_uri...");
      const malformedJwe = "eyJhbGciOiJFQ0RILUVTLN0.bad.bad.bad.bad";
      const formBody = new URLSearchParams({ response: malformedJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the malformed JWE...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-53 — SD-JWT integrity verification failure
  // -----------------------------------------------------------------------

  test("RPR-53: SD-JWT integrity verification failure | RP rejects a response containing a tampered KB-JWT signature", async () => {
    const log = baseLog.withTag("RPR-53");
    const DESCRIPTION =
      "RP correctly rejected response with tampered SD-JWT KB-JWT signature";
    log.start("Conformance test: SD-JWT integrity verification failure");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response) {
        throw new Error("auth request was not successful");
      }

      const { requestObject, responseUri } = authResult.response;
      const rawVpToken = authResult.response.authorizationResponse
        .authorizationResponsePayload.vp_token as Record<
        string,
        string | string[]
      >;

      log.info("→ Tampering KB-JWT signature inside the SD-JWT VP vp_token...");

      const tamperedVpToken: Record<string, string | string[]> = {};
      let tamperedSdJwtCount = 0;

      const tamperSdJwt = (sdJwt: string): string => {
        const parts = sdJwt.split("~");
        const kbJwt = parts[parts.length - 1];
        if (!kbJwt) {
          throw new Error(
            "Test setup failed: vp_token entry is not an SD-JWT with a KB-JWT segment",
          );
        }

        const jwtParts = kbJwt.split(".");
        if (jwtParts.length !== 3) {
          throw new Error(
            "Test setup failed: could not parse KB-JWT inside SD-JWT (expected 3 JWT parts)",
          );
        }

        const sig = jwtParts[2] ?? "";
        if (sig.length < 4) {
          throw new Error(
            "Test setup failed: KB-JWT signature too short to tamper",
          );
        }

        const tamperedSig =
          sig.slice(0, -4) + (sig.endsWith("AAAA") ? "BBBB" : "AAAA");
        jwtParts[2] = tamperedSig;
        parts[parts.length - 1] = jwtParts.join(".");
        tamperedSdJwtCount++;
        return parts.join("~");
      };

      for (const [credId, sdJwtVp] of Object.entries(rawVpToken)) {
        tamperedVpToken[credId] = Array.isArray(sdJwtVp)
          ? sdJwtVp.map(tamperSdJwt)
          : tamperSdJwt(sdJwtVp);
      }

      if (tamperedSdJwtCount === 0) {
        throw new Error(
          "Test setup failed: no SD-JWT entries were tampered (KB-JWT signature not found)",
        );
      }

      log.info(
        "→ Re-building JARM with tampered vp_token and posting to response_uri...",
      );

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
          encryptJwe: getEncryptJweCallback(),
        },
        config: ioWalletSdkConfig,
        requestObject,
        rpJwks: { jwks: metadata.jwks },
        vp_token: tamperedVpToken,
      } as CreateAuthorizationResponseVersionedOptions);

      const formBody = new URLSearchParams({
        response: tamperedAuthorizationResponse.jarm.responseJwe,
      });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the tampered SD-JWT...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-60 — Invalid HTTP methods
  // -----------------------------------------------------------------------

  test("RPR-60: Invalid HTTP methods | RP rejects GET request to response_uri", async () => {
    const log = baseLog.withTag("RPR-60");
    const DESCRIPTION = "RP correctly rejected GET request to response_uri";
    log.start("Conformance test: Invalid HTTP methods (GET)");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { responseUri } = authResult.response;

      log.info("→ Sending GET request to response_uri...");
      const response = await postToResponseUri(responseUri, {
        method: "GET",
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the GET method...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-63 — Response signature failures
  // -----------------------------------------------------------------------

  test("RPR-63: Response signature failures | RP rejects a response whose JARM ciphertext has been corrupted", async () => {
    const log = baseLog.withTag("RPR-63");
    const DESCRIPTION =
      "RP correctly rejected response with corrupted ciphertext";
    log.start("Conformance test: Response signature failures");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { authorizationResponse, responseUri } = authResult.response;
      const jarmJwe = authorizationResponse.jarm.responseJwe;

      log.info("→ Corrupting the JARM JWE ciphertext segment...");
      const parts = jarmJwe.split(".");
      expect(parts.length).toBe(5);
      // Corrupt the ciphertext (4th part, index 3)
      const ciphertext = parts[3];
      if (!ciphertext) throw new Error("received malformed jarm jwe");

      parts[3] = ciphertext.slice(0, 4) + "TAMPERED" + ciphertext.slice(12);
      const corruptedJwe = parts.join(".");

      log.info("→ Posting corrupted JARM to response_uri...");
      const formBody = new URLSearchParams({ response: corruptedJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the corrupted content...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-65 — Invalid JWT signatures
  // -----------------------------------------------------------------------

  test("RPR-65: Invalid JWT signatures | RP rejects a response whose JWT integrity is deliberately broken", async () => {
    const log = baseLog.withTag("RPR-65");
    const DESCRIPTION =
      "RP correctly rejected response with broken JWT integrity";
    log.start("Conformance test: Invalid JWT signatures");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { authorizationResponse, responseUri } = authResult.response;
      const jarmJwe = authorizationResponse.jarm.responseJwe;

      log.info("→ Appending garbage to the JARM JWE to break integrity...");
      const tamperedJwe = jarmJwe + "BROKEN";

      log.info("→ Posting broken JARM to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the broken JWT...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-66 — Invalid JWT claims
  // -----------------------------------------------------------------------

  test("RPR-66: Invalid JWT claims | RP rejects a response with invalid claim sets inside the encrypted payload", async () => {
    const log = baseLog.withTag("RPR-66");
    const DESCRIPTION =
      "RP correctly rejected response with invalid JWT claims";
    log.start("Conformance test: Invalid JWT claims");

    let testSuccess = false;
    try {
      const authResult = await runAuthorizationStep(
        testConfig.authorizeStepClass,
      );
      expect(authResult.success).toBe(true);
      if (!authResult.response)
        throw new Error("could not resolve authorization response");
      const { responseUri } = authResult.response;

      log.info("→ Building JARM with completely invalid claims...");

      // Encrypt an invalid claim set (missing required fields, wrong types)
      const invalidPayload = JSON.stringify({
        exp: "not-a-number",
        iss: 12345,
        unexpected_field: true,
      });

      const encryptJwe = getEncryptJweCallback();
      const { jwe: tamperedJwe } = await encryptJwe(
        {
          alg:
            verifierMetadata.authorization_encrypted_response_alg || "ECDH-ES",
          enc:
            verifierMetadata.authorization_encrypted_response_enc ||
            "A128CBC-HS256",
          method: "jwk" as const,
          publicJwk: verifierEncryptionKey,
        },
        invalidPayload,
      );

      log.info("→ Posting JARM with invalid claims to response_uri...");
      const formBody = new URLSearchParams({ response: tamperedJwe });
      const response = await postToResponseUri(responseUri, {
        body: formBody.toString(),
      });

      log.debug(`  Response status: ${response.status}`);
      log.info("→ Validating RP rejected the invalid claims...");
      expect(response.ok).toBe(false);

      testSuccess = true;
    } finally {
      log.testCompleted(DESCRIPTION, testSuccess);
    }
  });

  // -----------------------------------------------------------------------
  // RPR-76 — Unsupported HTTP methods
  // -----------------------------------------------------------------------

  test.each(["PUT", "DELETE", "PATCH"])(
    "RPR-76: Unsupported HTTP methods | RP rejects PUT, DELETE, and PATCH requests to response_uri",
    async (method) => {
      const log = baseLog.withTag("RPR-76");
      const DESCRIPTION = "RP correctly rejected unsupported HTTP methods";
      log.start("Conformance test: Unsupported HTTP methods");

      let testSuccess = false;
      try {
        const authResult = await runAuthorizationStep(
          testConfig.authorizeStepClass,
        );
        expect(authResult.success).toBe(true);
        if (!authResult.response)
          throw new Error("could not resolve authorization response");
        const { authorizationResponse, responseUri } = authResult.response;
        const jarmJwe = authorizationResponse.jarm.responseJwe;

        log.info(`→ Sending ${method} request to response_uri...`);
        const formBody = new URLSearchParams({ response: jarmJwe });
        const response = await postToResponseUri(responseUri, {
          body: formBody.toString(),
          method,
        });

        log.debug(`  ${method} response status: ${response.status}`);
        expect(response.ok, `RP should reject ${method} on response_uri`).toBe(
          false,
        );

        testSuccess = true;
      } finally {
        log.testCompleted(DESCRIPTION, testSuccess);
      }
    },
  );
});
