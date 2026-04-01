# Factory Helpers Guide

Factory helpers are lightweight utilities for creating step override classes with minimal boilerplate. Use them when your negative test requires only a **single deviant parameter** — without writing full custom step classes.

This guide explains **when and how** to use factory helpers for issuance and presentation conformance testing.

---

## Part 1: Using Factory Helpers in Tests

### 1.1 Inject into Test Configuration

Create your step classes using factory helpers and pass them to `IssuerTestConfiguration.createCustom()`:

```typescript
import { defineIssuanceTest } from "#/config/test-metadata";
import { IssuerTestConfiguration } from "#/config";
import {
  withSignJwtOverride,
  signWithHS256,
  signWithWrongKey,
} from "#/helpers/par-validation-helpers";
import { beforeAll, describe, test, expect } from "vitest";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import type { PushedAuthorizationRequestResponse } from "@/step/issuance";

// @ts-expect-error TS1309
const testConfigs = await defineIssuanceTest("MyNegativeTests");

testConfigs.forEach((baseConfig) => {
  describe(`[${baseConfig.name}] Comprehensive PAR Validation`, () => {

    // Variant 1: Signed with wrong key
    const wrongKeyConfig = IssuerTestConfiguration.createCustom({
      ...baseConfig,
      pushedAuthorizationRequestStepClass: withSignJwtOverride(
        baseConfig.pushedAuthorizationRequestStepClass,
        signWithWrongKey(),
      ),
    });

    const orchestrator = new WalletIssuanceOrchestratorFlow(wrongKeyConfig);
    const log = orchestrator.getLog();

    let parResponse: PushedAuthorizationRequestResponse;
    
    beforeAll(async () => {
      const result = await orchestrator.issuance();
      parResponse = result.pushedAuthorizationRequestResponse;
    });

    test(`Negative test`, () => {
      let testSuccess = false;
      try {
        expect(
          parResponse.success,
          "PAR must fail with plain challenge"
        ).toBe(false);
        testSuccess = true;
      } finally {
        log.testCompleted("CI_010", testSuccess);
      }
    });
  });
});
```

---

### 1.2 Multiple Override Variants in One Suite

Each variant gets its own `IssuerTestConfiguration` (created by spreading the base config and overriding one step class) and its own `WalletIssuanceOrchestratorFlow` that runs the full issuance flow independently.

```typescript
import { defineIssuanceTest } from "#/config/test-metadata";
import { IssuerTestConfiguration } from "#/config";
import {
  withSignJwtOverride,
  signWithHS256,
  signWithWrongKey,
} from "#/helpers/par-validation-helpers";
import { beforeAll, describe, test, expect } from "vitest";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import type { PushedAuthorizationRequestResponse } from "@/step/issuance";

// @ts-expect-error TS1309
const testConfigs = await defineIssuanceTest("MyNegativeTests");

testConfigs.forEach((baseConfig) => {
  describe(`[${baseConfig.name}] Comprehensive PAR Validation`, () => {

    // Variant 1: Signed with wrong key
    const wrongKeyConfig = IssuerTestConfiguration.createCustom({
      ...baseConfig,
      pushedAuthorizationRequestStepClass: withSignJwtOverride(
        baseConfig.pushedAuthorizationRequestStepClass,
        signWithWrongKey(),
      ),
    });

    // Variant 2: Signed with HS256
    const hs256Config = IssuerTestConfiguration.createCustom({
      ...baseConfig,
      pushedAuthorizationRequestStepClass: withSignJwtOverride(
        baseConfig.pushedAuthorizationRequestStepClass,
        signWithHS256("secret"),
      ),
    });

    // Run each variant independently
    const orchestrators = [
      { name: "Wrong Key", config: wrongKeyConfig },
      { name: "HS256", config: hs256Config },
    ];

    orchestrators.forEach(({ name, config }) => {
      const orchestrator = new WalletIssuanceOrchestratorFlow(config);
      const log = orchestrator.getLog();

      let parResponse: PushedAuthorizationRequestResponse;
      
      beforeAll(async () => {
        const result = await orchestrator.issuance();
        parResponse = result.pushedAuthorizationRequestResponse;
      });

      test(`Negative test: ${name}`, () => {
        let testSuccess = false;
        try {
          expect(
            parResponse.success,
            `PAR must fail with ${name}`
          ).toBe(false);
          testSuccess = true;
        } finally {
          log.testCompleted("CI_010", testSuccess);
        }
      });
    });
  });
});
```

---



### 1.3 Run the Flow Up to a Specific Step

For negative tests that target a **specific step** (e.g., the credential request), you don't need to re-run the entire flow for each test case. The orchestrator exposes three `runThrough*` methods that execute the flow up to a checkpoint and return the context needed to run the subsequent step manually.

#### Available checkpoints

| Method | Runs steps | Returns context for |
|---|---|---|
| `runThroughPar()` | Fetch Metadata → PAR | Token, Credential, or custom PAR re-run |
| `runThroughAuthorize()` | Fetch Metadata → PAR → Authorize | Token, Credential |
| `runThroughToken()` | Fetch Metadata → PAR → Authorize → Token | Nonce, Credential |

> **Warning:** Each `runThrough*` method starts the flow **from scratch** (step 1). Do **not** call `runThroughPar()` and then `runThroughToken()` on the same orchestrator instance — both will re-execute PAR from the beginning, producing duplicate requests.

#### Pattern: shared context in `beforeAll`, targeted step in each `test()`

The standard pattern is:

1. Call `runThroughPar()` (or another checkpoint) once in `beforeAll` to prepare shared context.
2. In each `test()`, instantiate the next step independently and run it with the context — one variant per test case.

```typescript
import { defineIssuanceTest } from "#/config/test-metadata";
import {
  withSignJwtOverride,
  signWithWrongKey,
  signWithHS256,
} from "#/helpers/par-validation-helpers";
import { beforeAll, describe, test, expect, afterEach } from "vitest";
import { createClientAttestationPopJwt } from "@pagopa/io-wallet-oauth2";
import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { PushedAuthorizationRequestDefaultStep } from "@/step/issuance";
import type { PushedAuthorizationRequestResponse } from "@/step/issuance";
import {
  createQuietLogger,
  loadConfigWithHierarchy,
  partialCallbacks,
  signJwtCallback,
} from "@/logic";
import type { AttestationResponse } from "@/types";

// @ts-expect-error TS1309
const testConfigs = await defineIssuanceTest("PARValidation");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] PAR Validation`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    // Context extracted once in beforeAll — shared across all test()
    let walletAttestationResponse: AttestationResponse;
    let pushedAuthorizationRequestEndpoint: string;
    let authorizationServer: string;

    beforeAll(async () => {
      // Run the flow through PAR to collect shared context.
      // After this call, the PAR step has already succeeded.
      const ctx = await orchestrator.runThroughPar();

      walletAttestationResponse = ctx.walletAttestationResponse;
      pushedAuthorizationRequestEndpoint = ctx.pushedAuthorizationRequestEndpoint;
      authorizationServer = ctx.authorizationServer;
    });

    // Creates a fresh OAuth-Client-Attestation-PoP JWT for each PAR invocation
    // to avoid 60 s TTL exhaustion when re-running the step multiple times.
    async function createFreshPop(): Promise<string> {
      return createClientAttestationPopJwt({
        authorizationServer,
        callbacks: {
          ...partialCallbacks,
          signJwt: signJwtCallback([walletAttestationResponse.unitKey.privateKey]),
        },
        clientAttestation: walletAttestationResponse.attestation,
      });
    }

    // Helper: run only the PAR step with a given step class,
    // reusing the shared context from beforeAll.
    async function runParStep(
      StepClass: typeof PushedAuthorizationRequestDefaultStep,
    ): Promise<PushedAuthorizationRequestResponse> {
      const config = loadConfigWithHierarchy();
      const step = new StepClass(config, createQuietLogger());
      return step.run({
        baseUrl: config.issuance.url,
        clientId: walletAttestationResponse.unitKey.publicKey.kid,
        credentialConfigurationIds: [testConfig.credentialConfigurationId],
        popAttestation: await createFreshPop(),
        pushedAuthorizationRequestEndpoint,
        walletAttestation: walletAttestationResponse,
      });
    }

    test("CI_015 — PAR with wrong key should fail", async () => {
      let testSuccess = false;
      try {
        const result = await runParStep(
          withSignJwtOverride(
            testConfig.pushedAuthorizationRequestStepClass,
            signWithWrongKey(),
          ),
        );
        expect(result.success, "PAR must be rejected with wrong key").toBe(false);
        testSuccess = true;
      } finally {
        baseLog.testCompleted("CI_015", testSuccess);
      }
    });

    test("CI_019 — PAR with HS256 algorithm should fail", async () => {
      let testSuccess = false;
      try {
        const result = await runParStep(
          withSignJwtOverride(
            testConfig.pushedAuthorizationRequestStepClass,
            signWithHS256("secret"),
          ),
        );
        expect(result.success, "PAR must be rejected with HS256").toBe(false);
        testSuccess = true;
      } finally {
        baseLog.testCompleted("CI_019", testSuccess);
      }
    });
  });
});
```

#### What the context objects contain

**`RunThroughParContext`** — returned by `runThroughPar()`:

| Field | Type | Description |
|---|---|---|
| `authorizationServer` | `string` | `iss` from the issuer's entity statement |
| `credentialIssuer` | `string` | Base URL of the credential issuer |
| `fetchMetadataResponse` | `FetchMetadataStepResponse` | Full metadata response including `entityStatementClaims` |
| `popAttestation` | `string` | The OAuth-Client-Attestation-PoP JWT generated during PAR |
| `pushedAuthorizationRequestEndpoint` | `string` | Endpoint URL for the PAR request |
| `pushedAuthorizationRequestResponse` | `PushedAuthorizationRequestResponse` | PAR step result |
| `walletAttestationResponse` | `AttestationResponse` | Wallet attestation with key pairs |

**`RunThroughAuthorizeContext`** — returned by `runThroughAuthorize()` (extends PAR context):

| Field | Type | Description |
|---|---|---|
| `authorizationEndpoint` | `string` | Authorization endpoint URL |
| `authorizeResponse` | `AuthorizeStepResponse` | Authorization step result |

**`RunThroughTokenContext`** — returned by `runThroughToken()` (extends Authorize context):

| Field | Type | Description |
|---|---|---|
| `tokenResponse` | `TokenRequestResponse` | Token step result including `access_token` |

---

## Part 2: Pushed Authorization Request (PAR) Helpers

PAR helpers live in `#/helpers/par-validation-helpers.ts` and override the `PushedAuthorizationRequestDefaultStep`.

### 2.1 `withParOverrides(StepClass, overrides)`

Override any field in the PAR request options.

**Signature:**
```typescript
withParOverrides(
  StepClass: typeof PushedAuthorizationRequestDefaultStep,
  overrides: Partial<CreatePushedAuthorizationRequestOptions>
): typeof PushedAuthorizationRequestDefaultStep
```

**Example 1: Wrong PKCE challenge method**
```typescript
import {
  withParOverrides,
  PushedAuthorizationRequestDefaultStep,
} from "#/helpers/par-validation-helpers";

// Produces a step that sends `code_challenge_method: "plain"` instead of "S256"
const WrongChallengeMethodStep = withParOverrides(
  PushedAuthorizationRequestDefaultStep,
  { code_challenge_method: "plain" },
);
```

**Example 2: Custom client ID**
```typescript
const CustomClientIdStep = withParOverrides(
  PushedAuthorizationRequestDefaultStep,
  { client_id: "wrong-client-id" },
);
```

**Example 3: Multiple overrides**
```typescript
const MultiOverrideStep = withParOverrides(
  PushedAuthorizationRequestDefaultStep,
  {
    code_challenge_method: "plain",
    response_type: "code id_token",  // wrong value
  },
);
```

### 2.2 `withSignJwtOverride(StepClass, signJwt)`

Replace **only** the JWT signing callback, preserving `generateRandom` and `hash` from the default callbacks.

**Important:** Always use this (not `withParOverrides({ callbacks: ... })`) because a shallow merge would silently drop `generateRandom` and `hash`, causing runtime failures.

**Signature:**
```typescript
withSignJwtOverride(
  StepClass: typeof PushedAuthorizationRequestDefaultStep,
  signJwt: SignJwtCallback
): typeof PushedAuthorizationRequestDefaultStep
```

**Example: Sign with wrong key**
```typescript
import {
  withSignJwtOverride,
  signWithWrongKey,
} from "#/helpers/par-validation-helpers";

const WrongKeyStep = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signWithWrongKey(),
);
```

---

## Part 3: JWT Signing Helpers

These helpers return `SignJwtCallback` functions designed for injection via `withSignJwtOverride`.

### 3.1 `signWithWrongKey()`

Signs with a fresh, unrelated EC key that has no relation to the wallet attestation.

```typescript
import { signWithWrongKey } from "#/helpers/par-validation-helpers";

const step = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signWithWrongKey(),
);
```

**Expected behavior:** Issuer rejects because the signature doesn't match the wallet attestation's public key.

---

### 3.2 `signWithHS256(secret)`

Signs with HMAC-SHA256 (symmetric algorithm). **Forbidden by IT-Wallet spec** — issuers must reject.

**Signature:**
```typescript
signWithHS256(secret: string): SignJwtCallback
```

**Example:**
```typescript
import { signWithHS256 } from "#/helpers/par-validation-helpers";

const step = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signWithHS256("my-secret-key"),
);
```

**Expected behavior:** Issuer rejects non-asymmetric algorithm.

---

### 3.3 `signWithMismatchedAlgorithm(headerAlg, signAlg)`

Signs with one algorithm (e.g., `ES384`) but declares another in the JWT header (e.g., `ES256`).

**Signature:**
```typescript
signWithMismatchedAlgorithm(
  headerAlg: "ES256" | "ES384" | "ES512" | "HS256" | "RS256",
  signAlg: "ES256" | "ES384" | "ES512" | "HS256" | "RS256"
): SignJwtCallback
```

**Example:**
```typescript
import { signWithMismatchedAlgorithm } from "#/helpers/par-validation-helpers";

// Sign with ES384, but declare ES256 in header
const step = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signWithMismatchedAlgorithm("ES256", "ES384"),
);
```

**Expected behavior:** Issuer rejects because algorithm validation fails.

---

### 3.4 `signWithWrongAlgHeader(alg, realPrivateKey, realPublicKey)`

Sign with the real key but override the `alg` header to an unexpected value.

**Signature:**
```typescript
signWithWrongAlgHeader(
  alg: "ES256" | "ES384" | "ES512" | "HS256" | "RS256",
  realPrivateKey: KeyPairJwk,
  realPublicKey: KeyPairJwk
): SignJwtCallback
```

**Example:**
```typescript
import { signWithWrongAlgHeader } from "#/helpers/par-validation-helpers";

const step = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signWithWrongAlgHeader("RS256", realPrivateKey, realPublicKey),
);
```

**Expected behavior:** Issuer rejects unsupported algorithm (RS256).

---

### 3.5 `signWithWrongKid(kid, realPrivateKey, realPublicKey)`

Sign with the real key but use a wrong `kid` in the JWS header.

**Example:**
```typescript
import { signWithWrongKid } from "#/helpers/par-validation-helpers";

const step = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signWithWrongKid("wrong-kid-value", realPrivateKey, realPublicKey),
);
```

---

### 3.6 `signThenTamperPayload(realPrivateKey, realPublicKey, field, value)`

Sign the JWT normally, then mutate a claim in the payload **without re-signing** (breaking signature integrity).

**Example:**
```typescript
import { signThenTamperPayload } from "#/helpers/par-validation-helpers";

// Sign normally, then change the `iss` claim
const step = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signThenTamperPayload(
    realPrivateKey,
    realPublicKey,
    "iss",
    "https://wrong-issuer.example.com"
  ),
);
```

**Expected behavior:** Issuer rejects because signature no longer matches payload.

---

### 3.7 `signWithCustomIss(iss, realPrivateKey, realPublicKey)`

Sign with the real key but inject a custom `iss` claim.

**Example:**
```typescript
import { signWithCustomIss } from "#/helpers/par-validation-helpers";

const step = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signWithCustomIss(
    "https://wrong-issuer.example.com",
    realPrivateKey,
    realPublicKey
  ),
);
```

**Expected behavior:** Issuer rejects because `iss` must equal `client_id`.

---

## Part 4: Credential Request Helpers

Credential helpers live in `#/helpers/credential-validation-helpers.ts` and override the `CredentialRequestDefaultStep`.

### 4.1 `withCredentialRequestOverrides(StepClass, overrides)`

Override any field in the credential request options.

**Signature:**
```typescript
withCredentialRequestOverrides(
  StepClass: typeof CredentialRequestDefaultStep,
  overrides: CredentialRequestStepOptions["createCredentialRequestOverrides"]
): typeof CredentialRequestDefaultStep
```

**Example: Custom format**
```typescript
import {
  withCredentialRequestOverrides,
} from "#/helpers/credential-validation-helpers";

const CustomFormatStep = withCredentialRequestOverrides(
  CredentialRequestDefaultStep,
  { format: "mso_mdoc" },  // override format
);
```

---

### 4.2 `withCredentialSignJwtOverride(StepClass, signJwt)`

Replace only the JWT signing callback for the credential proof.

**Signature:**
```typescript
withCredentialSignJwtOverride(
  StepClass: typeof CredentialRequestDefaultStep,
  signJwt: SignJwtCallback
): typeof CredentialRequestDefaultStep
```

**Example: Sign with HS256**
```typescript
import {
  withCredentialSignJwtOverride,
  signWithHS256,
} from "#/helpers/credential-validation-helpers";

const HS256ProofStep = withCredentialSignJwtOverride(
  CredentialRequestDefaultStep,
  signWithHS256("secret-key"),
);
```

---

### 4.3 Credential Proof Signing Helpers

#### `signWithHS256(secret)`
Sign the credential proof with HS256 (forbidden).

```typescript
import { signWithHS256 } from "#/helpers/credential-validation-helpers";

const step = withCredentialSignJwtOverride(
  CredentialRequestDefaultStep,
  signWithHS256("secret"),
);
```

---

#### `signWithWrongKey()`
Sign with a fresh, unrelated key — signature won't verify.

```typescript
import { signWithWrongKey } from "#/helpers/credential-validation-helpers";

const step = withCredentialSignJwtOverride(
  CredentialRequestDefaultStep,
  signWithWrongKey(),
);
```

---

#### `signWithoutClaim(claim, realPrivateKey, realPublicKey)`
Remove a required claim from the JWT payload before signing.

**Example: Missing nonce**
```typescript
import { signWithoutClaim } from "#/helpers/credential-validation-helpers";

const MissingNonceStep = withCredentialSignJwtOverride(
  CredentialRequestDefaultStep,
  signWithoutClaim("nonce", realPrivateKey, realPublicKey),
);
```

---

#### `signWithPrivateKeyInHeader(keyPair)`
Embed the private key `d` parameter in the JWT `jwk` header (forbidden).

```typescript
import { signWithPrivateKeyInHeader } from "#/helpers/credential-validation-helpers";

const step = withCredentialSignJwtOverride(
  CredentialRequestDefaultStep,
  signWithPrivateKeyInHeader(keyPair),
);
```

**Expected behavior:** Issuer must reject — JWK header must not contain private key material.

---

#### `signWithWrongTyp(typ, realPrivateKey, realPublicKey)`
Override the `typ` header claim.

**Example:**
```typescript
import { signWithWrongTyp } from "#/helpers/credential-validation-helpers";

const WrongTypStep = withCredentialSignJwtOverride(
  CredentialRequestDefaultStep,
  signWithWrongTyp("JWT", realPrivateKey, realPublicKey),  // wrong typ
);
```

---

### 4.4 DPoP Proof Helpers

#### `withAlgNoneDPoP(StepClass)`
Send a DPoP proof with `alg: "none"` (unsigned).

```typescript
import { withAlgNoneDPoP } from "#/helpers/credential-validation-helpers";

const step = withAlgNoneDPoP(CredentialRequestDefaultStep);
```

**Expected behavior:** Issuer rejects unsigned DPoP.

---

#### `withBadSignatureDPoP(StepClass)`
Send a DPoP signed with key A but claiming key B in the header.

```typescript
import { withBadSignatureDPoP } from "#/helpers/credential-validation-helpers";

const step = withBadSignatureDPoP(CredentialRequestDefaultStep);
```

**Expected behavior:** Issuer rejects because signature doesn't verify against claimed JWK.

---

#### `withDPoPSignedByWrongKey(StepClass)`
Send a DPoP signed by a completely different key (not the wallet's unit key).

```typescript
import { withDPoPSignedByWrongKey } from "#/helpers/credential-validation-helpers";

const step = withDPoPSignedByWrongKey(CredentialRequestDefaultStep);
```

**Expected behavior:** Issuer rejects — DPoP key must match the unit key.

---

## Part 5: Factory Helpers vs. Custom Step Classes

### When to Use Factory Helpers

✅ **Good use cases:**
- Flip a single boolean field
- Change one enum value
- Inject wrong JWT signing callback
- Override one header/parameter
- Negative tests with minimal deviation

**Pro:** Minimal boilerplate, explicit intent, no hidden logic.

### When to Write Full Step Classes

❌ **When factory helpers are insufficient:**
- Multi-step logic with state
- Complex calculations before sending request
- Post-processing response data
- Conditional behavior based on intermediate results
- Modifying request structure (adding/removing fields)

---

## Part 6: Best Practices

### 6.1 Naming Convention

Use clear names that describe the deviation:

```typescript
// ✅ Good
const WrongChallengeMethodStep = withParOverrides(...);
const MissingNonceProofStep = withCredentialSignJwtOverride(...);
const DPoPAlgNoneStep = withAlgNoneDPoP(...);

// ❌ Avoid
const BadParStep = withParOverrides(...);
const TestStep = withParOverrides(...);
```

### 6.2 Document Expected Behavior

```typescript
// ✅ Add a comment explaining why the test should fail
const step = withParOverrides(
  PushedAuthorizationRequestDefaultStep,
  { code_challenge_method: "plain" },
); // Per PKCE RFC 7636, only S256 is allowed; plain is deprecated and rejected

test("CI_010 — PAR rejects plain PKCE challenge", () => {
  expect(parResponse.success, "plain method must be rejected").toBe(false);
});
```

### 6.3 Avoid Over-Nesting

For complex negative test matrices, consider multiple `describe` blocks:

```typescript
// ✅ Clearer structure
describe("PAR Signature Tests", () => {
  test("wrong key", () => { /* ... */ });
  test("HS256 algorithm", () => { /* ... */ });
});

describe("PAR PKCE Tests", () => {
  test("plain method", () => { /* ... */ });
  test("missing challenge", () => { /* ... */ });
});
```

### 6.4 Reuse Factory Helpers Across Test Files

If the same override is tested in multiple files (e.g., different credential types), create a shared configuration factory:

```typescript
// helpers/par-negative-test-variants.ts
export const createWrongChallengeConfig = (baseConfig) =>
  baseConfig.createCustom({
    PushedAuthorizationRequestDefaultStep: withParOverrides(
      PushedAuthorizationRequestDefaultStep,
      { code_challenge_method: "plain" },
    ),
  });

// In your test file
import { createWrongChallengeConfig } from "#/helpers/par-negative-test-variants";

const wrongChallengeConfig = createWrongChallengeConfig(baseConfig);
```

---

## Summary

| Helper | Use Case | Example |
|---|---|---|
| `withParOverrides` | Override PAR options | `{ code_challenge_method: "plain" }` |
| `withSignJwtOverride` | Replace JWT signing callback | `signWithWrongKey()` |
| `signWithWrongKey` | Sign with unrelated key | Signature validation fails |
| `signWithHS256` | Use symmetric algorithm | Issuer rejects non-asymmetric |
| `signWithMismatchedAlgorithm` | Declare one alg, sign with another | Header vs. actual mismatch |
| `withCredentialRequestOverrides` | Override credential options | `{ format: "mso_mdoc" }` |
| `withAlgNoneDPoP` | Send unsigned DPoP | `alg: "none"` in header |
| `withBadSignatureDPoP` | Sign with wrong key in header | Signature doesn't verify |
| `signWithoutClaim` | Remove required JWT claim | Missing `nonce` in proof |

---

## Additional Resources

- [Issuance Testing Guide](./ISSUANCE-TESTING-GUIDE.md#step-7--negative-tests-with-factory-helpers-advanced)
- [Test Configuration Guide](./TEST-CONFIGURATION-GUIDE.md)
- Example test specs: [tests/conformance/issuance/](../tests/conformance/issuance/)
