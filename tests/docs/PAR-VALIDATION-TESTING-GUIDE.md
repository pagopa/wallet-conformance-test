# PAR Validation Testing Guide

This guide walks you through the design and implementation of `par-validation.issuance.spec.ts` — a **negative-test spec** that verifies a Credential Issuer correctly rejects malformed or malicious Pushed Authorization Requests (PAR).

Use this guide as a template when writing new conformance tests that target a single protocol step from multiple angles without re-running the entire issuance flow each time.

> **Prerequisites:** Complete the [Issuance Testing Guide](ISSUANCE-TESTING-GUIDE.md) first. This guide assumes you are familiar with the basic happy-flow spec structure, `defineIssuanceTest()`, and the `WalletIssuanceOrchestratorFlow`.

---

## Why a Separate Negative-Test Spec?

The happy-flow spec (see [Issuance Testing Guide](ISSUANCE-TESTING-GUIDE.md)) runs the full issuance flow — PAR → Authorize → Token → Nonce → Credential — once per credential type, then asserts on the collected responses.

Negative tests have a different shape:

- They must **re-run a single step** many times, each time with one deviant parameter.
- Re-running the *entire flow* for every variant would be slow and wasteful.
- The flow up to the target step must succeed (so we have valid context: attestation, endpoints, auth server URL) — but the subsequent steps do not need to run at all.

The solution is the **`runThroughPar()` checkpoint pattern**: run the flow once up to and including the real PAR step, capture the shared context, then re-invoke only the PAR step in each individual `test()` block with a tampered configuration.

---

## Architecture of the Spec

```
beforeAll
  └── orchestrator.runThroughPar()
        ├── FetchMetadata step  (runs once, resolves issuer metadata)
        └── PAR step            (runs once with valid request → succeeds)
              └── captures: walletAttestationResponse, pushedAuthorizationRequestEndpoint,
                            authorizationServer, credentialIssuer

test("CI_015")  ──► runParStep(withSignJwtOverride(..., signWithWrongKey()))
test("CI_015a") ──► runParStep(withSignJwtOverride(..., signWithMismatchedAlgorithm(...)))
test("CI_015b") ──► runParStep(..., fakeAttestation)
...
test("CI_028c") ──► runParStepWithCustomPop(expiredPopJwt)
```

Each `test()` block is fully independent: it builds a fresh step instance, optionally creates a new PoP JWT, and sends one deviant PAR request. Because the shared context is immutable after `beforeAll`, tests do not interfere with each other.

---

## Step 1 — Register the Test Suite

```typescript
import { defineIssuanceTest } from "#/config/test-metadata";
// ...other imports...

const testConfigs = await defineIssuanceTest("PARValidation");
```

`defineIssuanceTest("PARValidation")` reads `config.ini`, applies any `[steps_mapping]` override for `"PARValidation"`, and returns one `IssuerTestConfiguration` per `credential_types[]` entry. The string `"PARValidation"` is arbitrary — it becomes the suite name in test output.

---

## Step 2 — Run the Flow Up to PAR

Inside the `testConfigs.forEach(...)` callback:

```typescript
testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] PAR Request Object Validation`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let walletAttestationResponse: AttestationResponse;
    let pushedAuthorizationRequestEndpoint: string;
    let authorizationServer: string;
    let credentialIssuer: string;

    beforeAll(async () => {
      const ctx = await orchestrator.runThroughPar();

      walletAttestationResponse        = ctx.walletAttestationResponse;
      authorizationServer              = ctx.authorizationServer;
      pushedAuthorizationRequestEndpoint = ctx.pushedAuthorizationRequestEndpoint;
      credentialIssuer                 = ctx.credentialIssuer;
    });

    useTestSummary(baseLog, testConfig.name);

    afterEach(() => {
      vi.useRealTimers(); // guard against leaked fake timers
    });
```

`runThroughPar()` executes **FetchMetadata → PAR** using the valid default step classes. The context it returns contains everything needed to invoke the PAR step again manually:

| Field | Description |
|---|---|
| `walletAttestationResponse` | Wallet attestation JWT + key pairs |
| `authorizationServer` | `iss` from the issuer entity statement |
| `pushedAuthorizationRequestEndpoint` | URL of the PAR endpoint |
| `credentialIssuer` | Base URL of the credential issuer |

> **Important:** `runThroughPar()` starts the flow from scratch. Do **not** call it more than once per test suite — both calls would re-issue a PAR request, and subsequent steps may break because the authorization server would see a duplicate.

---

## Step 3 — Define the `runParStep` Helper

Rather than repeating the step setup in every test, define a local helper:

```typescript
async function runParStep(
  StepClass: typeof PushedAuthorizationRequestDefaultStep,
  attestationOverride?: Omit<AttestationResponse, "created">,
): Promise<PushedAuthorizationRequestResponse> {
  const config = loadConfigWithHierarchy();
  const freshPop = await createFreshPop({
    authorizationServer,
    walletAttestationResponse,
  });
  const step = new StepClass(config, createQuietLogger());
  return step.run({
    baseUrl: config.issuance.url,
    clientId: walletAttestationResponse.unitKey.publicKey.kid,
    credentialConfigurationIds: [testConfig.credentialConfigurationId],
    popAttestation: freshPop,
    pushedAuthorizationRequestEndpoint,
    walletAttestation: attestationOverride ?? walletAttestationResponse,
  });
}
```

Key design decisions:

- **`createFreshPop()`** — generates a new OAuth-Client-Attestation-PoP JWT on every call. PoP JWTs have a short TTL (~60 s); reusing the one captured in `beforeAll` would cause spurious failures in later tests.
- **`createQuietLogger()`** — suppresses step-internal log output to keep test output clean. Use `baseLog.withTag("CI_015")` only for the test-level log lines you explicitly write.
- **`attestationOverride`** — allows substituting a fake `AttestationResponse` without changing the step class (used in CI_015b).

---

## Step 4 — Write Negative Tests

All negative tests follow the same skeleton:

```typescript
test("CI_XXX: Short Title | Human-readable description of what is being tested", async () => {
  const log = baseLog.withTag("CI_XXX");
  const DESCRIPTION = "Issuer correctly rejected ...";

  log.start("Conformance test: ...");

  let testSuccess = false;
  try {
    // 1. Build the deviant step or prepare tampered data
    // 2. Call runParStep() (or the appropriate helper)
    // 3. Assert result.success === false
    testSuccess = true;
  } finally {
    log.testCompleted(DESCRIPTION, testSuccess);
  }
});
```

The sections below cover each technique used in the spec.

---

### Technique A — Override the JWT Signing Callback (`withSignJwtOverride`)

Use this when you need to change *how* the Request Object JWT is signed. `withSignJwtOverride` returns a new step class with the `signJwt` callback replaced — all other callbacks (`generateRandom`, `hash`) are preserved.

**Import:**
```typescript
import {
  signWithWrongKey,
  signWithMismatchedAlgorithm,
  signWithWrongKid,
  signThenTamperPayload,
  signWithHS256,
  signWithCustomIss,
  withSignJwtOverride,
} from "#/helpers/par-validation-helpers";
```

#### CI_015 — Sign with a completely different key

```typescript
test("CI_015: Request Object Signature Validation | ...", async () => {
  const log = baseLog.withTag("CI_015");
  let testSuccess = false;
  try {
    const result = await runParStep(
      withSignJwtOverride(
        testConfig.pushedAuthorizationRequestStepClass,
        signWithWrongKey(),
      ),
    );
    expect(result.success).toBe(false);
    testSuccess = true;
  } finally {
    log.testCompleted("Issuer correctly rejected PAR with invalid signature", testSuccess);
  }
});
```

`signWithWrongKey()` generates a fresh EC key pair with no relation to the wallet attestation and signs the JWT with it. The issuer must reject because the signature does not verify against the public key declared in the wallet attestation.

#### CI_015a — Declare one algorithm, sign with another

```typescript
const result = await runParStep(
  withSignJwtOverride(
    testConfig.pushedAuthorizationRequestStepClass,
    signWithMismatchedAlgorithm("ES256", "ES384"),
  ),
);
```

`signWithMismatchedAlgorithm(headerAlg, signAlg)` sets `alg: "ES256"` in the JWT header but actually signs with an ES384 key. A compliant issuer must use the declared `alg` header for validation (per RFC 9126/9101) and reject the JWT because the signature does not verify.

#### CI_015c — Wrong `kid` in the header

```typescript
const result = await runParStep(
  withSignJwtOverride(
    testConfig.pushedAuthorizationRequestStepClass,
    signWithWrongKid(
      "wrong-kid-that-does-not-match",
      walletAttestationResponse.unitKey.privateKey,
      walletAttestationResponse.unitKey.publicKey,
    ),
  ),
);
```

`signWithWrongKid(kid, privateKey, publicKey)` uses the real key to sign but injects `kid: "wrong-kid-that-does-not-match"` in the JWS protected header. The issuer must reject because the `kid` does not match the wallet attestation public key.

#### CI_015d — Tamper the payload after signing

```typescript
const result = await runParStep(
  withSignJwtOverride(
    testConfig.pushedAuthorizationRequestStepClass,
    signThenTamperPayload(
      walletAttestationResponse.unitKey.privateKey,
      walletAttestationResponse.unitKey.publicKey,
      "aud",
      "https://tampered.example.com",
    ),
  ),
);
```

`signThenTamperPayload(privateKey, publicKey, field, value)` signs the JWT normally, then base64url-decodes the payload, mutates one claim, re-encodes it, and reassembles the compact JWS — without re-signing. The signature is now cryptographically invalid.

#### CI_019 — Use a symmetric algorithm (HS256)

```typescript
const result = await runParStep(
  withSignJwtOverride(
    testConfig.pushedAuthorizationRequestStepClass,
    signWithHS256("conformance-test-hmac-value"),
  ),
);
```

HS256 is a symmetric algorithm forbidden by the IT-Wallet spec. The issuer must reject any PAR signed with it.

#### CI_021 — Inject a custom `iss` claim

```typescript
const result = await runParStep(
  withSignJwtOverride(
    testConfig.pushedAuthorizationRequestStepClass,
    signWithCustomIss(
      "https://attacker.example.com",
      walletAttestationResponse.unitKey.privateKey,
      walletAttestationResponse.unitKey.publicKey,
    ),
  ),
);
```

`signWithCustomIss(iss, privateKey, publicKey)` signs with the real key but overwrites the `iss` claim in the payload. The issuer must reject because `iss` must equal `client_id` (RFC 9101 §4).

---

### Technique B — Override PAR Request Options (`withParOverrides`)

Use this when you need to change a field in the PAR request *body* (not the JWT signing logic). `withParOverrides` spreads `Partial<CreatePushedAuthorizationRequestOptions>` over the computed defaults.

**Import:**
```typescript
import { withParOverrides } from "#/helpers/par-validation-helpers";
```

#### CI_020 — Mismatched `client_id` in POST body vs. JWT claim

```typescript
const result = await runParStep(
  withParOverrides(testConfig.pushedAuthorizationRequestStepClass, {
    clientId: "mallory_client_id_that_does_not_match",
  }),
);
```

The step sends the normal JWT (with `client_id` equal to the wallet attestation `kid`) but sets a *different* `client_id` in the POST body. The issuer must detect the mismatch and reject.

#### CI_022 — Wrong `aud` claim

```typescript
const result = await runParStep(
  withParOverrides(testConfig.pushedAuthorizationRequestStepClass, {
    audience: "https://wrong.example.com",
  }),
);
```

The `aud` claim in the Request Object must match the issuer's own identifier. Overriding it with an arbitrary URL forces the issuer to reject.

#### CI_024 — Missing `redirectUri`

```typescript
const result = await runParStep(
  withParOverrides(testConfig.pushedAuthorizationRequestStepClass, {
    // Intentionally cast: we need to send an absent redirectUri to verify
    // the issuer enforces this mandatory parameter (CI_024).
    redirectUri: undefined as unknown as string,
  }),
);
```

`redirectUri` is a mandatory PAR parameter. The cast is intentional: sending `undefined` exercises the issuer's parameter validation.

#### CI_027 — Replay attack (fixed `jti`)

```typescript
const FIXED_JTI = `conformance-test-jti-${crypto.randomUUID()}`;

const StepClass = withParOverrides(
  testConfig.pushedAuthorizationRequestStepClass,
  { jti: FIXED_JTI },
);

// First request — must succeed (server caches the jti)
const firstResult = await runParStep(StepClass);
expect(firstResult.success).toBe(true);

// Second request with the same jti — must be rejected
const secondResult = await runParStep(StepClass);
expect(secondResult.success).toBe(false);
```

`withParOverrides({ jti })` pins the JWT ID to a fixed value. The first request succeeds and the server caches the `jti`. The second request with the identical `jti` must be rejected as a replay.

> A random UUID suffix ensures the `jti` is globally unique per test run, so parallel runs do not interfere with each other.

---

### Technique C — Fake Wallet Attestation (`createFakeAttestationResponse`)

Use this when you need to test that the issuer validates the *trust chain* embedded in the wallet attestation.

**Import:**
```typescript
import { createFakeAttestationResponse } from "#/helpers/par-validation-helpers";
```

#### CI_015b — Attestation signed by an unregistered key

```typescript
const fakeAttestation = await createFakeAttestationResponse();

const result = await runParStep(
  testConfig.pushedAuthorizationRequestStepClass,
  fakeAttestation, // second argument → attestationOverride in runParStep
);
expect(result.success).toBe(false);
```

`createFakeAttestationResponse()` generates a new EC key pair, builds a minimal wallet-attestation JWT signed by that key, and returns it as an `AttestationResponse`. Because the key is not registered with the local Trust Anchor, the issuer's trust-chain resolution must fail.

The `runParStep` helper accepts an optional `attestationOverride` as its second argument (see Step 3). When provided, it replaces `walletAttestation` in the step options while keeping the normal step class.

---

### Technique D — Fake Timers (`vi.useFakeTimers`)

Use this to test `exp` and `iat` claim validation without actually waiting for tokens to expire.

**Import:**
```typescript
import { afterEach, vi } from "vitest";
```

> Always restore real timers in both the test body **and** the `afterEach` hook (added in the shared setup). A test that crashes before `vi.useRealTimers()` would otherwise leave fake timers active for subsequent tests.

#### CI_025 — Expired `exp` claim

```typescript
test("CI_025: Token Expiration | ...", async () => {
  let testSuccess = false;
  try {
    // Freeze time 10 minutes in the past so the SDK produces an already-expired JWT
    vi.useFakeTimers({ now: Date.now() - 10 * 60 * 1000 });

    const result = await runParStep(testConfig.pushedAuthorizationRequestStepClass);

    vi.useRealTimers();

    expect(result.success).toBe(false);
    testSuccess = true;
  } finally {
    vi.useRealTimers(); // restore even if expect() throws
    log.testCompleted(DESCRIPTION, testSuccess);
  }
});
```

`vi.useFakeTimers({ now: <timestamp> })` replaces the global `Date.now()` with the provided value. The SDK uses the current time when setting `iat` and computing `exp`, so moving the clock 10 minutes into the past produces a JWT whose `exp` is already in the past from the server's perspective.

#### CI_026 — Future `iat` claim

```typescript
vi.useFakeTimers({ now: Date.now() + 10 * 60 * 1000 }); // +10 minutes
```

Advancing the clock forward produces a JWT with `iat` 10 minutes ahead of the real current time, exceeding the server's clock-skew tolerance.

#### CI_026a — Stale `iat` (beyond 5-minute window)

```typescript
vi.useFakeTimers({ now: Date.now() - 6 * 60 * 1000 }); // −6 minutes
```

A JWT issued 6 minutes ago has an `iat` that exceeds the 5-minute acceptance window. This is distinct from CI_025 (`exp` in the past): here the JWT is not technically expired (its `exp` is still in the future) but its `iat` is too old.

---

### Technique E — Custom Fetch Injection (CI_023)

Some negative tests require mutating the HTTP request *after* the SDK has built it. The pattern is to wrap the global `fetch` with a custom function that intercepts and modifies the request body before forwarding it.

#### CI_023 — Inject a `request_uri` parameter (forbidden by RFC 9126)

RFC 9126 §2.1 prohibits combining `request` and `request_uri` in the same PAR request. This test verifies the issuer enforces that restriction.

```typescript
test("CI_023: Request URI Parameter Rejection | ...", async () => {
  // 1. Build a valid PAR request object using the SDK
  const config = loadConfigWithHierarchy();
  const parOptions = {
    audience: config.issuance.url,
    authorization_details: [
      {
        credential_configuration_id: testConfig.credentialConfigurationId,
        type: "openid_credential" as const,
      },
    ],
    callbacks: {
      generateRandom: partialCallbacks.generateRandom,
      hash: partialCallbacks.hash,
      signJwt: signJwtCallback([walletAttestationResponse.unitKey.privateKey]),
    },
    clientId: walletAttestationResponse.unitKey.publicKey.kid,
    codeChallengeMethodsSupported: ["S256"],
    dpop: {
      signer: {
        alg: "ES256" as const,
        method: "jwk" as const,
        publicJwk: walletAttestationResponse.unitKey.publicKey,
      },
    },
    pkceCodeVerifier: "example_code_verifier",
    redirectUri: "https://client.example.org/cb",
    responseMode: "query",
  };

  const signed: PushedAuthorizationRequest =
    await createPushedAuthorizationRequest(parOptions);

  // 2. Wrap global fetch to inject request_uri into the POST body
  const originalFetch = fetch;
  const customFetch: typeof fetch = async (input, init) => {
    if (init?.body != null) {
      const params = new URLSearchParams(init.body.toString());
      params.set("request_uri", "urn:ietf:params:oauth:request_uri:ci-023-test");
      return originalFetch(input, { ...init, body: params.toString() });
    }
    return originalFetch(input, init);
  };

  // 3. Send the request; expect an exception (the library throws on HTTP errors)
  let rejected = false;
  try {
    await fetchPushedAuthorizationResponse({
      callbacks: { fetch: customFetch },
      clientAttestationDPoP: await createFreshPop({ authorizationServer, walletAttestationResponse }),
      pushedAuthorizationRequest: signed,
      pushedAuthorizationRequestEndpoint,
      walletAttestation: walletAttestationResponse.attestation,
    });
  } catch {
    rejected = true;
  }

  expect(rejected).toBe(true);
});
```

Note that this test calls `fetchPushedAuthorizationResponse` directly (from `@pagopa/io-wallet-oauth2`) instead of using the `runParStep` helper, because the custom `fetch` must be wired through the library's own fetch callback parameter.

> Capture `originalFetch` before the monkey-patch so the custom fetch never calls itself recursively.

---

### Technique F — Tampered PoP JWT (`buildTamperedPopJwt`)

The `OAuth-Client-Attestation-PoP` (PoP) header is a separate JWT from the Request Object. Use `buildTamperedPopJwt()` to produce PoP variants with deviant properties.

**Import:**
```typescript
import { buildTamperedPopJwt } from "#/helpers/par-validation-helpers";
```

Because the PoP is passed as a raw string (not through the step class), define a second helper alongside `runParStep`:

```typescript
async function runParStepWithCustomPop(
  customPopAttestation: string,
): Promise<PushedAuthorizationRequestResponse> {
  const config = loadConfigWithHierarchy();
  const step = new testConfig.pushedAuthorizationRequestStepClass(
    config,
    createQuietLogger(),
  );
  return step.run({
    baseUrl: credentialIssuer,
    clientId: walletAttestationResponse.unitKey.publicKey.kid,
    credentialConfigurationIds: [testConfig.credentialConfigurationId],
    popAttestation: customPopAttestation,   // ← injected directly
    pushedAuthorizationRequestEndpoint,
    walletAttestation: walletAttestationResponse,
  });
}
```

#### CI_028a — PoP signed with a wrong key

```typescript
const tamperedPop = await buildTamperedPopJwt({
  authorizationServer,
  clientAttestation: walletAttestationResponse.attestation,
  realUnitKey: walletAttestationResponse.unitKey.privateKey,
  useWrongKey: true, // generate and use a random key instead of the real unit key
});

const result = await runParStepWithCustomPop(tamperedPop);
expect(result.success).toBe(false);
```

#### CI_028b — PoP with a wrong `aud` claim

```typescript
const tamperedPop = await buildTamperedPopJwt({
  authorizationServer,
  clientAttestation: walletAttestationResponse.attestation,
  realUnitKey: walletAttestationResponse.unitKey.privateKey,
  wrongAud: "https://attacker.example.com",
});
```

#### CI_028c — Expired PoP

```typescript
const pastIssuedAt  = new Date(Date.now() - 11 * 60 * 1000);
const pastExpiresAt = new Date(Date.now() - 10 * 60 * 1000);

const tamperedPop = await buildTamperedPopJwt({
  authorizationServer,
  clientAttestation: walletAttestationResponse.attestation,
  expiresAt: pastExpiresAt,
  issuedAt:  pastIssuedAt,
  realUnitKey: walletAttestationResponse.unitKey.privateKey,
});
```

`buildTamperedPopJwt` options summary:

| Option | Type | Effect |
|---|---|---|
| `useWrongKey: true` | `boolean` | Sign with a fresh, unregistered key |
| `wrongAud` | `string` | Override the `aud` claim |
| `expiresAt` | `Date` | Override the `exp` claim |
| `issuedAt` | `Date` | Override the `iat` claim |
| `jti` | `string` | Fix the `jti` (for replay tests) |

---

## Step 5 — Run the Tests

From the `wallet-conformance-test/` directory:

```bash
wct test:issuance \
  --file-ini          ../my-example/config.ini \
  --issuance-tests-dir ../my-example
```

To run only this spec:

```bash
pnpm vitest run ../my-example/my-par-validation.issuance.spec.ts
```

---

## Decision Guide: Which Technique to Use?

| What you want to deviate | Technique | Helper |
|---|---|---|
| Change the JWT signing key | A | `withSignJwtOverride` + `signWithWrongKey()` |
| Declare one alg, sign with another | A | `withSignJwtOverride` + `signWithMismatchedAlgorithm()` |
| Wrong `kid` in JWS header | A | `withSignJwtOverride` + `signWithWrongKid()` |
| Mutate a claim after signing | A | `withSignJwtOverride` + `signThenTamperPayload()` |
| Forbidden algorithm (HS256) | A | `withSignJwtOverride` + `signWithHS256()` |
| Wrong `iss` claim | A | `withSignJwtOverride` + `signWithCustomIss()` |
| Wrong field in PAR POST body | B | `withParOverrides({ field: value })` |
| Missing mandatory parameter | B | `withParOverrides({ param: undefined as unknown as T })` |
| Fixed `jti` for replay tests | B | `withParOverrides({ jti: FIXED_JTI })` |
| Unregistered / fake attestation | C | `createFakeAttestationResponse()` as `attestationOverride` |
| Expired `exp` or future `iat` | D | `vi.useFakeTimers({ now: Date.now() ± offset })` |
| Inject extra field into HTTP body | E | Custom `fetch` wrapper |
| Tampered PoP JWT | F | `buildTamperedPopJwt({ ...options })` + `runParStepWithCustomPop()` |

---

## Additional Resources

- [Issuance Testing Guide](ISSUANCE-TESTING-GUIDE.md) — basic happy-flow spec structure
- [Factory Helpers Guide](FACTORY-HELPERS-GUIDE.md) — full reference for all available helpers
- [Step Outputs Reference](STEP-OUTPUTS.md) — response structures for each step
- [IT Wallet Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html)
