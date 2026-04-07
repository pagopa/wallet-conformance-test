# Issuance Testing Guide for External Users

This guide walks you through writing and running **issuance conformance tests** for a Credential Issuer from outside the `wallet-conformance-test` repository.

You will keep your own test code in a separate folder (`my-example/`) alongside the cloned repository, so that you can update the tool independently of your tests.

---

## Prerequisites

- **Node.js ≥ 22.19.0** — [download](https://nodejs.org/en/about/previous-releases)
- **pnpm 10.x** — install with `npm install -g pnpm`

---

## Expected Folder Structure

After following this guide you will have the following layout:

```
my-test/
├── wallet-conformance-test/   ← cloned repository (do not edit)
└── my-example/                ← your test workspace
    ├── config.ini             ← your issuance configuration
    ├── my-test.issuance.spec.ts  ← your test spec
    └── steps/                 ← (optional) custom step overrides
        └── my-token-step.ts
```

---

## Step 1 — Install the Tool

Clone the repository and install it globally so that the `wct` command is available from anywhere.

```bash
# From inside my-test/
git clone https://github.com/pagopa/wallet-conformance-test
cd wallet-conformance-test
pnpm install
pnpm install -g
```

Verify the installation:

```bash
wct --version
```

> **Tip — command not found?** If `wct` is not on your PATH after the global install, run the
> following from `my-test/wallet-conformance-test/`:
>
> ```bash
> chmod +x ./bin/wct
> pnpm link --global
> ```

---

## Step 2 — Create Your Configuration File

Copy the `config.example.ini` from the repository into your workspace and customize it:

```bash
cp wallet-conformance-test/config.example.ini my-example/config.ini
```

Then edit `my-example/config.ini` to point to your Credential Issuer. Uncomment and update at
minimum these fields under the `[issuance]` section:

```ini
[issuance]
; URL of your Credential Issuer
url = https://your-issuer.example.com

; One or more credential configuration IDs to test.
; The test suite runs once per entry — add as many as you need.
credential_types[] = dc_sd_jwt_YourCredentialType
```

The `config.example.ini` template includes all available options (wallet configuration, trust
anchors, logging, network timeouts, etc.) with sensible defaults. You only need to change what
differs from the example.

> **`credential_types[]`** is mandatory. If it is missing or empty, `defineIssuanceTest()` will
> throw an error when you run the tests.

---

## Step 3 — Write Your First Test Spec

Create `my-test/my-example/my-test.issuance.spec.ts`.

The imports below use the path aliases defined by the tool (`#/` → `tests/`, `@/` → `src/`).
They always resolve correctly as long as you run `wct` from the `wallet-conformance-test/`
directory (see Step 4).

> **Before you write tests**, consult [STEP-OUTPUTS.md](STEP-OUTPUTS.md) to understand the full
> response structure of each step (`FetchMetadataStepResponse`, `PushedAuthorizationRequestResponse`,
> `AuthorizeStepResponse`, `TokenRequestResponse`, and `CredentialRequestResponse`). 
> Knowing what fields are available will help you write meaningful assertions.

```typescript
/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { useTestSummary } from "#/helpers/use-test-summary";
import { beforeAll, describe, expect, test } from "vitest";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import type {
  CredentialRequestResponse,
  TokenRequestResponse,
} from "@/step/issuance";

// Top-level await is valid in the Vitest ESM context.
// @ts-expect-error TS1309
const testConfigs = await defineIssuanceTest("MyIssuanceTest");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] My Issuance Tests`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let tokenResponse: TokenRequestResponse;
    let credentialResponse: CredentialRequestResponse;

    // Run the full issuance flow once before all assertions.
    beforeAll(async () => {
      ({ tokenResponse, credentialResponse } = await orchestrator.issuance());
    });

    // Register the summary hook (prints pass/fail counts after the suite).
    useTestSummary(baseLog, testConfig.name);

    // ── Individual test cases ─────────────────────────────────────────────

    test("CI_001 — token response contains access_token", async () => {
      let testSuccess = false;
      try {
        expect(
          tokenResponse.response?.access_token,
          "access_token must be present in the token response",
        ).toBeDefined();
        testSuccess = true;
      } finally {
        baseLog.testCompleted("CI_001", testSuccess);
      }
    });

    test("CI_002 — credential response is successful", async () => {
      let testSuccess = false;
      try {
        expect(
          credentialResponse.success,
          "credential request must succeed",
        ).toBe(true);
        testSuccess = true;
      } finally {
        baseLog.testCompleted("CI_002", testSuccess);
      }
    });
  });
});
```

### What happens when this test runs

1. `defineIssuanceTest("MyIssuanceTest")` reads `config.ini` and returns one
   `IssuerTestConfiguration` per `credential_types[]` entry.
2. For each configuration, a `WalletIssuanceOrchestratorFlow` executes the full issuance flow:
   **PAR → Authorize → Token → Nonce → Credential**.
3. The `beforeAll` block stores the step responses; each `test()` block asserts on them.

### Exploring Response Attributes

To understand the structure and attributes of the various step responses
(`TokenRequestResponse`, `CredentialRequestResponse`, etc.), see
[STEP-OUTPUTS.md](STEP-OUTPUTS.md) for a detailed reference guide.

---

## Step 4 — Run the Tests

All `wct` commands must be run from the **`wallet-conformance-test/` directory** because the
TypeScript path aliases (`#/`, `@/`) are resolved relative to that project root.

```bash
cd my-test/wallet-conformance-test

wct test:issuance \
  --file-ini          ../my-example/config.ini \
  --issuance-tests-dir ../my-example
```

| Option | Description |
|---|---|
| `--file-ini <path>` | Path to your `config.ini`, relative to `wallet-conformance-test/` |
| `--issuance-tests-dir <path>` | Directory where Vitest looks for `*.issuance.spec.ts` files |

> Both paths are resolved relative to `wallet-conformance-test/` (your current working directory).
> The `../my-example` examples above work because `my-example/` is a sibling of
> `wallet-conformance-test/` inside `my-test/`.

---

## Step 5 — Test Multiple Credential Types

To run the same test suite against several credential types, simply list them all in `config.ini`.
The system creates one independent test suite per entry:

```ini
[issuance]
url = https://issuer.example.com
credential_types[] = dc_sd_jwt_PersonIdentificationData
credential_types[] = dc_sd_jwt_DrivingLicense
credential_types[] = dc_sd_jwt_EuropeanDisabilityCard
```

Each `describe` block in your spec will execute three times, once per type.

---

## Step 6 — Customize Step Behavior (Advanced)

By default every step uses the built-in **happy-flow** implementation. There are two approaches
to customize or override steps:

1. **Write a custom step class** — Extend the corresponding `*DefaultStep` class for complete
   control over step logic. Use this when you need complex custom behavior.

2. **Use factory helpers** — Apply quick modifications (e.g., override a single parameter or
   signing key) without writing a full step class. Use this for simple variations like negative
   tests.

For detailed guidance, implementation examples, and a complete catalogue of available factory
helpers, see [FACTORY-HELPERS-GUIDE.md](FACTORY-HELPERS-GUIDE.md).

---

## Additional Resources

- [PAR Validation Testing Guide](PAR-VALIDATION-TESTING-GUIDE.md) — step-by-step walkthrough
  of `par-validation.issuance.spec.ts`; use as a template for negative-test specs
- [Test Configuration Guide](TEST-CONFIGURATION-GUIDE.md) — full reference for the
  auto-discovery system, config options, and all available helpers
- [IT Wallet Documentation](https://italia.github.io/eid-wallet-it-docs/)
- [Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html)
