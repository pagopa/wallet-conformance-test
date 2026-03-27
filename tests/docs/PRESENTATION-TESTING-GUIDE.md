# Presentation Testing Guide for External Users

This guide walks you through writing and running **presentation conformance tests** for a Relying Party (Verifier) from outside the `wallet-conformance-test` repository.

You will keep your own test code in a separate folder (`my-example/`) alongside the cloned repository, so that you can update the tool independently of your tests.

---

## Prerequisites

- **Node.js ≥ 22.19.0** — [download](https://nodejs.org/en/about/previous-releases)
- **pnpm 10.x** — install with `npm install -g pnpm`
- **Valid credentials** from a Credential Issuer (e.g., SD-JWT, mDOC)

---

## Expected Folder Structure

After following this guide you will have the following layout:

```
my-test/
├── wallet-conformance-test/   ← cloned repository (do not edit)
└── my-example/                ← your test workspace
    ├── config.ini             ← your presentation configuration
    ├── my-test.presentation.spec.ts  ← your test spec
    └── steps/                 ← (optional) custom step overrides
        └── my-redirect-step.ts
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

The `config.example.ini` template includes all available options (wallet configuration, trust
anchors, logging, network timeouts, etc.) with sensible defaults. You only need to change what
differs from the example.


---

## Step 3 — Write Your First Test Spec

Create `my-test/my-example/my-test.presentation.spec.ts`.

The imports below use the path aliases defined by the tool (`#/` → `tests/`, `@/` → `src/`).
They always resolve correctly as long as you run `wct` from the `wallet-conformance-test/`
directory (see Step 4).

```typescript
/* eslint-disable max-lines-per-function */

import { definePresentationTest } from "#/config/test-metadata";
import { useTestSummary } from "#/helpers/use-test-summary";
import { beforeAll, describe, expect, test } from "vitest";

import { WalletPresentationOrchestratorFlow } from "@/orchestrator";
import type {
  AuthorizationRequestStepResponse,
  RedirectUriStepResponse,
} from "@/step/presentation";

// Top-level await is valid in the Vitest ESM context.
// @ts-expect-error TS1309
const testConfig = await definePresentationTest("MyPresentationTest");

describe(`[${testConfig.name}] My Presentation Tests`, () => {
  const orchestrator = new WalletPresentationOrchestratorFlow(testConfig);
  const baseLog = orchestrator.getLog();

  let authorizationRequestResult: AuthorizationRequestStepResponse;
  let redirectUriResult: RedirectUriStepResponse;

  // Run the full presentation flow once before all assertions.
  beforeAll(async () => {
    ({ authorizationRequestResult, redirectUriResult } =
      await orchestrator.presentation());
  });

  // Register the summary hook (prints pass/fail counts after the suite).
  useTestSummary(baseLog, testConfig.name);

  // ── Individual test cases ───────────────────────────────────────────────

  test("CP_001 — authorization request is parsed successfully", async () => {
    let testSuccess = false;
    try {
      expect(
        authorizationRequestResult.success,
        "authorization request parsing must succeed",
      ).toBe(true);
      testSuccess = true;
    } finally {
      baseLog.testCompleted("CP_001", testSuccess);
    }
  });

  test("CP_002 — VP token is created and included in response", async () => {
    let testSuccess = false;
    try {
      expect(
        authorizationRequestResult.response?.authorizationResponse.authorizationResponsePayload.vp_token,
        "VP token must be present in authorization response",
      ).toBeDefined();
      testSuccess = true;
    } finally {
      baseLog.testCompleted("CP_002", testSuccess);
    }
  });

  test("CP_003 — authorization response is sent to verifier", async () => {
    let testSuccess = false;
    try {
      expect(
        authorizationRequestResult.response?.responseUri,
        "response URI must be set",
      ).toBeDefined();
      testSuccess = true;
    } finally {
      baseLog.testCompleted("CP_003", testSuccess);
    }
  });

  test("CP_004 — verifier accepts presentation", async () => {
    let testSuccess = false;
    try {
      expect(
        redirectUriResult.success,
        "redirect response must be successful",
      ).toBe(true);

      // Presentation was accepted if response code is present
      const isAccepted =
        redirectUriResult.response?.responseCode !== undefined;
      expect(isAccepted, "verifier should return a response code").toBe(true);

      testSuccess = true;
    } finally {
      baseLog.testCompleted("CP_004", testSuccess);
    }
  });

  test("CP_005 — response code is valid", async () => {
    let testSuccess = false;
    try {
      if (redirectUriResult.response?.responseCode) {
        expect(
          redirectUriResult.response.responseCode.length,
          "response code must be a non-empty string",
        ).toBeGreaterThan(0);
        testSuccess = true;
      } else {
        // If presentation was declined, skip this test
        testSuccess = true;
      }
    } finally {
      baseLog.testCompleted("CP_005", testSuccess);
    }
  });
});
```

### What happens when this test runs

1. `definePresentationTest("MyPresentationTest")` reads `config.ini` and creates one
   `PresentationTestConfiguration`.
2. The `WalletPresentationOrchestratorFlow` executes the full presentation flow:
   **Fetch RP Metadata → Authorization Request → Build VP Token → Send Authorization Response → Redirect**.
3. The `beforeAll` block stores the step responses; each `test()` block asserts on them.

### Exploring Response Attributes

To understand the structure and attributes of the various step responses
(`AuthorizationRequestStepResponse` and  `RedirectUriStepResponse`), see
[STEP-OUTPUTS.md](STEP-OUTPUTS.md) for a detailed reference guide.

---

## Step 4 — Run the Tests

All `wct` commands must be run from the **`wallet-conformance-test/` directory** because the
TypeScript path aliases (`#/`, `@/`) are resolved relative to that project root.

```bash
cd my-test/wallet-conformance-test

wct test:presentation \
  --file-ini           ../my-example/config.ini \
  --presentation-tests-dir ../my-example
  --presentation-authorize-uri 'https://your-verifier.example.com/authorize?....'
```

`--presentation-authorize-uri` point to your authorize url Relying Party (Verifier) (generally url included in QR code).

> **`--presentation-authorize-uri`** is mandatory. If it is missing, `definePresentationTest()` will
> throw an error when you run the tests.

| Option | Description |
|---|---|
| `--file-ini <path>` | Path to your `config.ini`, relative to `wallet-conformance-test/` |
| `--presentation-tests-dir <path>` | Directory where Vitest looks for `*.presentation.spec.ts` files |
| `--presentation-authorize-uri <uri>` | presentation authorize URL |

> Both paths are resolved relative to `wallet-conformance-test/` (your current working directory).
> The `../my-example` examples above work because `my-example/` is a sibling of
> `wallet-conformance-test/` inside `my-test/`.

---

## Step 5 — Override a Single Step (Advanced)

By default every step uses the built-in **happy-flow** implementation. To override one or more
steps — for example to inject a wrong value and test a negative case — extend the corresponding
`*DefaultStep` class.

### 5a. Write a custom step

```typescript
// my-test/my-example/steps/my-redirect-step.ts

import type {
  RedirectUriStepResponse,
  RedirectUriOptions,
} from "@/step/presentation";
import { RedirectUriDefaultStep } from "@/step/presentation";

export class MyRedirectStep extends RedirectUriDefaultStep {
  override async run(
    options: RedirectUriOptions,
  ): Promise<RedirectUriStepResponse> {
    const log = this.log.withTag(this.tag);
    log.debug("Custom Redirect URI step");

    return this.execute(async () => {
      // Your custom logic here.
      // Call super.run(options) to reuse the default behaviour
      // and only post-process the result.
      return super.run(options);
    });
  }
}
```

The class **must** extend one of the base classes listed in the table below. The auto-discovery
system identifies the correct configuration slot by walking the prototype chain.

| Base class | Flow slot |
|---|---|
| `FetchMetadataVpDefaultStep` | Fetch RP metadata |
| `AuthorizationRequestDefaultStep` | Authorization request & VP token creation |
| `RedirectUriDefaultStep` | Send authorization response to verifier |

All base classes are exported from `@/step/presentation`.

### 5b. Register the steps directory in `config.ini`

Add a `[steps_mapping]` section that maps your test flow name to the folder containing your
custom step files. The path is relative to `wallet-conformance-test/`.

```ini
[steps_mapping]
; Format: FlowName = path/to/steps/directory  (relative to wallet-conformance-test/)
MyPresentationTest = ../my-example/steps
```

The flow name (`MyPresentationTest`) must match the string passed to `definePresentationTest()` in
your spec file.

### 5c. How auto-discovery works

When `definePresentationTest("MyPresentationTest")` is called:

1. The loader reads `steps_mapping["MyPresentationTest"]` from `config.ini`.
2. It scans all `*.ts` files in that directory (excluding `*.spec.ts`).
3. For each exported class it walks the prototype chain to find which `*DefaultStep` it extends.
4. The matched class is injected into that slot; every unmatched slot falls back to the built-in
   default.

No registration boilerplate is needed — adding a file to the directory is enough.

At startup you will see log output in console:

```bash
[test-metadata] ℹ steps_mapping: resolved 'MyPresentationTest' -> /Users/pippo/../my-example/steps
```

---

## Step 6 — Advanced: Handling Declined Presentations

The wallet may decline a presentation request in certain scenarios (e.g., user rejects, credentials
don't match requirements). You can test both acceptance and rejection flows:

```typescript
test("CP_006 — handle declined presentation gracefully", async () => {
  let testSuccess = false;
  try {
    // When presentation is declined, redirectUri and responseCode are undefined
    const isDeclined =
      redirectUriResult.response?.responseCode === undefined &&
      redirectUriResult.response?.redirectUri === undefined;

    const isAccepted =
      redirectUriResult.response?.responseCode !== undefined;

    // Test should pass if request succeeded regardless of accept/decline
    expect(
      redirectUriResult.success,
      "redirect step must complete successfully",
    ).toBe(true);

    expect(
      isDeclined || isAccepted,
      "presentation result must be either accepted or declined",
    ).toBe(true);

    testSuccess = true;
  } finally {
    baseLog.testCompleted("CP_006", testSuccess);
  }
});
```

Check [STEP-OUTPUTS.md](./STEP-OUTPUTS.md#redirecturidefaultstep) for the full response structure.

---

## Step 7 — Negative Tests with Custom Steps (Advanced)

For tests that require a deviant response (e.g., malformed VP token, missing signature), create a
custom step class that modifies the response after the default behavior:

```typescript
// my-test/my-example/steps/my-auth-request-step.ts

import type {
  AuthorizationRequestStepResponse,
  AuthorizationRequestOptions,
} from "@/step/presentation";
import { AuthorizationRequestDefaultStep } from "@/step/presentation";

export class MalformedVpTokenStep extends AuthorizationRequestDefaultStep {
  override async run(
    options: AuthorizationRequestOptions,
  ): Promise<AuthorizationRequestStepResponse> {
    return this.execute(async () => {
      const result = await super.run(options);

      // Tamper with the VP token for negative testing
      if (result.response?.authorizationResponse.vpToken) {
        result.response.authorizationResponse.vpToken = "malformed.token.here";
      }

      return result;
    });
  }
}
```

Then register it in `steps/` as described in Step 5b — the auto-discovery mechanism will inject the custom step automatically when `definePresentationTest()` is called.

---

## Additional Resources

- [Step Outputs Reference](./STEP-OUTPUTS.md) — detailed output structure for each presentation step
- [Test Configuration Guide](../tests/TEST-CONFIGURATION-GUIDE.md) — full reference for
  auto-discovery and config options
- [Test Configuration Guide – Presentation](../tests/TEST-CONFIGURATION-GUIDE.md#presentation-configuration) —
  presentation-specific settings
- [IT Wallet Documentation](https://italia.github.io/eid-wallet-it-docs/)
- [Relying Party Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-relying-party.html)
