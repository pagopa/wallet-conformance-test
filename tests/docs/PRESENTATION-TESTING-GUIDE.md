# Presentation Testing Guide for External Users

This guide walks you through writing and running **presentation conformance tests** for a Relying Party (Verifier) from outside the `wallet-conformance-test` repository.

You will keep your own test code in a separate folder (`my-example/`) alongside the cloned repository, so that you can update the tool independently of your tests.

---

## Overview

The presentation flow simulates a wallet presenting a credential to a Relying Party (RP / Verifier). The tool:

1. Fetches the RP's federation metadata.
2. Parses the authorization request (the URL normally encoded in a QR code).
3. Builds a VP (Verifiable Presentation) token from the locally available credentials.
4. Sends the authorization response to the RP's `response_uri`.
5. Follows the redirect and collects the `response_code`.

The credentials available for presentation include the **auto-generated mock PID** (`dc_sd_jwt_PersonIdentificationData`) and any credentials saved during previous issuance test runs.

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

### `authorize_request_url` — static URL

The simplest approach: paste the full authorization request URL directly into `config.ini`.

```ini
[presentation]
authorize_request_url = https://rp.example.com/auth?client_id=https://rp.example.com&request_uri=https://rp.example.com/auth/request/abc123&state=abc123
```

> **Limitation**: Most Relying Parties generate a **fresh URL per session**, so a static URL
> typically expires after one use. The full presentation suite runs several spec files
> (`happy`, `authorization-request`, `redirect-uri`), each of which executes the orchestrator
> flow independently — meaning the same URL would be consumed on the first spec and already
> expired by the time the next one runs.
>
> A static `authorize_request_url` is therefore only reliable when you limit the run to the
> **happy flow test alone**:
>
> ```bash
> wct test:presentation --tests HappyFlowPresentation
> ```
>
> For any other scenario — running the full suite or automating in CI — use
> [`authorize_request_script`](#authorize_request_script--dynamic-url-via-script) instead, so
> a fresh URL is fetched before each spec.

### `authorize_request_script` — dynamic URL via script

When the RP creates a new authorization request on every run (the standard case), configure a
script that calls the RP's API and prints the resulting URL to `stdout`. The tool
executes this script before each test run and uses the URL it outputs. The script must be executable and can be any kind of script (bash, Python, Node.js, etc.) as long as it meets the contract below.

```ini
[presentation]
authorize_request_script = ./tests/scripts/presentation.example.sh
```

Contract for the script:

| Requirement    | Detail                                                               |
| -------------- | -------------------------------------------------------------------- |
| **Executable** | The file must be executable (`chmod +x`).                            |
| **Stdout**     | Print exactly one line: the full authorization request URL.          |
| **Exit code**  | Exit `0` on success; any non-zero exit code is treated as a failure. |
| **Timeout**    | The tool waits up to **15 seconds** for the script to complete.      |
| **Stderr**     | Written to the tool's own stderr for debugging; not parsed.          |

#### Example script

The repository ships a ready-to-use example at [`tests/scripts/presentation.example.sh`](../tests/scripts/presentation.example.sh).

### Mutual exclusivity

`authorize_request_url` and `authorize_request_script` are **mutually exclusive**. If both are
set, `authorize_request_script` takes precedence. You must provide at least one of them.

### Optional settings

```ini
[presentation]
# Optional: explicit RP Verifier base URL when the federation metadata
# domain differs from the authorize_request_url domain.
verifier = https://rp.example.com
```

---

## Step 3 — Write Your First Test Spec

Create `my-test/my-example/my-test.presentation.spec.ts`.

The imports below use the path aliases defined by the tool (`#/` → `tests/`, `@/` → `src/`).
They always resolve correctly as long as you run `wct` from the `wallet-conformance-test/`
directory (see Step 4).

> **Before you write tests**, consult [STEP-OUTPUTS.md](STEP-OUTPUTS.md) to understand the full
> response structure of each step (`FetchMetadataVpStepResponse`,
> `AuthorizationRequestStepResponse`, and `RedirectUriStepResponse`). Knowing what fields are
> available will help you write meaningful assertions.

```typescript
/* eslint-disable max-lines-per-function */

import { definePresentationTest } from "#/config/test-metadata";
import { useTestSummary } from "#/helpers/use-test-summary";
import { beforeAll, describe, expect, test } from "vitest";

import { WalletPresentationOrchestratorFlow } from "@/orchestrator";
import type {
  AuthorizationRequestStepResponse,
  FetchMetadataVpStepResponse,
  RedirectUriStepResponse,
} from "@/step/presentation";

// Top-level await is valid in the Vitest ESM context.
// @ts-expect-error TS1309
const testConfig = await definePresentationTest("MyPresentationTest");

describe(`[${testConfig.name}] My Presentation Tests`, () => {
  const orchestrator = new WalletPresentationOrchestratorFlow(testConfig);
  const baseLog = orchestrator.getLog();

  let fetchMetadataResult: FetchMetadataVpStepResponse;
  let authorizationRequestResult: AuthorizationRequestStepResponse;
  let redirectUriResult: RedirectUriStepResponse;

  // Run the full presentation flow once before all assertions.
  beforeAll(async () => {
    ({ fetchMetadataResult, authorizationRequestResult, redirectUriResult } =
      await orchestrator.presentation());
  });

  // Register the summary hook (prints pass/fail counts after the suite).
  useTestSummary(baseLog, testConfig.name);

  // ── Individual test cases ───────────────────────────────────────────────

  test("RPR_001 — authorization request is parsed successfully", async () => {
    let testSuccess = false;
    try {
      expect(
        authorizationRequestResult.success,
        "authorization request parsing must succeed",
      ).toBe(true);
      testSuccess = true;
    } finally {
      baseLog.testCompleted("RPR_001", testSuccess);
    }
  });

  test("RPR_002 — VP token is created and included in response", async () => {
    let testSuccess = false;
    try {
      expect(
        authorizationRequestResult.response?.authorizationResponse
          .authorizationResponsePayload.vp_token,
        "VP token must be present in authorization response",
      ).toBeDefined();
      testSuccess = true;
    } finally {
      baseLog.testCompleted("RPR_002", testSuccess);
    }
  });

  test("RPR_003 — authorization response is sent to verifier", async () => {
    let testSuccess = false;
    try {
      expect(
        authorizationRequestResult.response?.responseUri,
        "response URI must be set",
      ).toBeDefined();
      testSuccess = true;
    } finally {
      baseLog.testCompleted("RPR_003", testSuccess);
    }
  });

  test("RPR_004 — verifier accepts presentation", async () => {
    let testSuccess = false;
    try {
      expect(
        redirectUriResult.success,
        "redirect response must be successful",
      ).toBe(true);

      // Presentation was accepted if response code is present
      const isAccepted = redirectUriResult.response?.responseCode !== undefined;
      expect(isAccepted, "verifier should return a response code").toBe(true);

      testSuccess = true;
    } finally {
      baseLog.testCompleted("RPR_004", testSuccess);
    }
  });

  test("RPR_005 — response code is valid", async () => {
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
      baseLog.testCompleted("RPR_005", testSuccess);
    }
  });
});
```

### What happens when this test runs

1. `definePresentationTest("MyPresentationTest")` reads `config.ini` and creates one
   `PresentationTestConfiguration`.
2. The `WalletPresentationOrchestratorFlow` executes the full presentation flow:
   **Fetch RP Metadata → Authorization Request → Build VP Token → Send Authorization Response → Redirect**.
3. The `beforeAll` block stores the three step responses; each `test()` block asserts on them.

---

## Step 4 — Run the Tests

All `wct` commands must be run from the **`wallet-conformance-test/` directory** because the
TypeScript path aliases (`#/`, `@/`) are resolved relative to that project root.

```bash
cd my-test/wallet-conformance-test
```

### Using `config.ini`

When `authorize_request_url` or `authorize_request_script` is already set in `config.ini`, no
extra flags are needed:

```bash
# Static URL (from config.ini)
wct test:presentation --file-ini ../my-example/config.ini --presentation-tests-dir ../my-example

# Dynamic URL via script (from config.ini)
wct test:presentation --file-ini ../my-example/config.ini --presentation-tests-dir ../my-example
```

### Using CLI Options

Override configuration at runtime without editing `config.ini`:

```bash
# Static URL
wct test:presentation \
  --file-ini                    ../my-example/config.ini \
  --presentation-tests-dir      ../my-example \
  --presentation-authorize-uri  'https://your-verifier.example.com/authorize?....'

# Dynamic URL via script
wct test:presentation \
  --file-ini                       ../my-example/config.ini \
  --presentation-tests-dir         ../my-example \
  --presentation-authorize-script  ./tests/scripts/presentation.example.sh
```

`--presentation-authorize-uri` points to the authorize URL of the Relying Party (Verifier)
(generally the URL encoded in a QR code).

### Using Environment Variables

```bash
# Static URL
CONFIG_PRESENTATION_AUTHORIZE_URI='https://rp.example.com/auth?...' \
  wct test:presentation --file-ini ../my-example/config.ini --presentation-tests-dir ../my-example

# Dynamic URL via script
CONFIG_PRESENTATION_AUTHORIZE_SCRIPT=./tests/scripts/presentation.example.sh \
  wct test:presentation --file-ini ../my-example/config.ini --presentation-tests-dir ../my-example
```

### CLI Reference

| Option                                   | Environment Variable                   | Config key (`[presentation]`) | Description                                                       |
| ---------------------------------------- | -------------------------------------- | ----------------------------- | ----------------------------------------------------------------- |
| `--file-ini <path>`                      | —                                      | —                             | Path to your `config.ini`, relative to `wallet-conformance-test/` |
| `--presentation-tests-dir <path>`        | `CONFIG_PRESENTATION_TESTS_DIR`        | `tests_dir`                   | Directory where Vitest looks for `*.presentation.spec.ts` files   |
| `--presentation-authorize-uri <url>`     | `CONFIG_PRESENTATION_AUTHORIZE_URI`    | `authorize_request_url`       | Static authorization request URL                                  |
| `--presentation-authorize-script <path>` | `CONFIG_PRESENTATION_AUTHORIZE_SCRIPT` | `authorize_request_script`    | Path to a script that outputs the URL dynamically                 |

> Both `--file-ini` and `--presentation-tests-dir` paths are resolved relative to
> `wallet-conformance-test/` (your current working directory). The `../my-example` examples above
> work because `my-example/` is a sibling of `wallet-conformance-test/` inside `my-test/`.

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

| Base class                        | Flow slot                                 |
| --------------------------------- | ----------------------------------------- |
| `FetchMetadataVpDefaultStep`      | Fetch RP metadata                         |
| `AuthorizationRequestDefaultStep` | Authorization request & VP token creation |
| `RedirectUriDefaultStep`          | Send authorization response to verifier   |

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
test("RPR_006 — handle declined presentation gracefully", async () => {
  let testSuccess = false;
  try {
    // When presentation is declined, redirectUri and responseCode are undefined
    const isDeclined =
      redirectUriResult.response?.responseCode === undefined &&
      redirectUriResult.response?.redirectUri === undefined;

    const isAccepted = redirectUriResult.response?.responseCode !== undefined;

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
    baseLog.testCompleted("RPR_006", testSuccess);
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
      if (
        result.response?.authorizationResponse.authorizationResponsePayload
          .vp_token
      ) {
        result.response?.authorizationResponse.authorizationResponsePayload.vp_token =
          "malformed.token.here";
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
- [Test Configuration Guide](./TEST-CONFIGURATION-GUIDE.md) — full reference for
  auto-discovery and config options
- [Test Configuration Guide – Presentation](./TEST-CONFIGURATION-GUIDE.md) —
  presentation-specific settings
- [IT Wallet Documentation](https://italia.github.io/eid-wallet-it-docs/)
- [Relying Party Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-relying-party.html)
