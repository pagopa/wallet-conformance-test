# Test Configuration Internal Guide: Complete Reference

This comprehensive guide shows you how to configure and run conformance tests with the auto-discovery system.

## Architecture Overview

The test system uses a **convention-over-configuration** approach with automatic discovery of custom steps:

```
Test Spec File (*.spec.ts)
    ↓
Calls defineIssuanceTest() or definePresentationTest()
    ↓
Resolves steps_mapping[testName] from config.ini
    ↓
Auto-discovers custom steps from mapped directory
    ↓
Returns test configuration(s)
    ↓
Test suite uses returned configuration
    ↓
Vitest executes tests
```

### Key Concepts

- **Auto-Discovery**: Custom steps are automatically discovered from directories specified in `steps_mapping` using prototype chain inspection
- **Minimal Metadata**: Test specs only need to define a unique test `name` (string)
- **Optional Mapping**: Tests may have a `steps_mapping` entry in `config.ini` pointing to a custom step directory; if omitted, built-in default step implementations are used automatically
- **Versioned Steps**: Encourages reusable, versioned step implementations shared across tests
- **Configuration Hierarchy**: CLI options > Custom INI > Default INI
- **Required Configuration**: `credential_types[]` must be configured in `config.ini` for issuance tests
- **Default Step IT Wallet Happy Flow**: All default step classes contain IT Wallet Happy Flow implementations that can be overridden

## Directory Structure

```
src/
├── orchestrator/
│   ├── wallet-issuance-orchestrator-flow.ts
│   └── wallet-presentation-orchestrator-flow.ts
└── step/
    ├── issuance/                          # Default step implementations for issuance
    │   ├── authorize-step.ts              # AuthorizeDefaultStep
    │   ├── credential-request-step.ts     # CredentialRequestDefaultStep
    │   ├── fetch-metadata-step.ts         # FetchMetadataDefaultStep
    │   ├── nonce-request-step.ts          # NonceRequestDefaultStep
    │   ├── pushed-authorization-request-step.ts  # PushedAuthorizationRequestDefaultStep
    │   ├── token-request-step.ts          # TokenRequestDefaultStep
    │   └── index.ts
    └── presentation/                      # Default step implementations for presentation
        ├── authorization-request-step.ts  # AuthorizationRequestDefaultStep
        ├── fetch-metadata-step.ts         # FetchMetadataVpDefaultStep
        ├── redirect-uri-step.ts           # RedirectUriDefaultStep
        └── index.ts

tests/
├── conformance/                           # Conformance test specs
│   ├── issuance/
│   │   ├── authorization-validation.issuance.spec.ts
│   │   ├── credential-validation.issuance.spec.ts
│   │   ├── happy.issuance.spec.ts
│   │   └── par-validation.issuance.spec.ts
│   └── presentation/
│       └── happy.presentation.spec.ts
│
├── config/
│   ├── issuance-test-configuration.ts     # IssuerTestConfiguration
│   ├── presentation-test-configuration.ts # PresentationTestConfiguration
│   ├── test-loader.ts                     # TestLoader (auto-discovery system)
│   ├── test-metadata.ts                   # defineIssuanceTest() / definePresentationTest()
│   └── index.ts
│
├── helpers/
│   ├── credential-validation-helpers.ts   # Factory helpers for negative credential tests
│   ├── par-validation-helpers.ts          # Factory helpers for negative PAR tests
│   └── use-test-summary.ts                # useTestSummary() hook
│
└── global-setup.ts                        # Global test setup (starts Trust Anchor)
```

## Quick Start

### Step 1: Create a New Test

Create a test spec file with minimal metadata — custom steps are automatically discovered:

```typescript
// tests/example/my-test.issuance.spec.ts
/* eslint-disable max-lines-per-function */

import { defineIssuanceTest } from "#/config/test-metadata";
import { useTestSummary } from "#/helpers/use-test-summary";
import { beforeAll, describe, expect, test } from "vitest";

import { WalletIssuanceOrchestratorFlow } from "@/orchestrator";
import { TokenRequestResponse } from "@/step/issuance";

// @ts-expect-error TS1309: top-level await is valid in Vitest (ESM context)
const testConfigs = await defineIssuanceTest("MyIssuanceTest");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] My Issuance Tests`, () => {
    const orchestrator = new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    let tokenResponse: TokenRequestResponse;

    beforeAll(async () => {
      ({ tokenResponse } = await orchestrator.issuance());
    });

    // Register summary hooks — call this inside describe, before any test() blocks
    useTestSummary(baseLog, testConfig.name);

    test("CI_XXX — token response contains access_token", async () => {
      let testSuccess = false;
      try {
        expect(
          tokenResponse.response?.access_token,
          "access_token must be present",
        ).toBeDefined();
        testSuccess = true;
      } finally {
        baseLog.testCompleted("CI_XXX", testSuccess);
      }
    });
  });
});
```

### Step 2: Run Tests

```bash
# Run test files in a specific directory
wct test:issuance --issuance-tests-dir ./tests/example
```

That's it! The test automatically discovers custom steps and configures itself when loaded.

## Configuration

## Advanced Customization

### Custom Step Implementation

Custom steps are automatically discovered by `TestLoader` using prototype chain inspection. You only need to extend a `*DefaultStep` base class — the loader maps it to the correct configuration slot automatically.

#### Step Discovery Location

Steps are discovered from the directory specified in `steps_mapping[flowName]`:

```
tests/example/steps
├── my-token-step.ts     # class MyTokenStep extends TokenRequestDefaultStep
└── ...
```

**Configuration required:** The flow must have a `steps_mapping` entry pointing to this directory.

#### Example: Custom Token Request Step

```typescript
// tests/example/steps/my-token-step.ts

import {
  TokenRequestDefaultStep,
  TokenRequestResponse,
  TokenRequestStepOptions,
} from "@/step/issuance";

export class MyTokenStep extends TokenRequestDefaultStep {
  override async run(
    options: TokenRequestStepOptions,
  ): Promise<TokenRequestResponse> {
    const log = this.log.withTag(this.tag);
    log.debug("Starting custom Token Request step");

    return this.execute(async () => {
      // Custom implementation
    });
  }
}
```

**Configure in config.ini:**

```ini
[steps_mapping]
MyIssuanceTest = ./tests/example/steps/my-token-step.ts
```

**How it works:**

1. `defineIssuanceTest("MyIssuanceTest")` is called
2. `TestLoader` checks `config.steps_mapping.mapping["MyIssuanceTest"]`
3. Finds `./tests/example/steps/`
4. Scans that directory for TypeScript files
5. Inspects prototype chain of each export to determine which base class it extends
6. Maps `MyTokenStep extends TokenRequestDefaultStep` → slot `"tokenRequest"`
7. Any step slot not covered falls back to the built-in `*DefaultStep` implementation

**Fallback:** If no `steps_mapping` entry exists, or a step is not found in the mapped directory, the built-in default step is used automatically.

### Available Base Classes for Extension

**Issuance Steps** (`@/step/issuance`):

| Base Class                              | Config Slot                  | Description                            |
| --------------------------------------- | ---------------------------- | -------------------------------------- |
| `FetchMetadataDefaultStep`              | `fetchMetadata`              | Fetches OpenID4VCI issuer metadata     |
| `PushedAuthorizationRequestDefaultStep` | `pushedAuthorizationRequest` | Sends PAR to the issuer                |
| `AuthorizeDefaultStep`                  | `authorize`                  | Performs the OAuth2 authorization step |
| `TokenRequestDefaultStep`               | `tokenRequest`               | Exchanges auth code for access token   |
| `NonceRequestDefaultStep`               | `nonceRequest`               | Requests a nonce for credential proof  |
| `CredentialRequestDefaultStep`          | `credentialRequest`          | Requests the credential                |

**Presentation Steps** (`@/step/presentation`):

| Base Class                        | Config Slot            | Description                             |
| --------------------------------- | ---------------------- | --------------------------------------- |
| `FetchMetadataVpDefaultStep`      | `fetchMetadataVp`      | Fetches verifier metadata               |
| `AuthorizationRequestDefaultStep` | `authorizationRequest` | Sends authorization request to verifier |
| `RedirectUriDefaultStep`          | `redirectUri`          | Handles the redirect URI response       |

### Negative Test Helpers

For tests requiring only one or a few deviant parameters, use factory helpers instead of writing a full custom step class.

#### PAR Validation Helpers (`#/helpers/par-validation-helpers`)

| Helper                                             | Description                                                                           |
| -------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `withParOverrides(StepClass, overrides)`           | Spreads `Partial<CreatePushedAuthorizationRequestOptions>` onto computed PAR defaults |
| `withSignJwtOverride(StepClass, signJwt)`          | Replaces only the `signJwt` callback; preserves `generateRandom` and `hash`           |
| `buildTamperedPopJwt(options)`                     | Builds a possibly-tampered OAuth-Client-Attestation-PoP JWT                           |
| `createFakeAttestationResponse()`                  | Creates a wallet attestation signed by an unregistered key                            |
| `signThenTamperPayload(key, pubKey, field, value)` | Signs normally then mutates a payload field without re-signing                        |
| `signWithCustomIss(iss, key, pubKey)`              | Signs with the correct key but injects a custom `iss` claim                           |
| `signWithHS256(secret)`                            | Signs with symmetric HS256 (forbidden by spec)                                        |
| `signWithMismatchedAlgorithm(headerAlg, signAlg)`  | Declares one algorithm in the header but signs with another                           |
| `signWithWrongAlgHeader(alg, key, pubKey)`         | Signs with a wrong algorithm header value                                             |
| `signWithWrongKey()`                               | Signs with a fresh unrelated EC key                                                   |
| `signWithWrongKid(kid, key, pubKey)`               | Signs with the correct key but injects a wrong `kid` header                           |
| `tamperJwtPayload(jwt, field, value)`              | Mutates a JWT payload claim without re-signing                                        |

#### Credential Validation Helpers (`#/helpers/credential-validation-helpers`)

**Step class factories** (`withCredential*` pattern — mirror `withParOverrides` / `withSignJwtOverride`):

| Helper                                                 | Description                                                        |
| ------------------------------------------------------ | ------------------------------------------------------------------ |
| `withCredentialRequestOverrides(StepClass, overrides)` | Spreads overrides onto `createCredentialRequestOverrides`          |
| `withCredentialSignJwtOverride(StepClass, signJwt)`    | Replaces only the credential proof `signJwt` callback              |
| `withNoDPoP(StepClass)`                                | Sends an empty DPoP header (CI_082a)                               |
| `withWrongHtmDPoP(StepClass)`                          | Sets `htm = "GET"` in DPoP (CI_082b)                               |
| `withWrongAthDPoP(StepClass)`                          | Sets `ath` to the hash of a fake token (CI_082c)                   |
| `withNoAthDPoP(StepClass)`                             | Omits `ath` from DPoP (CI_082d)                                    |
| `withWrongTypDPoP(StepClass)`                          | Sets DPoP `typ: "JWT"` (CI_082e)                                   |
| `withAlgNoneDPoP(StepClass)`                           | Sets DPoP `alg: "none"` (CI_082f)                                  |
| `withBadSignatureDPoP(StepClass)`                      | DPoP signed with key A but declares key B (CI_082g)                |
| `withPrivateKeyInDPoPHeader(StepClass)`                | Embeds private `d` parameter in DPoP `jwk` header (CI_082h)        |
| `withWrongHtuDPoP(StepClass)`                          | Sets `htu` to a value other than the credential endpoint (CI_082i) |
| `withStaleIatDPoP(StepClass)`                          | Sets DPoP `iat` 6 minutes in the past (CI_082j)                    |
| `withDPoPSignedByWrongKey(StepClass)`                  | Signs DPoP with a key not bound to the access token (CI_083)       |

**`SignJwtCallback` factories** (for credential proof manipulation):

| Helper                                 | Description                                                            |
| -------------------------------------- | ---------------------------------------------------------------------- |
| `signWithHS256(secret)`                | Signs proof with symmetric HS256 (CI_074)                              |
| `signWithoutClaim(claim, key, pubKey)` | Removes a required claim from the proof (CI_071)                       |
| `signWithPrivateKeyInHeader(keyPair)`  | Embeds private `d` in the `jwk` header (CI_076)                        |
| `signWithWrongKey()`                   | Signs with an unrelated key but embeds a different public key (CI_075) |
| `signWithWrongTyp(typ, key, pubKey)`   | Sets a wrong `typ` header (CI_073)                                     |

#### Usage Example

```typescript
import {
  withParOverrides,
  withSignJwtOverride,
} from "#/helpers/par-validation-helpers";
import { PushedAuthorizationRequestDefaultStep } from "@/step/issuance";

// Override only the code_challenge_method field
const WrongChallengeMethodStep = withParOverrides(
  PushedAuthorizationRequestDefaultStep,
  {
    code_challenge_method: "plain",
  },
);

// Replace the signJwt callback with one that uses a wrong key
const WrongKeyStep = withSignJwtOverride(
  PushedAuthorizationRequestDefaultStep,
  signWithWrongKey(),
);
```

### Step Discovery and Mapping

**Discovery process** when `defineIssuanceTest("MyFlow")` or `definePresentationTest("MyFlow")` is called:

1. **Resolve steps directory**
   - Checks `config.steps_mapping.mapping["MyFlow"]` for a mapping entry
   - If not found, no custom steps are loaded (built-in defaults used, no error thrown)

2. **Discover steps from mapped directory** (if a mapping exists)
   - Scans with `custom_step_pattern` (default: `**/*.ts`)
   - Excludes `**/*.spec.ts` and `**/step-options.ts`
   - Dynamically imports each file and inspects every export

3. **Prototype chain inspection**
   - Uses `Object.getPrototypeOf()` to walk the chain
   - Matches against known `*DefaultStep` class names via `STEP_CLASS_TO_KEY`
   - Maps to a configuration slot string (e.g., `"tokenRequest"`)

4. **Fallback for missing steps**
   - Any slot not covered by a discovered class falls back to the built-in `*DefaultStep`

**Example workflows:**

```
defineIssuanceTest("HappyFlowIssuance")
    ↓
steps_mapping["HappyFlowIssuance"] = ./tests/steps/version_1_0/issuance
    ↓
Scan directory, discover custom step classes
    ↓
Missing steps use built-in default implementations
```

```
defineIssuanceTest("MyCustomTest")
    ↓
steps_mapping["MyCustomTest"] → not found
    ↓
All steps use built-in default implementations (no error)
```






### config.ini Structure

Test directories and step mappings are configured in `config.ini`:

```ini
[issuance]
url = https://issuer.example.com
tests_dir = ./tests/conformance/issuance       # Directory for issuance test specs
credential_types[] = dc_sd_jwt_EuropeanDisabilityCard

[presentation]
authorize_request_url = https://verifier.example.com/authorize
tests_dir = ./tests/conformance/presentation   # Directory for presentation test specs

[steps_mapping]
# Map test flow names to custom step directories (optional)
# Format: FlowName = ./path/to/steps
HappyFlowIssuance     = ./tests/steps/version_1_0/issuance
HappyFlowPresentation = ./tests/steps/version_1_0/presentation

[testing]
spec_pattern        = **/*.spec.ts  # Pattern for test spec files
custom_step_pattern = **/*.ts       # Pattern for custom step files
```

**`steps_mapping` Section:**

- Maps test flow names to custom step directories
- Steps are discovered from the mapped directory instead of the test spec directory
- Allows reusing versioned step implementations across multiple tests
- If a flow name has no mapping entry, all built-in default step implementations are used (no error)

### Multiple Credential Types

Test the same flow with multiple credential types by listing them in `config.ini`:

```ini
[issuance]
credential_types[] = dc_sd_jwt_EuropeanDisabilityCard
credential_types[] = dc_sd_jwt_DrivingLicense
credential_types[] = dc_sd_jwt_ElectronicHealthCard
```

The system automatically creates one `IssuerTestConfiguration` per credential type. Each `describe` block in the spec runs independently for each type.

**Important**: If `credential_types[]` is empty or not configured, `defineIssuanceTest()` throws an error.

## Test Execution Reference

See [TEST-EXECUTION-REFERENCE.md](./TEST-EXECUTION-REFERENCE.md) for the full list of issuance and presentation test cases.

---

## API Reference

### `defineIssuanceTest(name)`

Creates issuance test configurations with automatic discovery of custom steps.

**Parameters:**

- `name` (string, required): Unique flow name — used for display, logging, and `steps_mapping` lookup

**Returns:** `Promise<IssuerTestConfiguration[]>` — one configuration per `credential_types[]` entry

**Important:**

- Requires `credential_types[]` to be configured under `[issuance]` in `config.ini`
- Throws if `credential_types` is empty
- If `steps_mapping[name]` is configured, custom steps are discovered from that directory
- If `steps_mapping[name]` is absent, all steps use built-in default implementations

**Example:**

```typescript
// @ts-expect-error TS1309: top-level await is valid in Vitest (ESM context)
const testConfigs = await defineIssuanceTest("MyIssuanceTest");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Tests`, () => {
    // ...
  });
});
```

### `definePresentationTest(name)`

Creates a presentation test configuration with automatic discovery of custom steps.

**Parameters:**

- `name` (string, required): Unique flow name — used for display, logging, and `steps_mapping` lookup

**Returns:** `Promise<PresentationTestConfiguration>` — single configuration object

**Example:**

```typescript
// @ts-expect-error TS1309: top-level await is valid in Vitest (ESM context)
const testConfig = await definePresentationTest("MyPresentationTest");

describe(`[${testConfig.name}] Tests`, () => {
  // ...
});
```

### `IssuerTestConfiguration`

Holds the resolved step classes and credential type for a single issuance test run.

**Public properties:**

| Property                              | Type                                           |
| ------------------------------------- | ---------------------------------------------- |
| `name`                                | `string`                                       |
| `credentialConfigurationId`           | `string`                                       |
| `fetchMetadataStepClass`              | `typeof FetchMetadataDefaultStep`              |
| `pushedAuthorizationRequestStepClass` | `typeof PushedAuthorizationRequestDefaultStep` |
| `authorizeStepClass`                  | `typeof AuthorizeDefaultStep`                  |
| `tokenRequestStepClass`               | `typeof TokenRequestDefaultStep`               |
| `nonceRequestStepClass`               | `typeof NonceRequestDefaultStep`               |
| `credentialRequestStepClass`          | `typeof CredentialRequestDefaultStep`          |

**Static factory methods:**

- `IssuerTestConfiguration.createCustom(config)` — used internally by `defineIssuanceTest()`
- `IssuerTestConfiguration.createDefault()` — hardcodes `dc_sd_jwt_PersonIdentificationData`

### `PresentationTestConfiguration`

Holds the resolved step classes for a single presentation test run.

**Public properties:**

| Property                 | Type                                     |
| ------------------------ | ---------------------------------------- |
| `name`                   | `string`                                 |
| `fetchMetadataStepClass` | `typeof FetchMetadataVpDefaultStep`      |
| `authorizeStepClass`     | `typeof AuthorizationRequestDefaultStep` |
| `redirectUriStepClass`   | `typeof RedirectUriDefaultStep`          |

**Static factory methods:**

- `PresentationTestConfiguration.createCustom(config)` — used internally by `definePresentationTest()`
- `PresentationTestConfiguration.createDefault()` — uses all built-in defaults

### `TestLoader` (Internal)

Singleton (`testLoader`) that handles auto-discovery of custom steps.

#### `testLoader.discoverCustomSteps(directory)`

Scans a directory for custom step implementations using prototype chain inspection.

**Parameters:**

- `directory` (string): Absolute path to scan

**Returns:** `Promise<CustomStepsMap>` — map of step slot key to step class

**Excluded from discovery:**

- `**/*.spec.ts` — test spec files
- `**/step-options.ts` — legacy step options files

**Example discovered map:**

```typescript
{
  "authorize": AuthorizeCustomStep,
  "tokenRequest": TokenRequestCustomStep,
  "credentialRequest": CredentialRequestCustomStep,
}
```

---

## Additional Resources

- [IT Wallet Documentation](https://italia.github.io/eid-wallet-it-docs/)
- [Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html)
- [Credential Verifier Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-presentation.html)
