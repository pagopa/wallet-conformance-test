# 🚀 Test Configuration Guide: Complete Reference

This comprehensive guide shows you how to configure and run conformance tests with the new auto-discovery system.

## 🏗️ Architecture Overview

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
- **Minimal Metadata**: Test specs only need to define a unique test `name` (string) - no object required
- **Optional Mapping**: Tests may have a `steps_mapping` entry in `config.ini` pointing to a custom step directory; if omitted, built-in default step stubs are used automatically
- **Versioned Steps**: Encourages reusable, versioned step implementations shared across tests
- **Configuration Hierarchy**: CLI options > Custom INI > Default INI
- **Required Configuration**: `credential_types[]` must be configured in `config.ini` for issuance tests
- **Default Step IT Wallet Happy Flow**: All default step classes now contain implementations about Happy Flow that can be overridden

## 📁 Directory Structure

```
│
steps/                             # Shared step implementations, IT Wallet Happy Flow step implementations
│── issuance/
│   ├── authorize-step.ts
│   ├── credential-request-step.ts
│   ├── fetch-metadata-step.ts
│   ├── nonce-request-step.ts
│   ├── pushed-authorization-request-step.ts
│   └── token-request-step.ts
│── presentation/
│   ├── authorization-request-step.ts
│   ├── fetch-metadata-step.ts
│   └── redirect-uri-step.ts
│
tests/
├── conformance/                       # conformance test structure
│   ├── issuance/
│   │   └── happy.issuance.spec.ts # Test spec (uses defineIssuanceTest)
│   │   └── par-validation.issuance.spec.ts # Test spec (uses defineIssuanceTest)
│   └── presentation/
│       └── happy.presentation.spec.ts # Test spec (uses definePresentationTest)
│
├── config/
│   ├── test-metadata.ts               # defineIssuanceTest() / definePresentationTest()
│   ├── test-loader.ts                 # TestLoader (auto-discovery system)
│   ├── issuance-test-configuration.ts # IssuerTestConfiguration
│   └── presentation-test-configuration.ts # PresentationTestConfiguration
│
└── global-setup.ts                    # Global test setup
```

## 🎯 Quick Start

### Step 1: Create a New Test

Create a test spec file with minimal metadata - custom steps and options are automatically discovered:

```typescript
// tests/example/my-test.issuance.spec.ts

import { defineIssuanceTest } from "#/config/test-metadata";
// ... other imports

// Define and get test configurations (automatically discovers default steps)
const testConfigs = await defineIssuanceTest("ExampleIssuanceTest");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Example Issuance Tests: Token response`, () => {

    // Define an Issuance Orchestrator
    const orchestrator: WalletIssuanceOrchestratorFlow =
      new WalletIssuanceOrchestratorFlow(testConfig);
    const baseLog = orchestrator.getLog();

    // Define tokenResponse which will include token step response
    let tokenResponse: TokenRequestResponse;

    beforeAll(async () => {
      baseLog.testSuite({
        profile: testConfig.credentialConfigurationId,
        target: orchestrator.getConfig().issuance.url,
        title: "Issuance Token response Tests",
      });

      ({ tokenResponse } = await orchestrator.issuance());

    });

      // Define your tests

       test("...", , async () => { })
    });
});
```

### Step 2: Run Tests

```bash
# Run issuance tests
wct test:issuance --issuance-tests-dir ./tests/example --credential-issuer-uri ...
```

**Important**: 
You can permanently set the issuance tests directory in your `config.ini` file:

```ini
[issuance]
url = ..

tests_dir = ./tests/example/issuance
```

That's it! The test automatically discovers custom steps and configures itself when loaded.

## ⚙️ Configuration

### config.ini Structure

Test directories and step mappings are configured in `config.ini`:

```ini
[issuance]
url = https://issuer.example.com
tests_dir = ./tests/conformance/issuance  # Directory for issuance test specs
credential_types[] = dc_sd_jwt_EuropeanDisabilityCard

[presentation]
authorize_request_url = https://verifier.example.com/....
tests_dir = ./tests/conformance/presentation  # Directory for presentation test specs

[steps_mapping]
# Map test flows to shared step directories (optional)
# Format: FlowName = ./path/to/steps
HappyFlowIssuance = ./tests/steps/version_1_0/issuance
HappyFlowPresentation = ./tests/steps/version_1_0/presentation

[testing]
spec_pattern = **/*.spec.ts  # Pattern for test spec files
custom_step_pattern = **/*.ts  # Pattern for custom step files
```

**`steps_mapping` Section:**
- Maps test flow names to shared step directories
- Steps are discovered from mapped directory instead of test directory
- Allows reusing versioned step implementations across multiple tests

### CLI Overrides

Override test directories via CLI:

```bash
# Override issuance tests directory
wct test:issuance --issuance-tests-dir ./custom/issuance/path

# Override presentation tests directory
wct test:presentation --presentation-tests-dir ./custom/presentation/path

# Override credential types
wct test:issuance --credential-types "dc_sd_jwt_Type1,dc_sd_jwt_Type2"
```

**Configuration hierarchy**: CLI options > Custom INI > Default INI

### Multiple Credential Types

Test the same flow with multiple credential types by configuring them in `config.ini`:

```ini
[issuance]
credential_types[] = dc_sd_jwt_EuropeanDisabilityCard
credential_types[] = dc_sd_jwt_DrivingLicense
credential_types[] = dc_sd_jwt_ElectronicHealthCard
```

The system automatically creates one test configuration per credential type for each test.

**Important**: If `credential_types[]` is empty or not configured, `defineIssuanceTest()` will throw an error.

## 🔧 Advanced Customization

### Custom Step Implementation

Custom steps are automatically discovered by the `TestLoader` based on prototype chain inspection.

#### Step Discovery Location

Steps are discovered from the directory specified in `steps_mapping`:

**Shared Steps Directory** (Versioned, reusable via `steps_mapping`):
```
src/step/issuance/
├── authorize-step.ts           # AuthorizeDefaultStep
├── token-request-step.ts       # TokenRequestDefaultStep
└── ...
```

**Configuration Required:**
Test that you want to ovveride step implementation must have a `steps_mapping` entry in `config.ini` that specifies the directory containing its custom steps.

#### Example: Custom Token Request Steps

```typescript
// tests/steps/custom_token_request/issuance/custom-token-step.ts

import { TokenRequestDefaultStep, TokenRequesttepOptions } from "@/step/issuance";

export class TokenRequestCustomStep extends TokenRequestDefaultStep {
  async run(options: TokenRequestStepOptions) : Promise<TokenRequestResponse> {
    const log = this.log.withTag(this.tag);
    log.debug("Starting Custom Token Request Step");
    
    // Custom specific implementation
    // ...
    
    return this.execute(async () => {
      // Implementation details
    });
  }
}
```

**Configure in config.ini:**
```ini
[steps_mapping]
# map specific test flows to step directories
ExampleIssuanceTest = ./tests/steps/custom_token_request/issuance
```

**How it works:**
1. When `defineIssuanceTest("ExampleIssuanceTest")` is called
2. `TestLoader` checks `config.steps_mapping.mapping["ExampleIssuanceTest"]`
3. Finds `./tests/steps/custom_token_request/issuance`
4. Scans that directory for custom steps (e.g., `TokenRequestCustomStep`)
5. Auto-discovers and maps to test configuration

**Fallback mechanism:**
- **Default stub**: If no `steps_mapping` entry exists for a test, or a step is not found in the mapped directory, the built-in default step stub is used (logs a warning)

#### Available Base Classes for Extension

**Issuance Steps:**
- `FetchMetadataDefaultStep` → `fetchMetadata`
- `PushedAuthorizationRequestDefaultStep` → `pushedAuthorizationRequest`
- `AuthorizeDefaultStep` → `authorize`
- `TokenRequestDefaultStep` → `tokenRequest`
- `NonceRequestDefaultStep` → `nonceRequest`
- `CredentialRequestDefaultStep` → `credentialRequest`

**Presentation Steps:**
- `FetchMetadataVpDefaultStep` → `fetchMetadataVp`
- `AuthorizationRequestDefaultStep` → `authorizationRequest` (mapped to `authorize` in config)
- `RedirectUriDefaultStep` → `redirectUri`

**Important Notes:**
- All default step classes now contain **IT Wallet Happy Flow implementations**
- See `src/steps/` for reference implementations

### Step Discovery and Mapping

**Discovery Process:**

When you call `defineIssuanceTest("MyTestFlow")` or `definePresentationTest("MyTestFlow")`:

1. **Resolve steps directory**:
   - Checks `config.steps_mapping.mapping["MyTestFlow"]` for a specific mapping
   - If not found, no custom steps are loaded (built-in stubs are used, no error)

2. **Discover steps from mapped directory** (if a mapping exists):
   - Scans the resolved directory for custom step implementations

3. **Use stub for missing steps**:
   - Steps not found in the mapped directory fall back to built-in default stub implementations

**Example Configuration:**

```ini
[steps_mapping]
HappyFlowIssuance = ./tests/steps/version_1_0/issuance
HappyFlowPresentation = ./tests/steps/version_1_0/presentation
```

**Workflow with specific mapping:**
```
defineIssuanceTest("HappyFlowIssuance")
    ↓
Check steps_mapping.mapping["HappyFlowIssuance"]
    ↓
Found: ./tests/steps/version_1_0/issuance
    ↓
Discover custom steps from that directory
    ↓
Any missing steps use built-in default stubs
```

**Workflow with no mapping:**
```
defineIssuanceTest("MyCustomTest")
    ↓
Check steps_mapping.mapping["MyCustomTest"]
    ↓
Not found → log info, use built-in default step stubs for all steps
```

### Auto-Discovery Process

When you call `defineIssuanceTest("MyTest")` or `definePresentationTest("MyTest")`:

1. **Steps Directory Resolution**: 
   - First looks up `config.steps_mapping.mapping["MyTest"]` for specific mapping
   - If not found, no custom steps are loaded (built-in stubs are used, no error thrown)
   
2. **Custom Step Discovery**: Scans for `.ts` files matching `custom_step_pattern` (default: `**/*.ts`)
   - Excludes `**/*.spec.ts` (test files)
   - Reads and imports each TypeScript file

3. **Prototype Chain Inspection**: Checks which base class each export extends
   - Uses `Object.getPrototypeOf()` to walk the prototype chain
   - Compares against known base classes (e.g., `AuthorizeDefaultStep`)

4. **Step Type Mapping**: Maps discovered steps to configuration keys
   - `AuthorizeCustomStep extends AuthorizeDefaultStep` → `authorize`
   - `CustomTokenStep extends TokenRequestDefaultStep` → `tokenRequest`

5. **Configuration Creation**: Builds `IssuerTestConfiguration` or `PresentationTestConfiguration`
   - Injects discovered custom steps
   - Uses default steps for any non-overridden steps (with stub warning)

**File Patterns (configurable in config.ini):**
- `spec_pattern`: Pattern for test spec files (default: `**/*.spec.ts`)
- `custom_step_pattern`: Pattern for custom step files (default: `**/*.ts`)

**Excluded from discovery:**
- `**/*.spec.ts` - Test spec files

## 📝 Test Execution Reference

### Issuance Flow Tests

The issuance flow validates credential issuance conformance according to [Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html).

#### Federation Metadata Tests

- **CI_001**: Federation Entity publishes its own Entity Configuration in the .well-known/openid-federation endpoint
- **CI_002**: Entity Configuration response media type check (must be `application/entity-statement+jwt`)
- **CI_003**: The Entity Configuration is cryptographically signed (JWT signature validation)
- **CI_006**: Entity Configurations have in common these parameters: `iss`, `sub`, `iat`, `exp`, `jwks`, `metadata`
- **CI_008**: Credential Issuer metadata includes `federation_entity`, `oauth_authorization_server`, and `openid_credential_issuer` sections
- **CI_009**: Inclusion of `openid_credential_verifier` metadata in User Authentication via Wallet

#### Pushed Authorization Request (PAR) Tests

- **CI_040**: `request_uri` validity time is set to less than one minute
- **CI_041**: Generated `request_uri` includes a cryptographic random value of at least 128 bits
- **CI_042**: Complete `request_uri` doesn't exceed 512 ASCII characters
- **CI_043**: When verification is successful, Credential Issuer returns HTTP 201 status code
- **CI_044a**: HTTP response includes `request_uri` parameter containing the generated one-time authorization URI
- **CI_044b**: HTTP response includes `expires_in` parameter specifying the validity duration in seconds

#### Authorization Tests

- **CI_049**: Credential Issuer successfully identifies and correlates each authorization request as a direct result of a previously submitted PAR
- **CI_054**: (Q)EAA Provider successfully performs User authentication by requesting and validating a valid PID from the Wallet Instance
- **CI_055**: (Q)EAA Provider uses OpenID4VP protocol to request PID presentation from the Wallet Instance
- **CI_056**: (Q)EAA Provider successfully provides the presentation request to the Wallet
- **CI_058a**: Authorization code response includes the `code` parameter
- **CI_058b**: Authorization code response includes the `state` parameter matching the original request
- **CI_058c**: Authorization code response includes the `iss` parameter identifying the issuer

#### Token Request Tests

- **CI_064**: Credential Issuer provides the Wallet Instance with a valid Access Token upon successful authorization
- **CI_066**: Both Access Token and Refresh Token (when issued) are cryptographically bound to the DPoP key
- **CI_094**: When all validation checks succeed, Credential Issuer generates new Access Token and new Refresh Token, both bound to the DPoP key
- **CI_095**: Both the Access Token and the Refresh Token are sent back to the Wallet Instance
- **CI_101**: Access Tokens and Refresh Tokens are bound to the same DPoP key

#### Nonce Request Tests

- **CI_068**: Credential Issuer provides a `c_nonce` value to the Wallet Instance
- **CI_069**: The `c_nonce` parameter is provided as a string value with sufficient unpredictability to prevent guessing attacks (≥32 characters with sufficient entropy)

#### Credential Request Tests

- **CI_084**: When all validation checks succeed, Credential Issuer creates a new Credential cryptographically bound to the validated key material and provides it to the Wallet Instance
- **CI_118**: (Q)EAA are Issued to a Wallet Instance in SD-JWT VC or mdoc-CBOR data format

---

### Presentation Flow Tests

The presentation flow validates credential presentation conformance according to [Credential Verifier Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-presentation.html).

#### QR Code and Authorization Request Tests

- **RPR003**: Relying Party issues the QR-Code containing a URL using the base URL provided within its metadata
- **RPR009**: Relying Party accepts defaults to GET method for request objects
- **RPR012**: Relying Party receives and validates response with `state` and `nonce` values
- **RPR019**: User is redirected correctly, the endpoint works

#### DCQL Query Tests

- **RPR078**: Wallet Attestation request correctly uses standard DCQL query format
- **RPR079**: `claims` parameter is not included in DCQL query for Wallet Attestation
- **RPR080**: `vct_values` parameter is correctly required in DCQL query

#### Metadata and Configuration Tests

- **RPR082**: `response_types_supported` is correctly set to `vp_token` in verifier metadata
- **RPR083**: Relying Party correctly provides and handles `redirect_uri` and `response_uri`

#### JWT and Parameter Validation Tests

- **RPR089**: JWT `typ` parameter is correctly set to `oauth-authz-req+jwt`
- **RPR090**: `response_mode` parameter is correctly set to `direct_post.jwt`
- **RPR091**: `response_type` parameter is correctly set to `vp_token`
- **RPR092**: Relying Party sends Authorization Response to correct `response_uri` endpoint
- **RPR093**: `nonce` parameter has sufficient entropy with at least 32 characters
- **RPR094**: JWT `exp` parameter is correctly set and not expired

---

## 📚 API Reference

### `defineIssuanceTest(name)`

Defines and creates issuance test configurations with automatic discovery of custom steps and options.

**Parameters**:
- `name` (string, required): Unique test name (used for display and logging)

**Returns**: `Promise<IssuerTestConfiguration[]>` - Array of test configurations (one per credential type)

**Important**: 
- Requires `credential_types[]` to be configured in `config.ini` [issuance] section
- Throws an error if `credential_types` is empty
- If `steps_mapping[name]` is configured, custom steps are discovered from that directory
- If `steps_mapping[name]` is absent, all steps use built-in default stub implementations
- **Does NOT discover step options** - options system has been removed

**Example**:
```typescript
const testConfigs = await defineIssuanceTest("MyIssuanceTest");

testConfigs.forEach((config) => {
  describe(`[${config.name}] Tests`, () => {
    // Your tests
  });
});
```

### `definePresentationTest(name)`

Defines and creates a presentation test configuration with automatic discovery of custom steps and options.

**Parameters**:
- `name` (string, required): Unique test name (used for display and logging)

**Returns**: `Promise<PresentationTestConfiguration>` - Single test configuration

**Example**:
```typescript
const testConfig = await definePresentationTest("MyPresentationTest");

describe(`[${testConfig.name}] Tests`, () => {
  // Your tests
});
```

### `TestLoader` (Internal)

Internal utility class that handles auto-discovery of custom steps.

**Important**: Step options discovery has been removed in this refactoring.

#### `testLoader.discoverCustomSteps(directory)`

Scans a directory for custom step implementations using prototype chain inspection.

**Parameters**:
- `directory` (string): Absolute path to scan

**Returns**: `Promise<Record<string, any>>` - Map of step type to step class

**Internal use only** - Called automatically by `defineIssuanceTest()` and `definePresentationTest()`

**How It Works**:
1. Scans directory for `.ts` files (excluding `*.spec.ts`)
2. Imports each file and inspects exports
3. Checks if export extends a known base class via prototype chain
4. Maps to step type (e.g., `AuthorizeDefaultStep` → `authorize`)

**Example Discovered Steps**:
```typescript
{
  "authorize": AuthorizeCustomStep,
  "tokenRequest": TokenRequestCustomStep,
  "credentialRequest": CredentialRequestCustomStep
}
```
---

## 📖 Additional Resources

- [IT Wallet Documentation](https://italia.github.io/eid-wallet-it-docs/)
- [Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html)
- [Credential Verifier Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-presentation.html)
