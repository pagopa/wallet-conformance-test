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
- **Required Mapping**: Each test MUST have a `steps_mapping` entry in `config.ini` pointing to its custom step directory
- **Versioned Steps**: Encourages reusable, versioned step implementations shared across tests
- **Configuration Hierarchy**: CLI options > Custom INI > Default INI
- **Required Configuration**: `credential_types[]` must be configured in `config.ini` for issuance tests
- **Default Step Stubs**: All default step classes now contain stub implementations that must be overridden

## 📁 Directory Structure

```
tests/
├── conformance/                       # New conformance test structure
│   ├── issuance/
│   │   └── happy.issuance.spec.ts # Test spec (uses defineIssuanceTest)
│   └── presentation/
│       └── happy.presentation.spec.ts # Test spec (uses definePresentationTest)
│
├── steps/                             # Shared step implementations (versioned)
│   └── version_1_0/                   # IT Wallet 1.0 step implementations
│       ├── issuance/
│       │   ├── authorize-step.ts
│       │   ├── credential-request-step.ts
│       │   ├── fetch-metadata-step.ts
│       │   ├── nonce-request-step.ts
│       │   ├── pushed-authorization-request-step.ts
│       │   └── token-request-step.ts
│       └── presentation/
│           ├── authorization-request-step.ts
│           ├── fetch-metadata-step.ts
│           └── redirect-uri-step.ts
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
// tests/issuance/my-test.issuance.spec.ts

import { defineIssuanceTest } from "#/config/test-metadata";
// ... other imports

// Define and get test configurations (automatically discovers custom steps)
const testConfigs = await defineIssuanceTest("ExampleIssuanceTest");

testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Example Issuance Tests`, () => {
      // ... your tests
    });
});
```

### Step 2: Add Custom Steps

Create versioned steps in `tests/steps/version_X_Y/` and configure via `steps_mapping`:

```typescript
// tests/steps/version_X_Y/issuance/authorize-step.ts

import { AuthorizeDefaultStep } from "@/step/issuance";

export class AuthorizeXYStep extends AuthorizeDefaultStep {
  async run(context) {
    // IT Wallet 1.0 specific implementation
  }
}
```

Then configure in `config.ini`:

```ini
[steps_mapping]
ExampleIssuanceTest = ./tests/steps/version_X_Y/issuance
```

**Important**: 
- Default step classes contain stub implementations that log a warning
- You **must** override steps with custom implementations for actual functionality
- Each test requires a `steps_mapping` entry pointing to its custom step directory

### Step 3: Run Tests

```bash
# Run issuance tests
pnpm test:issuance

# Run presentation tests
pnpm test:presentation

# Run all tests
pnpm test
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
tests/steps/version_1_0/issuance/
├── authorize-step.ts           # AuthorizeITWallet1_0Step
├── token-request-step.ts       # TokenRequestITWallet1_0Step
└── ...
```

**Configuration Required:**
Each test must have a `steps_mapping` entry in `config.ini` that specifies the directory containing its custom steps.

#### Example: Shared Versioned Steps

```typescript
// tests/steps/version_1_0/issuance/authorize-step.ts

import { AuthorizeDefaultStep, AuthorizeStepOptions } from "@/step/issuance";

export class AuthorizeITWallet1_0Step extends AuthorizeDefaultStep {
  async run(options: AuthorizeStepOptions) {
    const log = this.log.withTag(this.tag);
    log.info("Starting IT Wallet 1.0 Authorize Step");
    
    // IT Wallet 1.0 specific implementation
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
# Optional: Default directory used for:
# 1. Tests without specific mapping
# 2. Fallback for missing steps in specific directories
default_steps_dir = ./tests/steps/version_1_0

# Specific mappings take precedence over default
HappyFlowIssuance = ./tests/steps/version_1_0/issuance
```

**How it works:**
1. When `defineIssuanceTest("HappyFlowIssuance")` is called
2. `TestLoader` checks `config.steps_mapping.mapping["HappyFlowIssuance"]`
3. Finds `./tests/steps/version_1_0/issuance`
4. Scans that directory for custom steps (e.g., `AuthorizeITWallet1_0Step`)
5. **If any steps are missing**, scans `default_steps_dir` for them
6. Merges steps (specific directory steps have priority)
7. Auto-discovers and maps to test configuration

**Fallback mechanisms:**
- **Directory fallback**: If no specific mapping exists, uses `config.steps_mapping.default_steps_dir`
- **Step fallback**: Missing steps in specific directory are searched in `default_steps_dir`
- **Default stub**: If step not found anywhere, uses stub implementation (logs warning)

#### Available Base Classes for Extension

**Issuance Steps:**
- `FetchMetadataDefaultStep` → `fetchMetadata`
- `PushedAuthorizationRequestDefaultStep` → `pushedAuthorizationRequest`
- `AuthorizeDefaultStep` → `authorize`
- `TokenRequestDefaultStep` → `tokenRequest`
- `NonceRequestDefaultStep` → `nonceRequest`
- `CredentialRequestDefaultStep` → `credentialRequest`

**Presentation Steps:**
- `FetchMetadataDefaultStep` → `fetchMetadata`
- `AuthorizationRequestDefaultStep` → `authorizationRequest` (mapped to `authorize` in config)
- `RedirectUriDefaultStep` → `redirectUri`

**Important Notes:**
- All default step classes now contain **stub implementations** that only log warnings
- You **must** extend and override these steps with actual implementations
- See `tests/steps/version_1_0/` for reference implementations

### Step Discovery and Mapping

**Discovery Process:**

When you call `defineIssuanceTest("MyTestFlow")` or `definePresentationTest("MyTestFlow")`:

1. **Resolve primary steps directory**: 
   - **First**: Checks `config.steps_mapping.mapping["MyTestFlow"]` for specific mapping
   - **Second**: Falls back to `config.steps_mapping.default_steps_dir` if no mapping
   - **Third**: Throws error if neither is configured

2. **Discover steps from primary directory**:
   - Scans the resolved directory for custom step implementations
   
3. **Merge with default steps (if applicable)**:
   - If `default_steps_dir` is configured AND different from primary directory
   - Scans `default_steps_dir` for additional steps
   - Merges: primary steps take priority, default steps fill gaps
   
4. **Use stub for missing steps**:
   - Any steps not found in either location use default stub implementations

**Example Configuration:**

```ini
[steps_mapping]
# Default directory for shared steps
# Used as: 1) Fallback when no mapping exists
#          2) Source for missing steps in specific directories
default_steps_dir = ./tests/steps/version_1_0

# Specific mappings (take precedence over default)
HappyFlowIssuance = ./tests/steps/version_1_0/issuance
HappyFlowPresentation = ./tests/steps/version_1_0/presentation

# MyCustomTest will use default_steps_dir entirely
# MyPartialTest would use its directory + missing steps from default_steps_dir
```

**Workflow with specific mapping + step merge:**
```
defineIssuanceTest("MyPartialTest")
    ↓
Check steps_mapping.mapping["MyPartialTest"]
    ↓
Found: ./tests/custom/my-partial-test (has only AuthorizeStep)
    ↓
Discover steps from ./tests/custom/my-partial-test
    ↓
Found: authorize
    ↓
Check if default_steps_dir exists and is different
    ↓
Found: ./tests/steps/version_1_0 (has all 6 steps)
    ↓
Merge: keep authorize from primary, add missing 5 from default
    ↓
Result: 6 steps (1 custom + 5 from default)
```

**Workflow with default_steps_dir fallback:**
```
defineIssuanceTest("MyCustomTest")
    ↓
Check steps_mapping.mapping["MyCustomTest"]
    ↓
Not found → Use steps_mapping.default_steps_dir
    ↓
Found: ./tests/steps/version_1_0
    ↓
Discover all steps from default directory
    ↓
Use shared steps from default directory
```

**Workflow with no configuration:**
```
defineIssuanceTest("MyCustomTest")
    ↓
Check steps_mapping.mapping["MyCustomTest"]
    ↓
Not found → Check steps_mapping.default_steps_dir
    ↓
Not found
    ↓
Throw Error: No steps_mapping entry or default_steps_dir configured
```

### Auto-Discovery Process

When you call `defineIssuanceTest("MyTest")` or `definePresentationTest("MyTest")`:

1. **Steps Directory Resolution**: 
   - First looks up `config.steps_mapping.mapping["MyTest"]` for specific mapping
   - If not found, falls back to `config.steps_mapping.default_steps_dir`
   - Throws error if neither is configured
   
2. **Custom Step Discovery**: Scans for `.ts` files matching `custom_step_pattern` (default: `**/*.ts`)
   - Excludes `**/*.spec.ts` (test files)
   - Reads and imports each TypeScript file

3. **Prototype Chain Inspection**: Checks which base class each export extends
   - Uses `Object.getPrototypeOf()` to walk the prototype chain
   - Compares against known base classes (e.g., `AuthorizeDefaultStep`)

4. **Step Type Mapping**: Maps discovered steps to configuration keys
   - `AuthorizeITWallet1_0Step extends AuthorizeDefaultStep` → `authorize`
   - `CustomTokenStep extends TokenRequestDefaultStep` → `tokenRequest`

5. **Configuration Creation**: Builds `IssuerTestConfiguration` or `PresentationTestConfiguration`
   - Injects discovered custom steps
   - Uses default steps for any non-overridden steps (with stub warning)

**File Patterns (configurable in config.ini):**
- `spec_pattern`: Pattern for test spec files (default: `**/*.spec.ts`)
- `custom_step_pattern`: Pattern for custom step files (default: `**/*.ts`)

**Excluded from discovery:**
- `**/*.spec.ts` - Test spec files

**No longer used:**
- `**/step-options.ts` - Step options have been removed in this refactoring

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
- Requires `steps_mapping[name]` to be configured in `config.ini` [steps_mapping] section
- Throws an error if `credential_types` is empty or `steps_mapping` entry is missing
- Automatically discovers custom steps from the directory specified in `steps_mapping[name]`
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
  "authorize": AuthorizeITWallet1_0Step,
  "tokenRequest": TokenRequestITWallet1_0Step,
  "credentialRequest": CredentialRequestITWallet1_0Step
}
```

---

## 🐛 Troubleshooting

### "No credential types configured"

**Cause**: The `credential_types[]` array in config.ini is empty or not configured.

**Solution**:
1. Add credential types to `config.ini`:
   ```ini
   [issuance]
   credential_types[] = dc_sd_jwt_EuropeanDisabilityCard
   ```
2. Or override via CLI:
   ```bash
   wct test:issuance --credential-types "dc_sd_jwt_MyCredential"
   ```

### Tests not found

**Cause**: Test directory or pattern mismatch.

**Solution**:
1. Check `tests_dir` in `config.ini` matches your directory structure
2. Verify test files match the `spec_pattern` (default: `**/*.spec.ts`)
3. Try running with `--issuance-tests-dir` or `--presentation-tests-dir` to override

### Custom step not detected

**Cause**: Custom step doesn't extend a recognized base class, file is excluded, or wrong discovery directory.

**Solution**:
1. Ensure your custom step extends one of the base classes:
   - Issuance: `FetchMetadataDefaultStep`, `PushedAuthorizationRequestDefaultStep`, `AuthorizeDefaultStep`, etc.
   - Presentation: `AuthorizationRequestDefaultStep`, `RedirectUriDefaultStep`, etc.
2. Check that the file is not named `*.spec.ts` (excluded from discovery)
3. Verify the file matches `custom_step_pattern` in config.ini (default: `**/*.ts`)
4. Make sure the custom step class is exported: `export class MyCustomStep extends BaseStep { ... }`
5. **Check `steps_mapping` configuration**: If your test uses `steps_mapping`, ensure the mapped directory contains the step implementations
6. **Verify discovery directory**: Check logs to see which directory is being scanned for steps

**Debug Steps:**
```bash
# Check what directory is being scanned
wct test:issuance --log-level DEBUG

# Look for log entries like:
# [TestLoader] steps_mapping: resolved 'MyTest' -> /path/to/steps

# If steps_mapping is missing, you'll get an error:
# Error: No steps_mapping entry found for test 'MyTest'
```

### Missing steps_mapping configuration

**Cause**: Test name not found in `[steps_mapping]` section of config.ini.

**Symptoms**:
```
Error: No steps_mapping entry found for test 'MyTestName'.
Please add the following to your config.ini:

[steps_mapping]
MyTestName = tests/steps/version_1_0/issuance
```

**Solution**:
1. **Add mapping to config.ini**: Add the test name to `[steps_mapping]` section
   ```ini
   [steps_mapping]
   MyTestName = ./tests/steps/version_1_0/issuance
   ```
2. **Or use default_steps_dir**: Configure a default directory that will be used as fallback
   ```ini
   [steps_mapping]
   default_steps_dir = ./tests/steps/version_1_0
   ```
3. **Create step directory**: Ensure the mapped directory exists and contains your custom step implementations
4. **Match test name**: The key in `steps_mapping` must exactly match the name passed to `defineIssuanceTest()` or `definePresentationTest()`

### Partial step implementation (using step merge)

**Use Case**: You want to customize only some steps and use default implementations for others.

**Example Scenario**:
```
You have a custom AuthorizeStep but want to reuse all other steps from version_1_0
```

**Solution**:
```ini
[steps_mapping]
# Default directory with all step implementations
default_steps_dir = ./tests/steps/version_1_0

# Your test directory with only AuthorizeStep
MyPartialTest = ./tests/my-partial-test
```

**Directory Structure**:
```
tests/
├── my-partial-test/
│   └── authorize-step.ts        # Only this step is custom
└── steps/version_1_0/
    ├── authorize-step.ts        # Will be ignored (overridden)
    ├── token-request-step.ts    # Will be used
    ├── credential-request-step.ts # Will be used
    └── ...                      # All other steps will be used
```

**How it works**:
1. System discovers `AuthorizeStep` from `./tests/my-partial-test`
2. System discovers all steps from `./tests/steps/version_1_0` (default_steps_dir)
3. Merges with priority: custom steps override default steps
4. Result: Your custom `AuthorizeStep` + 5 default steps from version_1_0

**Benefits**:
- Reuse existing step implementations
- Override only what you need
- Maintain consistency across tests
- Easier maintenance and updates

### Default steps log warnings

**Cause**: Test is using default step stubs that only log warnings.

**Symptoms**:
```
[STEP_NAME] Method not implemented.
```

**Solution**:
1. **Implement custom steps**: Default steps now contain only stub implementations
2. **Use shared versioned steps**: Configure `steps_mapping` to use pre-implemented steps:
   ```ini
   [steps_mapping]
   MyTest = ./tests/steps/version_1_0/issuance
   ```
3. **Create your own implementation**: Extend the default step class and override the `run()` method
4. See `tests/steps/version_1_0/` for reference implementations

### Step signature/interface mismatch

**Cause**: Step implementations don't match the expected interface after refactoring.

**Symptoms**:
- Type errors when extending step classes
- Missing required parameters in `run()` method

**Solution**:
1. Check the base class signature - it may have changed in this refactoring
2. Update your step implementation to match the new signature
3. Refer to `tests/steps/version_1_0/` for updated examples
4. Common changes:
   - Some step options interfaces have been simplified
   - Return types may have been updated
   - Parameter passing may have changed

### "Error checking inheritance" or unexpected discovery behavior

**Cause**: Prototype chain inspection issue.

**Solution**:
1. Check that your custom step properly extends the base class
2. Verify the base class is imported correctly
3. Ensure you're using `extends` keyword in class declaration
4. Check the console for detailed error messages from `TestLoader`

---

## 📖 Additional Resources

- [IT Wallet Documentation](https://italia.github.io/eid-wallet-it-docs/)
- [Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html)
- [Credential Verifier Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-presentation.html)
