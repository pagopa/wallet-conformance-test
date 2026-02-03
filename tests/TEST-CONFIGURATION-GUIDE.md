# 🚀 Test Configuration Guide: Complete Reference

This comprehensive guide shows you how to configure and run conformance tests with the new auto-discovery system.

## 🏗️ Architecture Overview

The test system uses a **convention-over-configuration** approach with automatic discovery of custom steps and options:

```
Test Spec File (*.spec.ts)
    ↓
Calls defineIssuanceTest() or definePresentationTest()
    ↓
Auto-discovers custom steps and options from test directory
    ↓
Returns test configuration(s)
    ↓
Test suite uses returned configuration
    ↓
Vitest executes tests
```

### Key Concepts

- **Auto-Discovery**: Custom steps and options are automatically discovered from the test directory using prototype chain inspection
- **Minimal Metadata**: Test specs only need to define a unique test `name` (string) - no object required
- **Directory-Based Configuration**: Custom steps can be placed in the same directory as the test spec
- **Configuration Hierarchy**: CLI options > Custom INI > Default INI
- **Required Configuration**: `credential_types[]` must be configured in `config.ini` for issuance tests

## 📁 Directory Structure

```
tests/
├── issuance/                          # Issuance test directory (configured in config.ini)
│   └── happy-flow/
│       ├── happy.issuance.spec.ts     # Test spec (uses defineIssuanceTest)
│       ├── custom-authorize.ts        # Optional: Custom authorize step implementation
│       └── step-options.ts            # Optional: Centralized step options
│
├── presentation/                      # Presentation test directory (configured in config.ini)
│   └── happy-flow/
│       ├── happy.presentation.spec.ts # Test spec (uses definePresentationTest)
│       └── step-options.ts            # Optional: Centralized step options
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
// tests/issuance/my-test/my-test.issuance.spec.ts

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

### Step 2: (Optional) Add Custom Steps

If you need custom step behavior, create a custom step class in the same directory:

```typescript
// tests/issuance/my-test/custom-authorize.ts

import { AuthorizeDefaultStep } from "@/step/issuance";

export class CustomAuthorizeStep extends AuthorizeDefaultStep {
  async run(context) {
    // Your custom implementation
    return super.run(context);
  }
}
```

The system automatically detects custom steps by inspecting the prototype chain - no registration needed!

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

Test directories are configured in `config.ini`:

```ini
[issuance]
url = https://issuer.example.com
tests_dir = ./tests/issuance  # Directory for issuance test specs
credential_types[] = dc_sd_jwt_EuropeanDisabilityCard

[presentation]
authorize_request_url = https://verifier.example.com/....
tests_dir = ./tests/presentation  # Directory for presentation test specs

[testing]
spec_pattern = **/*.spec.ts  # Pattern for test spec files
custom_step_pattern = **/*.ts  # Pattern for custom step files
```

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

Custom steps are automatically discovered by the `TestLoader` based on prototype chain inspection:

```
tests/issuance/my-test/
├── my-test.issuance.spec.ts   # Test spec
├── custom-authorize.ts         # Custom authorize step (auto-discovered)
├── custom-token.ts             # Custom token step (auto-discovered)
└── step-options.ts             # Centralized step options (optional)
```

#### Example: Custom Step Class

```typescript
// tests/issuance/my-test/custom-authorize.ts

import { AuthorizeDefaultStep, AuthorizeStepOptions } from "@/step/issuance";

export class CustomAuthorizeStep extends AuthorizeDefaultStep {
  async run(context) {
    // Pre-processing
    console.log("Custom authorize step running");
    
    // Call parent implementation
    const result = await super.run(context);
    
    // Post-processing
    return result;
  }
}
```

**How it works:**
1. `TestLoader.discoverCustomSteps()` scans the test directory
2. Uses prototype chain inspection to detect which base class each custom step extends
3. Automatically maps it to the correct step type (e.g., `CustomAuthorizeStep` → `authorize`)

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
- `AuthorizationRequestDefaultStep` → `authorize` (internal: `authorizationRequest`)
- `RedirectUriDefaultStep` → `redirectUri`

### Step Options

You can configure step options in two ways:

#### 1. Centralized Options File

```typescript
// tests/issuance/my-test/step-options.ts

export const authorize = {
  timeout: 30000,
  customOption: "value"
};

export const tokenRequest = {
  retries: 3
};
```

#### 2. Inline Options (in Custom Step File)

```typescript
// tests/issuance/my-test/custom-authorize.ts

import { AuthorizeDefaultStep } from "@/step/issuance";

export class CustomAuthorizeStep extends AuthorizeDefaultStep {
  // ... implementation
}

// Inline options (has precedence over centralized options)
export const options = {
  timeout: 30000,
  customOption: "value"
};
```

**Precedence**: Inline options > Centralized options

### Auto-Discovery Process

When you call `defineIssuanceTest("MyTest")`:

1. **Caller Directory Detection**: Determines the test directory using stack trace inspection
2. **Custom Step Discovery**: Scans for `.ts` files matching `custom_step_pattern` (default: `**/*.ts`)
3. **Prototype Chain Inspection**: Checks which base class each export extends
4. **Step Type Mapping**: Maps discovered steps to configuration keys
5. **Options Discovery**: Loads both centralized (`step-options.ts`) and inline options
6. **Configuration Creation**: Builds `IssuerTestConfiguration` with discovered customizations

**File Patterns (configurable in config.ini):**
- `spec_pattern`: Pattern for test spec files (default: `**/*.spec.ts`)
- `custom_step_pattern`: Pattern for custom step files (default: `**/*.ts`)

**Excluded from discovery:**
- `**/*.spec.ts` - Test spec files
- `**/step-options.ts` - Options configuration file

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
- Automatically discovers custom steps from the caller's directory
- Automatically discovers step options from `step-options.ts` or inline exports

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

Internal utility class that handles auto-discovery of custom steps and options.

#### `testLoader.discoverCustomSteps(directory)`

Scans a directory for custom step implementations using prototype chain inspection.

**Parameters**:
- `directory` (string): Absolute path to scan

**Returns**: `Promise<Record<string, any>>` - Map of step type to step class

**Internal use only** - Called automatically by `defineIssuanceTest()` and `definePresentationTest()`

#### `testLoader.discoverStepOptions(directory, customSteps)`

Scans for step options in centralized `step-options.ts` or inline exports.

**Parameters**:
- `directory` (string): Absolute path to scan
- `customSteps` (Record<string, any>): Previously discovered custom steps

**Returns**: `Promise<Record<string, any>>` - Map of step type to options object

**Internal use only** - Called automatically by `defineIssuanceTest()` and `definePresentationTest()`

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

**Cause**: Custom step doesn't extend a recognized base class or file is excluded.

**Solution**:
1. Ensure your custom step extends one of the base classes:
   - Issuance: `FetchMetadataDefaultStep`, `PushedAuthorizationRequestDefaultStep`, `AuthorizeDefaultStep`, etc.
   - Presentation: `AuthorizationRequestDefaultStep`, `RedirectUriDefaultStep`, etc.
2. Check that the file is not named `*.spec.ts` or `step-options.ts` (excluded from discovery)
3. Verify the file matches `custom_step_pattern` in config.ini (default: `**/*.ts`)
4. Make sure the custom step class is exported: `export class MyCustomStep extends BaseStep { ... }`

### Step options not applied

**Cause**: Options file not detected or naming mismatch.

**Solution**:
1. For centralized options, create `step-options.ts` in the test directory:
   ```typescript
   export const authorize = { timeout: 30000 };
   ```
2. For inline options, export `options` in the same file as your custom step:
   ```typescript
   export const options = { timeout: 30000 };
   ```
3. Ensure the export name matches the step type (e.g., `authorize`, `tokenRequest`, not `authorizeOptions`)

### "Error checking inheritance" or unexpected discovery behavior

**Cause**: Prototype chain inspection issue.

**Solution**:
1. Check that your custom step properly extends the base class
2. Verify the base class is imported correctly
3. Ensure you're using `extends` keyword in class declaration
4. Check the console for detailed error messages from `TestLoader`

---

## 🔄 Migration from Legacy System

If you have tests using the old `test.config.ts` or registry-based system:

### Before (Legacy Registry System)
```typescript
// tests/test.config.ts
const testConfig = IssuerTestConfiguration.createCustom({
  name: "My Test",
  credentialConfigurationId: "dc_sd_jwt_MyCredential",
});
issuerRegistry.registerTest(HAPPY_FLOW_NAME, testConfig);

// tests/issuance/my-test.spec.ts
import "../test.config";
issuerRegistry.get(HAPPY_FLOW_NAME).forEach((testConfig) => {
  // tests
});
```

### After (New Auto-Discovery System)
```typescript
// tests/issuance/my-test/my-test.issuance.spec.ts
import { defineIssuanceTest } from "#/config/test-metadata";

// Define and get test configurations (auto-discovers custom steps)
const testConfigs = await defineIssuanceTest("MyTest");

// Use the returned configurations
testConfigs.forEach((testConfig) => {
  describe(`[${testConfig.name}] Tests`, () => {
    // tests
  });
});
```

**Key Changes:**
1. **No centralized config file**: Each test is self-contained
2. **No manual registration**: `defineIssuanceTest()` returns configurations directly
3. **No registry lookups**: Configurations returned from define function
4. **Automatic discovery**: Custom steps are found via prototype chain inspection
5. **Directory-based customization**: Custom steps and options live with the test

**Credential Types:**
- Previously: Configured in test metadata or `test.config.ts`
- Now: Exclusively configured in `config.ini` [issuance] section

**Custom Steps:**
- Previously: Manually specified in test configuration object
- Now: Automatically discovered from test directory using `extends` detection

**Benefits:**
- No centralized `test.config.ts` file to maintain
- Tests are self-contained and easier to understand
- Easier to add new tests (just create a new file)
- Configuration co-located with test implementation
- Less boilerplate code
- Type-safe step detection via prototype chain

### Migration Checklist

- [ ] Remove centralized `test.config.ts` file
- [ ] Update test specs to use `await defineIssuanceTest()` or `await definePresentationTest()`
- [ ] Remove `export const testName` and registry imports
- [ ] Use returned configurations instead of `registry.get()`
- [ ] Move custom step classes to test directory (optional)
- [ ] Create `step-options.ts` for step configuration (optional)
- [ ] Move credential types to `config.ini` [issuance] section
- [ ] Update test file naming to match pattern (e.g., `*.issuance.spec.ts`)
- [ ] Test auto-discovery is working correctly

---

## 📖 Additional Resources

- [IT Wallet Documentation](https://italia.github.io/eid-wallet-it-docs/)
- [Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html)
- [Credential Verifier Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-presentation.html)
- [CLAUDE.md](../CLAUDE.md) - Developer guide for this codebase
