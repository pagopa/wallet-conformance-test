# 🚀 Test Configuration Guide: Complete Reference

This comprehensive guide shows you how to configure and run Issuer conformance tests, from quick start to advanced customization.

## 📋 Prerequisites

- Repository cloned
- Dependencies installed (`pnpm install`)

---

## 🎯 Quick Start

### Step 1: Use the Default Configuration

The default configuration is already set up in `tests/test.config.ts`:

```typescript
import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { PresentationTestConfiguration } from "./config/presentation-test-configuration";
import { issuerRegistry, presentationRegistry } from "./config/test-registry";

// Load configuration (credential types come from config.ini or CLI)
const config = loadConfigWithHierarchy();
const credentialTypes = config.issuance.credential_types || ["dc_sd_jwt_EuropeanDisabilityCard"];

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";
export const HAPPY_FLOW_PRESENTATION_NAME = "HappyFlowPresentationTest";

// Automatically register tests for each credential type
for (const credentialType of credentialTypes) {
  const testConfig = IssuerTestConfiguration.createCustom({
    name: `Happy Flow ${credentialType} Test`,
  });
  issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, testConfig);
}

presentationRegistry.registerTest(HAPPY_FLOW_PRESENTATION_NAME, PresentationTestConfiguration.createDefault());
```

### Step 2: Run the Tests

```bash
pnpm test:issuance
```

### Step 3: View Results

```
[SETUP|ISS] ℹ Setting Up Wallet conformance Tests
[SETUP|ISS] ℹ Loading Configuration...
[Issuance Happy Flow]: Starting Issuer Flow Tests...
...
✓ CI-001: Federation Entity publishes its own Entity Configuration
✓ CI-002: Entity Configuration response media type check
✓ CI-003: The Entity Configuration is cryptographically signed
...
```

**That's it!** You're running tests. Read on to customize your configuration.

---

## 🏗️ How It Works

The test configuration system has four main components:

1. **Configuration File (`test.config.ts`)**: Where you define and register test configurations
2. **Flow Names**: Constants that identify which test flow to run (e.g., `HAPPY_FLOW_ISSUANCE_NAME`, `HAPPY_FLOW_PRESENTATION_NAME`)
3. **Registries (`issuerRegistry`, `presentationRegistry`)**: Manage all registered configurations organized by flow name
4. **Test Suites (`happy.issuance.spec.ts`, `happy.presentation.spec.ts`)**: Automatically load and run configurations

**Flow:**
```
test.config.ts → Registers configs → Registry → Test suite retrieves configs → Tests run
```

---

## 📚 Configuration Examples


### Example 1: Custom Credential Type

Test different credential types by configuring them in `config.ini` or via CLI.

**Option 1: Using config.ini**
```ini
[issuance]
credential_types[] = dc_sd_jwt_DrivingLicense
credential_types[] = dc_sd_jwt_PersonIdentificationData
```

**Option 2: Using CLI**
```bash
pnpm test:issuance -- --credential-types dc_sd_jwt_DrivingLicense,dc_sd_jwt_PersonIdentificationData
```

The test configuration will automatically pick up these credential types:
```typescript
// test.config.ts (no changes needed)
import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

const config = loadConfigWithHierarchy();
const credentialTypes = config.issuance.credential_types || ["dc_sd_jwt_EuropeanDisabilityCard"];

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

for (const credentialType of credentialTypes) {
  issuerRegistry.registerTest(
    HAPPY_FLOW_ISSUANCE_NAME,
    IssuerTestConfiguration.createCustom({
      name: `Happy Flow ${credentialType} Test`,
    })
  );
}
```

**Run**: `pnpm test:issuance`

---

### Example 2: Multiple Credential Types

Test multiple credential types in one run by specifying them in `config.ini` or via CLI.

**Using config.ini:**
```ini
[issuance]
credential_types[] = dc_sd_jwt_PersonIdentificationData
credential_types[] = dc_sd_jwt_DrivingLicense
credential_types[] = dc_sd_jwt_EuropeanDisabilityCard
```

**Using CLI:**
```bash
pnpm test:issuance -- --credential-types dc_sd_jwt_PersonIdentificationData,dc_sd_jwt_DrivingLicense,dc_sd_jwt_EuropeanDisabilityCard
```

**No changes needed in test.config.ts** - the system automatically creates test configurations for each credential type:
```typescript
// The loop in test.config.ts automatically handles multiple types
for (const credentialType of credentialTypes) {
  issuerRegistry.registerTest(
    HAPPY_FLOW_ISSUANCE_NAME,
    IssuerTestConfiguration.createCustom({
      name: `Happy Flow ${credentialType} Test`,
    })
  );
}
```

**Run**: `pnpm test:issuance`  
**Result**: All configured credential types will run automatically

---

### Example 3: Environment-Based Configuration

Use different credential types for dev/prod environments.

**Create environment-specific config files:**

`config.dev.ini`:
```ini
[issuance]
credential_types[] = dc_sd_jwt_DevCredential
```

`config.prod.ini`:
```ini
[issuance]
credential_types[] = dc_sd_jwt_ProdCredential
```

**Or use CLI with environment variables:**
```bash
# Dev
pnpm test:issuance -- --credential-types dc_sd_jwt_DevCredential

# Prod
pnpm test:issuance -- --credential-types dc_sd_jwt_ProdCredential
```

**The test.config.ts automatically adapts** to the loaded configuration:
```typescript
// No environment-specific code needed - it's handled by config loading
const config = loadConfigWithHierarchy();
const credentialTypes = config.issuance.credential_types || ["dc_sd_jwt_EuropeanDisabilityCard"];
```

---

### Example 4: Custom Metadata Path

Use a custom well-known path for federation metadata.

```typescript
// test.config.ts
import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

const config = loadConfigWithHierarchy();
const credentialTypes = config.issuance.credential_types || ["dc_sd_jwt_EuropeanDisabilityCard"];

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

for (const credentialType of credentialTypes) {
  const customMetadataConfig = IssuerTestConfiguration.createCustom({
    name: `Custom Metadata ${credentialType} Test`,
    fetchMetadata: {
      options: {
        wellKnownPath: "/.well-known/custom-federation",
      },
    },
  });
  issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, customMetadataConfig);
}
```

**Run**: `pnpm test:issuance`

---

### Example 5: Custom Step Classes

Replace default step implementations with custom ones for testing scenarios.

```typescript
// test.config.ts
import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";
import { FetchMetadataHardcodedStep } from "@/step/issuance/fetch-metadata-hardcoded-step";

const config = loadConfigWithHierarchy();
const credentialTypes = config.issuance.credential_types || ["dc_sd_jwt_EuropeanDisabilityCard"];

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

for (const credentialType of credentialTypes) {
  const hardcodedMetadataConfig = IssuerTestConfiguration.createCustom({
    name: `Hardcoded Metadata ${credentialType} Test`,
    fetchMetadata: {
      stepClass: FetchMetadataHardcodedStep,
    },
  });
  issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, hardcodedMetadataConfig);
}
```

**Use Cases**:
- Testing with mock data
- Simulating error conditions
- Testing different metadata configurations
- Bypassing network calls in tests

**Run**: `pnpm test:issuance`

---

### Example 7: Combining Options and Custom Steps

Use both custom options and custom step classes together.

```typescript
// test.config.ts
import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

const config = loadConfigWithHierarchy();
const credentialTypes = config.issuance.credential_types || ["dc_sd_jwt_EuropeanDisabilityCard"];

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

for (const credentialType of credentialTypes) {
  const advancedConfig = IssuerTestConfiguration.createCustom({
    name: `Advanced ${credentialType} Test`,
    fetchMetadata: {
      options: {
        wellKnownPath: "/.well-known/custom-federation",
      },
      // stepClass: CustomStep, // Can also specify custom step
    },
    pushedAuthorizationRequest: {
      options: {
        // Your PAR options here
      },
      // stepClass: CustomPARStep, // Can also specify custom step
    },
  });
  issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, advancedConfig);
}
```

**Run**: `pnpm test:issuance`

---

## 🔄 Managing Multiple Configurations

### Running All Configurations for a Flow

All configurations registered to the same flow name run automatically:

```typescript
// test.config.ts
export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, config1); // ✓ Will run
issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, config2); // ✓ Will run
issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, config3); // ✓ Will run
```

**Run**: `pnpm test:issuance` → All three configurations execute

### Organizing Tests into Different Flows

Create separate flows for different test scenarios:

```typescript
// test.config.ts
export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";
export const ERROR_FLOW_ISSUANCE_NAME = "ErrorFlowIssuanceTest";

// Register to happy flow
issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, happyConfig1);
issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, happyConfig2);

// Register to error flow
issuerRegistry.registerTest(ERROR_FLOW_ISSUANCE_NAME, errorConfig1);
issuerRegistry.registerTest(ERROR_FLOW_ISSUANCE_NAME, errorConfig2);
```

Then create corresponding test files:
- `tests/issuance/happy.issuance.spec.ts` → Uses `HAPPY_FLOW_ISSUANCE_NAME`
- `tests/issuance/error.issuance.spec.ts` → Uses `ERROR_FLOW_ISSUANCE_NAME`

### Quickly Switching Configurations

Comment/uncomment to activate different configs:

```typescript
// issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, config1);  // ✗ Commented out
issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, config2);     // ✓ Active
// issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, config3);  // ✗ Commented out
```

---

## ✅ Best Practices

1. **Keep configurations in `test.config.ts`**  
   Centralized location makes configs easy to find and modify

2. **Use descriptive test names**  
   Helps identify which configuration is running in logs

3. **Define flow name constants**  
   Export flow names as constants for reuse across files

4. **Start with defaults, customize incrementally**  
   Use `createDefault()` first, then add customizations as needed

5. **Use environment variables**  
   Configure different credentials for dev, staging, production

6. **Document your configurations**  
   Add comments explaining why specific configurations exist

7. **Organize by flows**  
   Group related tests using the same flow name

8. **Custom steps for testing**  
   Use custom step classes to simulate scenarios or mock data

---

## 🐛 Troubleshooting

### ❌ Error: "No test configuration registered!"

**Cause**: No configuration registered for the flow in `test.config.ts`

**Solution**: Add at least one configuration:
```typescript
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, IssuerTestConfiguration.createDefault());
```

---

## 📊 Verification Checklist

Before running tests, verify:

- [ ] `test.config.ts` exists in `tests/` directory
- [ ] Flow name constant is defined (e.g., `HAPPY_FLOW_ISSUANCE_NAME`, `HAPPY_FLOW_PRESENTATION_NAME`)
- [ ] At least one `issuerRegistry.registerTest()` or `presentationRegistry.registerTest()` call is present
- [ ] Credential types are configured in `config.ini` or via CLI (for issuance tests)
- [ ] Configuration is not commented out
- [ ] No syntax errors in file
- [ ] Flow name matches between config and test files

---

## 📂 File Structure

```
tests/
├── test.config.ts                         # ← Your configurations here
├── issuance/
│   └── happy.issuance.spec.ts             # Test suite (issuance happy flow)
├── presentation/
│   └── happy.presentation.spec.ts         # Test suite (presentation happy flow)
├── config/
│   ├── issuance-test-configuration.ts     # Issuance configuration class
│   ├── presentation-test-configuration.ts # Presentation configuration class
│   └── test-registry.ts                   # Registry system (issuerRegistry, presentationRegistry)
└── TEST-CONFIGURATION-GUIDE.md            # This guide
```

---

## 🎉 Success!

If you see test results, **congratulations!** Your tests are running.
