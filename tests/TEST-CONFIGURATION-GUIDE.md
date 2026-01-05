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
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { PresentationTestConfiguration } from "./config/presentation-test-configuration";
import { issuerRegistry, presentationRegistry } from "./config/test-registry";

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest"; // Reference to happy.issuance.spec.ts
export const HAPPY_FLOW_PRESENTATION_NAME = "HappyFlowPresentationTest"; // Reference to happy.presentation.spec.ts

const happyFlowCredentialConfig = IssuerTestConfiguration.createCustom({
  credentialConfigurationId: "dc_sd_jwt_EuropeanDisabilityCard",
  name: "Happy Flow EuropeanDisabilityCard Test",
});

issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, happyFlowCredentialConfig);
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

Test a different credential type (e.g., DrivingLicense).

```typescript
// test.config.ts
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

const mdlConfig = IssuerTestConfiguration.createCustom({
  name: "DrivingLicense Test",
  credentialConfigurationId: "dc_sd_jwt_DrivingLicense",
});

issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, mdlConfig);
```

**Run**: `pnpm test:issuance`

---

### Example 2: Multiple Credential Types

Test multiple credential types in one run.

```typescript
// test.config.ts
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

const pidConfig = IssuerTestConfiguration.createCustom({
  name: "PersonIdentificationData Test",
  credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
});

const mdlConfig = IssuerTestConfiguration.createCustom({
  name: "DrivingLicense Test",
  credentialConfigurationId: "dc_sd_jwt_DrivingLicense",
});

// Option 1: Register individually
issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, pidConfig);
issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, mdlConfig);

// Option 2: Register multiple at once
// issuerRegistry.registerMany(HAPPY_FLOW_ISSUANCE_NAME, [pidConfig, mdlConfig]);
```

**Run**: `pnpm test:issuance`  
**Result**: Both configurations will run automatically

---

### Example 3: Environment-Based Configuration

Use different configurations for dev/prod environments.

```typescript
// test.config.ts
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

const environment = process.env.TEST_ENV || "dev";

const configs = {
  dev: "dc_sd_jwt_DevCredential",
  prod: "dc_sd_jwt_ProdCredential",
};

const credentialId = configs[environment as keyof typeof configs];

const envConfig = IssuerTestConfiguration.createCustom({
  name: `${environment.toUpperCase()} Test`,
  credentialConfigurationId: credentialId,
});

issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, envConfig);
```

**Run**:
- Dev: `pnpm test:issuance`
- Prod: `TEST_ENV=prod pnpm test:issuance`

---

### Example 4: Custom Metadata Path

Use a custom well-known path for federation metadata.

```typescript
// test.config.ts
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

const customMetadataConfig = IssuerTestConfiguration.createCustom({
  name: "Custom Metadata Path Test",
  credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
  fetchMetadata: {
    options: {
      wellKnownPath: "/.well-known/custom-federation",
    },
  },
});

issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, customMetadataConfig);
```

**Run**: `pnpm test:issuance`

---

### Example 5: Custom Step Classes

Replace default step implementations with custom ones for testing scenarios.

```typescript
// test.config.ts
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";
import { FetchMetadataHardcodedStep } from "@/step/issuance/fetch-metadata-hardcoded-step";

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

const hardcodedMetadataConfig = IssuerTestConfiguration.createCustom({
  name: "Hardcoded Metadata Fetch Test",
  credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
  fetchMetadata: {
    stepClass: FetchMetadataHardcodedStep,
  },
});

issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, hardcodedMetadataConfig);
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
import { IssuerTestConfiguration } from "./config/issuance-test-configuration";
import { issuerRegistry } from "./config/test-registry";

export const HAPPY_FLOW_ISSUANCE_NAME = "HappyFlowIssuanceTest";

const advancedConfig = IssuerTestConfiguration.createCustom({
  name: "Advanced Combined Test",
  credentialConfigurationId: "dc_sd_jwt_PersonIdentificationData",
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
- [ ] `credentialConfigurationId` is correct (for issuance tests)
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
