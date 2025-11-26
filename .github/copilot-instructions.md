# Copilot Instructions for wallet-conformance-test

## Project Overview

This is an automated conformance testing tool for the **Italian IT Wallet ecosystem** (EUDI Wallet). It validates Credential Issuers and Relying Parties against Italian/European technical specifications using **OpenID Federation**, **OpenID4VCI**, and **SD-JWT/mDOC** standards.

**Tech Stack**: TypeScript, Node.js, Vitest, Express (Trust Anchor server)  
**Core Dependencies**: `@pagopa/io-wallet-*` libraries (OAuth2, OID Federation, OID4VCI, OID4VP), `@sd-jwt/*`, `@auth0/mdl`

## Architecture Patterns

### 1. Orchestrator-Step Pattern (Critical to Understand)

The codebase uses a **two-layer architecture** for test flows:

```
Orchestrator (Flow Coordinator) → Steps (Individual Actions)
```

**Orchestrators** (`src/orchestrator/`):
- `WalletIssuanceOrchestratorFlow`: Coordinates credential issuance tests
- `WalletPresentationOrchestratorFlow`: Coordinates credential presentation tests
- Load config, initialize logger, coordinate multiple steps, handle wallet attestations

**Steps** (`src/step/`):
- Inherit from `StepFlow` abstract class (`src/step/step-flow.ts`)
- Each step has a `tag` property for logging and a `run()` method
- Use `execute()` helper for try-catch wrapping and consistent error handling
- Examples: `FetchMetadataDefaultStep`, `PushedAuthorizationRequestDefaultStep`

**Key Pattern**: Steps are **pluggable** - tests can use custom step classes via configuration:

```typescript
// Default step usage
new FetchMetadataDefaultStep(config, log)

// Custom step usage (injected via test config)
new FetchMetadataHardcodedStep(config, log)  // For mocking
```

### 2. Test Registry Pattern

Tests use a **registry system** for configuration management:

```
tests/test.config.ts → Registers configs → Registry → Test suite retrieves
```

**Flow**:
1. `tests/test.config.ts`: Define flow name constants (e.g., `HAPPY_FLOW_ISSUANCE_NAME`)
2. Create `IssuerTestConfiguration` instances with credential types and options
3. Register configurations: `issuerRegistry.registerTest(FLOW_NAME, config)`
4. Test specs retrieve configs: `issuerRegistry.get(FLOW_NAME).forEach(testConfig => {...})`

**Why**: Supports multiple test configurations per flow, environment-based testing, and custom step injection.

### 3. JWK/JWT Management

- **Key Generation**: `src/logic/jwk.ts` - generates ES256 keys with KSUID-based `kid`
- **Key Storage**: Keys stored in `backup_storage_path` (e.g., `wallet_provider_jwks`, `issuer_jwks`)
- **JWT Signing**: `signJwtCallback()` in `src/logic/jwt.ts` wraps signing with proper headers
- **Federation Metadata**: `src/logic/federation-metadata.ts` creates OpenID Federation entity configurations

**Critical**: All JWKs now include `alg: "ES256"` field (recent change in `feature/WLEO-702-load-config` branch)

### 4. Configuration System

**Hierarchy** (highest to lowest precedence):
1. Command-line options
2. Custom `.ini` file (`--file-ini`)
3. Default `config.ini`

**Config Schema** (`src/types/config.ts`): Uses Zod for validation with sections:
- `[wallet]`: Instance ID, provider URL, storage paths
- `[trust]`: CA certs, eIDAS lists, federation trust anchors
- `[issuance]`: Credential issuer URLs and credential type mappings
- `[network]`: Timeouts, retries, user agent
- `[server]`: Trust Anchor local server port (default: 3001)
- `[logging]`: Level, format, file path

**Path Aliases**: 
- `@/*` maps to `src/*`
- `#/*` maps to `tests/*`

## Development Workflows

### Running Tests

```bash
# All tests
pnpm test

# Unit tests only
pnpm test:unit

# Issuance conformance tests
pnpm test:issuance

# Presentation conformance tests
pnpm test:presentation

# Watch mode
pnpm test:watch
```

### Trust Anchor Server

**Auto-starts** in tests via `tests/global-setup.ts` on `http://localhost:3001`.

Manual start for debugging:
```bash
pnpm ta:server
```

**Purpose**: Provides OpenID Federation root metadata for test federation chains.

### Code Quality Checks

```bash
pnpm types:check      # TypeScript type checking (no emit)
pnpm lint             # ESLint with auto-fix
pnpm format           # Prettier formatting
pnpm code-review      # Full pre-merge check (types + lint + format + build + test)
```

**Git Hooks**:
- Pre-commit: `pnpm pre-commit` (format + lint)
- Pre-push: `pnpm pre-push` (pre-commit + types:check + test)

### Building & Running CLI

```bash
pnpm build                    # Compile TypeScript to dist/
pnpm link --global            # Make CLI available globally

# Run CLI
wallet-conformance-test test:issuance --credential-type PersonIdentificationData
```

## Project-Specific Conventions

### File Naming
- **Type files**: lowercase (e.g., `config.ts`, `credential.ts`, `logger.ts`) - changed from PascalCase in recent branch
- **Implementation files**: kebab-case (e.g., `load-attestation.ts`, `federation-metadata.ts`)
- **Test files**: `*.spec.ts` for Vitest tests

### Import Organization
- External dependencies first
- Internal imports from `@/` second
- Type imports separated or inline with `type` keyword

### Error Handling
- Steps use `execute()` wrapper for consistent try-catch
- Orchestrators catch errors and log with context
- Use custom error types from `@pagopa/io-wallet-utils` (e.g., `ValidationError`)

### Logging
- Logger from `@/logic/logs` with `.withTag()` for context
- Standard tags: `"FETCH METADATA"`, `"PUSHED_AUTHORIZATION_REQUEST"`, `"CI_001"` (test IDs)
- Log levels: `.info()`, `.debug()`, `.success()`, `.error()`, `.start()`, `.testCompleted()`

### Mock Credentials

**SD-JWT Generation** (`src/functions/mock-credentials.ts`):
- Uses `@sd-jwt/sd-jwt-vc` library
- Creates test PIDs (PersonIdentificationData) with selective disclosure
- Includes trust chain in JWT header
- **Bug Fix Needed**: Line 112 has `kid: issuer.keyPair.privateKey` (should be `.kid`)

**mDOC Generation**: Uses `@auth0/mdl` library for mDL credentials

## Integration Points

### External Services
- **Credential Issuers**: Defined in `[issuance]` config section
- **Trust Anchors**: Federation root entities, configured in `[trust]` section
- **eIDAS Trusted Lists**: Optional, for X.509 certificate validation

### Key Libraries
- `@pagopa/io-wallet-oid-federation`: Federation entity configuration, trust chain resolution
- `@pagopa/io-wallet-oid4vci`: Credential issuance protocol (wallet attestation, PAR, token)
- `@pagopa/io-wallet-oauth2`: OAuth2/DPoP/client attestation
- `@sd-jwt/core`, `@sd-jwt/sd-jwt-vc`: SD-JWT credential handling
- `jose`: Low-level JWT/JWK operations

## Common Tasks

### Adding a New Test Configuration

1. Open `tests/test.config.ts`
2. Create configuration:
   ```typescript
   const myConfig = IssuerTestConfiguration.createCustom({
     testName: "My Custom Test",
     credentialConfigurationId: "dc_sd_jwt_MyCredential",
   });
   ```
3. Register: `issuerRegistry.registerTest(HAPPY_FLOW_ISSUANCE_NAME, myConfig)`

### Creating a Custom Step

1. Create file in `src/step/issuance/my-custom-step.ts`
2. Extend `StepFlow`:
   ```typescript
   export class MyCustomStep extends StepFlow {
     tag = "MY_CUSTOM_STEP";
     
     async run(options: MyOptions): Promise<MyResponse> {
       return this.execute(async () => {
         // Implementation
       });
     }
   }
   ```
3. Use in test config:
   ```typescript
   fetchMetadata: {
     stepClass: MyCustomStep,
     options: { /* custom options */ }
   }
   ```

### Loading Test Credentials

Use `loadCredentials()` from `@/functions`:
```typescript
const credentials = await loadCredentials({
  credentialsPath: config.wallet.credentials_storage_path,
  credentialType: "dc_sd_jwt_PersonIdentificationData"
});
```

## Known Issues & Gotchas

1. **JWK `kid` field**: Recent changes added `alg` field - ensure all consumers handle it
2. **Mock credentials bug**: `createMockSdJwt()` passes entire private key object instead of `kid` to JWT header (line 112)
3. **Trust Anchor startup**: Tests automatically start server - don't run `pnpm ta:server` concurrently
4. **Config paths**: Use absolute paths in `.ini` or relative to project root
5. **Vitest configs**: Three separate configs (`vitest.config.mjs`, `vitest.unit.config.mjs`, `vitest.issuance.config.mjs`) with different test patterns

## Reference Files

- **Architecture**: `src/orchestrator/wallet-issuance-orchestrator-flow.ts`, `src/step/step-flow.ts`
- **Test Configuration**: `tests/TEST-CONFIGURATION-GUIDE.md`, `tests/test.config.ts`
- **Config Schema**: `src/types/config.ts`, `config.example.ini`
- **Key Management**: `src/logic/jwk.ts`, `src/functions/load-attestation.ts`
- **Federation**: `src/logic/federation-metadata.ts`, `src/trust-anchor/server.ts`
