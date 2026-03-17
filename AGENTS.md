# AGENTS.md

Guidance for agentic coding agents working in this repository.

## Project Overview

Automated conformance testing tool for the Italian IT Wallet ecosystem. Simulates a wallet to validate Credential Issuers and Relying Parties against official Italian/European technical specifications (OpenID4VCI, OpenID4VP, OpenID Federation).

---

## Build / Lint / Test Commands

```bash
pnpm install               # Install dependencies (Node >=22.19.0, pnpm 10.x)
pnpm build                 # Compile TypeScript to dist/
pnpm types:check           # Type-check without emitting (tsc --noEmit)

# Formatting & linting
pnpm format                # Prettier write (src + tests)
pnpm format:check          # Prettier check only
pnpm lint                  # ESLint --fix
pnpm lint:check            # ESLint check only
pnpm pre-commit            # format + lint (run before every commit)
pnpm pre-push              # format + lint + type-check + all tests

# Tests
pnpm test                  # All tests (vitest run)
pnpm test:unit             # Unit tests only
pnpm test:issuance         # Issuance conformance tests
pnpm test:presentation     # Presentation conformance tests
pnpm test:issuance:unsafe  # Issuance tests with TLS verification disabled

# Run a single test file
pnpm vitest run tests/conformance/issuance/happy.issuance.spec.ts

# Run tests matching a name pattern (e.g. a single test ID)
pnpm vitest run -t "CI_001"
pnpm vitest run -t "CI_015"

# Trust Anchor server (auto-starts during test runs; manual start for debugging)
pnpm ta:server
```

---

## Architecture

### Three-layer flow pattern

1. **Orchestrator** (`src/orchestrator/`): Coordinates a complete issuance or presentation flow by calling steps in sequence and threading state between them.
2. **Step** (`src/step/`): Individual protocol steps, each extending `StepFlow`. Classes named `*DefaultStep` implement the canonical flow used by tests; optional step overrides, when present, are discovered from a `steps_mapping` directory.
3. **Test spec** (`tests/conformance/`): Calls `defineIssuanceTest()` / `definePresentationTest()`, receives configured `IssuerTestConfiguration[]`, then runs assertions against orchestrator results.

### Step result pattern

All steps return `StepResponse & { response?: T }`:

```typescript
{ success: boolean; error?: Error; durationMs?: number; response?: T }
```

Always use the inherited `execute()` helper in step implementations — it wraps actions with consistent error handling and timing.

### Step override helpers (negative tests)

For tests requiring only one or a few deviant parameters, use factory helpers instead of full new step classes:

- `withParOverrides(StepClass, overrides)` — spreads `Partial<CreatePushedAuthorizationRequestOptions>` over computed defaults.
- `withSignJwtOverride(StepClass, signJwt)` — replaces only the `signJwt` callback (preserves `generateRandom` and `hash`).

Factory helpers live in `tests/helpers/`. Add a new `withX()` helper there whenever a step gains a new `protected *Overrides` field; do **not** create full new step classes just to mutate a single option.

---

## Path Aliases (always use these — never relative `../../`)

| Alias | Resolves to |
| ----- | ----------- |
| `@/*` | `src/*`     |
| `#/*` | `tests/*`   |

---

## Code Style

### TypeScript

- **Strict mode** is enabled: `strict: true`, `noUncheckedIndexedAccess: true`. Never suppress with `any` without a clear comment.
- Target: `ES2022`, module system: `NodeNext` / `moduleResolution: NodeNext`.
- Use explicit return types on exported functions. Let inference work for internal/local functions.
- Prefer `interface` for object shapes that may be extended; use `type` for unions, intersections, and aliases.
- Zod is used for runtime validation of external data (config, API responses). Always define a schema and `z.infer<>` the type from it — never duplicate types manually.
- Use `unknown` instead of `any` for caught errors; narrow with `instanceof Error` before accessing `.message`.
- Use `asserts` type predicates for validation functions that throw on failure (see `validateCredentialTypes`).

### Imports

- Group in this order, separated by blank lines: (1) Node built-ins (`node:fs`, `node:path`), (2) external packages, (3) internal `@/` aliases, (4) internal `#/` aliases. Prettier + ESLint enforce ordering automatically.
- Named imports are preferred. Use `type` imports for type-only dependencies: `import type { Foo } from "..."`.
- Do **not** use barrel re-exports from deeply nested files; import from the nearest public `index.ts`.

### Formatting

- Prettier handles all formatting; do not manually align or wrap. Run `pnpm format` before committing.
- ESLint config extends `@pagopa/eslint-config` (flat config via `eslint.config.mjs`). Avoid `// eslint-disable` comments; if unavoidable, add a brief justification on the same line.
- The `/* eslint-disable max-lines-per-function */` directive is acceptable at the top of long test specs.

### Naming Conventions

| Concept             | Convention                                                                               |
| ------------------- | ---------------------------------------------------------------------------------------- |
| Classes             | `PascalCase` with suffix: `*DefaultStep`, `*OrchestratorFlow`                            |
| Interfaces / types  | `PascalCase` with suffix: `*Options`, `*Response`, `*Configuration`                      |
| Functions           | `camelCase`                                                                              |
| Constants           | `camelCase` for module-level; `SCREAMING_SNAKE_CASE` for true constants inside functions |
| Test IDs            | `CI_001`, `CI_015a` — always uppercase prefix + underscore                               |
| Step `tag` property | `SCREAMING_SNAKE_CASE` string literal (e.g. `"PUSHED_AUTHORIZATION_REQUEST"`)            |
| Config keys         | `snake_case` (INI convention)                                                            |

### Error Handling

- All step logic must be wrapped in `this.execute(async () => { … })`. Do not throw from `run()`; let `execute()` catch and wrap the error.
- In `catch` blocks: `error instanceof Error ? error.message : String(error)`.
- Validate at boundaries (config load, external API responses) using Zod; throw descriptive errors with context.
- Use `asserts` type predicates for guard functions that throw (`asserts x is T`).

### Logging

- Use `this.log.withTag(this.tag)` inside step implementations.
- Use `createQuietLogger()` (level 0) when running sub-steps inside conformance test helpers to avoid polluting test output.
- Log progression: `log.debug` for internals, `log.info` for key milestones, `log.error` for failures.
- Call `log.testCompleted(DESCRIPTION, testSuccess)` in every test's `finally` block.

### Testing Conventions

- Test files: `tests/conformance/issuance/*.issuance.spec.ts` or `*.presentation.spec.ts`.
- Register with `const testConfigs = await defineIssuanceTest("FlowName")` at module top-level (top-level await is valid in Vitest ESM context; suppress with `@ts-expect-error TS1309`).
- Use `beforeAll` for the shared orchestrator run; individual `test()` blocks only assert on already-collected results.
- Track pass/fail with a local `let testSuccess = false` and always update it inside `try`, call `log.testCompleted` in `finally`.
- Prefer `expect(x).toBe(y)` with a descriptive second argument for failures: `expect(result, "reason").toBe(true)`.
- Use `vi.useFakeTimers` / `vi.useRealTimers` for time-sensitive tests; restore in both `afterEach` and the `finally` block.
- Unit tests live in `tests/unit/`; they use `vitest.unit.config.mjs` and do not require the Trust Anchor.

### Zod Usage

- Import from `zod` (or `zod/v3` in test files that use the legacy shim): `import { z } from "zod"`.
- Define schemas as `const fooSchema = z.object({ … })` then derive the type: `type Foo = z.infer<typeof fooSchema>`.
- Use `.safeParse()` when the caller should handle validation errors gracefully; use `.parse()` when a thrown error is the correct behaviour.

---

## Key Source Files

| Path                                                        | Purpose                                                           |
| ----------------------------------------------------------- | ----------------------------------------------------------------- |
| `src/orchestrator/wallet-issuance-orchestrator-flow.ts`     | Issuance flow: PAR → authorize → token → nonce → credential       |
| `src/orchestrator/wallet-presentation-orchestrator-flow.ts` | Presentation flow: fetch metadata → authorization → redirect      |
| `src/step/step-flow.ts`                                     | `StepFlow` abstract base class; `execute()` error wrapper         |
| `src/step/issuance/`                                        | Default step implementations for issuance                         |
| `src/step/presentation/`                                    | Default step implementations for presentation                     |
| `src/logic/config-loader.ts`                                | Hierarchical INI config loader                                    |
| `src/logic/logs.ts`                                         | Custom `Logger` type with `testCompleted`, `testSuite`, `withTag` |
| `src/types/config.ts`                                       | Zod schema + `Config` type for all config options                 |
| `tests/config/test-metadata.ts`                             | `defineIssuanceTest()` / `definePresentationTest()`               |
| `tests/config/test-loader.ts`                               | `TestLoader` — prototype-chain step auto-discovery                |
| `tests/helpers/par-validation-helpers.ts`                   | Factory helpers for negative PAR tests                            |
| `tests/global-setup.ts`                                     | Starts the local Trust Anchor before test runs                    |

---

## Config (`config.ini`)

Required sections for tests:

```ini
[issuance]
url = https://issuer.example.com
credential_types[] = dc_sd_jwt_SomeCredential

[presentation]
authorize_request_url = https://verifier.example.com/authorize

[steps_mapping]
; Example paths for custom steps — create these directories or adjust to your own layout
HappyFlowIssuance     = ./tests/steps/version_1_0/issuance
HappyFlowPresentation = ./tests/steps/version_1_0/presentation
```

- If no `[steps_mapping]` entry exists for a test name, built-in `*DefaultStep` classes are used automatically — no error.
- CLI options override `config.ini`; a custom `--file-ini` path overrides the default.
