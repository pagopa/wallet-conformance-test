# Presentation Flow Testing

This guide explains how to configure and run **presentation conformance tests** against a Relying Party (Verifier) using the IT-Wallet Conformance Tool.

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

- Complete the [Getting Started](../README.md#-getting-started) section.
- Ensure the three local federation server hostnames resolve to `127.0.0.1` (see [Local Federation Servers](../README.md#-local-federation-servers)).
- Have a running Relying Party instance whose `authorize_request_url` (or the URL from a QR code) is available.

---

## Configuration

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

When the RP creates a new authorization request on every run (the standard case), configure a **shell script** that calls the RP's API and prints the resulting URL to `stdout`. The tool executes this script before each test run and uses the URL it outputs.

```ini
[presentation]
authorize_request_script = ./scripts/presentation.example.sh
```

Contract for the script:

| Requirement    | Detail                                                               |
| -------------- | -------------------------------------------------------------------- |
| **Executable** | The file must be executable (`chmod +x`).                            |
| **Stdout**     | Print exactly one line: the full authorization request URL.          |
| **Exit code**  | Exit `0` on success; any non-zero exit code is treated as a failure. |
| **Timeout**    | The tool waits up to **15 seconds** for the script to complete.      |
| **Stderr**     | Written to the tool's own stderr for debugging; not parsed.          |

#### Example script (V1.3)

The repository ships a ready-to-use example at [`scripts/presentation.example.sh`](../scripts/presentation.example.sh)

#### Adapting the script to your RP

The only parts you typically need to change are:

| Variable    | What to change                                                                                                                                                    |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `API_URL`   | Your RP's authorization-request creation endpoint.                                                                                                                |
| `VCT_VALUE` | The credential type (`vct`) the RP should request, e.g. `urn:eudi:pid:it:1` (V1.3) or `https://pre.ta.wallet.ipzs.it/vct/v1.0.0/personidentificationdata` (V1.0). |
| `dcqlQuery` | Adjust the claims and credential format to match the RP's requirements.                                                                                           |

The script expects the RP to return a JSON body with a `url` key containing the full authorization request URL. Adapt the `jq` expression if your RP uses a different response shape.

#### Mutual exclusivity

`authorize_request_url` and `authorize_request_script` are **mutually exclusive**. If both are set, `authorize_request_script` takes precedence. You must provide at least one of them.

---

## Running the Tests

### Using `config.ini`

```bash
# Static URL
wct test:presentation

# Dynamic URL via script
wct test:presentation
```

Both modes are driven entirely by `config.ini`; no extra flags are needed once the file is configured.

### Using CLI Options

Override configuration at runtime without editing `config.ini`:

```bash
# Static URL
wct test:presentation \
  --presentation-authorize-uri 'https://rp.example.com/auth?client_id=...&request_uri=...&state=...'

# Dynamic URL via script
wct test:presentation \
  --presentation-authorize-script ./scripts/presentation.example.sh
```

### Using Environment Variables

```bash
# Static URL
CONFIG_PRESENTATION_AUTHORIZE_URI='https://rp.example.com/auth?...' wct test:presentation

# Dynamic URL via script
CONFIG_PRESENTATION_AUTHORIZE_SCRIPT=./scripts/presentation.example.sh wct test:presentation
```

### CLI Reference

| Option                                   | Environment Variable                   | Config key (`[presentation]`) | Description                                                      |
| ---------------------------------------- | -------------------------------------- | ----------------------------- | ---------------------------------------------------------------- |
| `--presentation-authorize-uri <url>`     | `CONFIG_PRESENTATION_AUTHORIZE_URI`    | `authorize_request_url`       | Static authorization request URL.                                |
| `--presentation-authorize-script <path>` | `CONFIG_PRESENTATION_AUTHORIZE_SCRIPT` | `authorize_request_script`    | Path to a script that outputs the URL dynamically.               |
| `--presentation-tests-dir <path>`        | `CONFIG_PRESENTATION_TESTS_DIR`        | `tests_dir`                   | Directory where Vitest discovers `*.presentation.spec.ts` files. |

---

## Optional Settings

```ini
[presentation]
# Optional: explicit RP Verifier base URL when the federation metadata
# domain differs from the authorize_request_url domain.
verifier = https://rp.example.com
```

---

## Credentials Used During Presentation

The tool uses two credential sources, in order:

1. **Auto-generated mock PID** — always available; created automatically at test startup.
2. **Saved issuance credentials** — credentials stored during previous `test:issuance` runs when `save_credential = true` is configured.

> Currently only `dc_sd_jwt_PersonIdentificationData` (PID) is used for presentation.
> Other credential types are not yet supported in the presentation flow.

---

## Further Reading

- [External Presentation Testing Guide](../tests/docs/PRESENTATION-TESTING-GUIDE.md) — writing custom test specs outside the repository.
- [Step Outputs Reference](../tests/docs/STEP-OUTPUTS.md) — detailed response structure for each presentation step.
- [Test Configuration Guide](../tests/docs/TEST-CONFIGURATION-GUIDE.md) — advanced configuration and step auto-discovery.
- [IT Wallet Technical Specification](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/)
- [Relying Party Test Plans](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-relying-party.html)
