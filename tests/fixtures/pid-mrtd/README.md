# PID MRTD PKI fixtures

Mock **CSCA** (Country Signing CA) and **DSC** (Document Signing Certificate) used by the
Wallet Conformance Tool for the L2+ MRTD proof-of-possession path.

| File       | Role                                      |
| ---------- | ----------------------------------------- |
| `csca.pem` | Self-signed CSCA certificate (EC P-256)   |
| `csca.key` | CSCA private key (PKCS#8 PEM)             |
| `dsc.pem`  | DSC certificate signed by the mock CSCA   |
| `dsc.key`  | DSC private key (PKCS#8 PEM)              |

The **IAS** key pair is **not** stored here; it is generated in memory per test run (REQ-03).

## Regenerate fixtures

From the repository root:

```bash
pnpm fixtures:pid-mrtd
```

Force regeneration (e.g. after expiry):

```bash
pnpm fixtures:pid-mrtd -- --force
```

Conformance and unit test runs also invoke `ensurePidMrtdFixtures()` from `tests/global-setup.ts`
when files are missing or expired.

## SUT trust store

For end-to-end L2+ tests against a real PID Provider, either:

- load `csca.pem` into the SUT ICAO trust store, or
- run the SUT in test mode with ICAO trust validation disabled.

See the PID Provider MRTD issuance test documentation for operational notes.
