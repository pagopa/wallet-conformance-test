# PID MRTD PKI fixtures

Mock **CSCA** (Country Signing CA) and **DSC** (Document Signing Certificate) used by the
Wallet Conformance Tool for the L2+ MRTD proof-of-possession path.

## Default storage location

Fixtures are written under the same runtime data model as attestations and credentials:

| Default | `{wallet.backup_storage_path}/pid-mrtd` → typically `./data/backup/pid-mrtd` |
| Override | `[issuance_pid] fixture_storage_path = ./data/pid-mrtd` in `config.ini` |

Files are **not** stored under `tests/fixtures/` or the installed package root.

| File       | Role                                    |
| ---------- | --------------------------------------- |
| `csca.pem` | Self-signed CSCA certificate (EC P-256) |
| `csca.key` | CSCA private key (PKCS#8 PEM)           |
| `dsc.pem`  | DSC certificate signed by the mock CSCA |
| `dsc.key`  | DSC private key (PKCS#8 PEM)            |

The **IAS** key pair is generated in memory per test run (REQ-03), not persisted here.

## Regenerate fixtures

```bash
pnpm fixtures:pid-mrtd
pnpm fixtures:pid-mrtd -- --force
```

Conformance and unit test runs call `ensurePidMrtdFixtures()` from `tests/global-setup.ts`
using the resolved config path.

## SUT trust store

For E2E L2+ tests against a real PID Provider, load `csca.pem` into the SUT ICAO trust store
or run the SUT in test mode with ICAO trust validation disabled.
