# IT-Wallet Conformance Tool

Tool for the automated conformance testing of services integrating with the [Italian IT Wallet ecosystem](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en). It helps all actors within the ecosystem—including Relying Parties (RPs), Credential Issuers, Authentic Sources, and Certification Bodies—to develop and validate their implementations.

The primary challenge is ensuring that all solutions are correct, up-to-date, and aligned with official Italian and European technical and regulatory standards. This tool automates a comprehensive suite of tests, providing detailed reports that highlight any errors or discrepancies from the technical specifications.

## Key Goals

- ✅ **Automate Conformance Testing**: Run tests defined by the official Italian technical rules to ensure compliance.
- ✅ **Improve Development Cycles**: Increase implementation quality and efficiency by catching errors early.
- ✅ **Support the Ecosystem**: Provide a reliable tool for both developers integrating with the IT Wallet and regulatory bodies certifying the solutions.

## Key Features

- 🤖 **CI/CD Integration**: Designed to be executed automatically in your CI/CD pipelines.
- 💻 **Headless CLI**: A powerful command-line interface perfect for server and development environments.
- 🌐 **Open Source**: Fully open-source and ready for community contributions.
- 📄 **Detailed Reports**: Generates clear reports on test outcomes (success, failure, not applicable) to quickly identify issues.
- 🐛 **Verbose Debugging**: Offers advanced technical output to simplify debugging and integration.
- 👥 **For Integrators & Certifiers**: Built to serve both entities building solutions and those who verify them.

## 🚀 Getting Started

Follow these steps to get the **IT-Wallet Conformance Tool** running on your local machine.

### Prerequisites

You must have [Node.js >= 22.19.0](https://nodejs.org/en/about/previous-releases) and pnpm installed on your system.

### Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/pagopa/wallet-conformance-test
   ```

2. Navigate into the project directory:

   ```bash
   cd wallet-conformance-test
   ```

3. Install dependencies using pnpm:

   ```bash
   pnpm install
   ```

4. Install the CLI globally using pnpm:

   ```bash
   pnpm install -g
   ```

This will make the `wct` command available system-wide. You can use this command or `pnpm` to launch test as described below.

5. Verify the installation by checking the version:

   ```bash
   wct --version
   ```

   This should print the current version of the tool (e.g., `1.1.0`).

### Command not found? 🤔

If you encounter an issue where the `wct` command is not available system-wide after installation, you can manually link it. From the root of the wallet-conformance-test directory, run the following commands:

1. Make the script executable:

   ```bash
   chmod +x ./bin/wct
   ```

2. Create a global symbolic link to the command:

   ```bash
   pnpm link --global
   ```

## 🐳 Docker Usage

If you prefer using Docker, you can pull the official image from the GitHub Container Registry or build it locally.

### Build image

1. Pull the latest image with the following command:

   ```bash
   docker pull ghcr.io/pagopa/wallet-conformance-test:latest
   ```

   Alternatively, you can build the Docker image from the source code:

   ```bash
   docker build --tag pagopa/wallet-conformance-test:latest .
   ```

2. Run the CLI for example to start issuance test:

   ```bash
   docker run --rm wallet-conformance-test:latest test:issuance
   ```

3. If you want to mount a local folder for data or configuration (as suggested in the README):

   ```bash
   docker run --rm -v "$(pwd)/data:/wallet-conformance-test/data" wallet-conformance-test:latest [COMMAND]
   ```

### Run Container

To run the tests, create a local directory (e.g., data) to store configuration and reports. Then, launch the container, mounting your local directory as a volume:

1. Create a directory for your data

```bash
mkdir data
```

2. Run the container

```bash
docker run -v "$(pwd)/data:/wallet-conformance-test/data" pagopa/wallet-conformance-test:latest [COMMAND]
```

Replace [COMMAND] with the specific test command you want to run (e.g., test:issuance).

## ⚙️ Usage

The CLI tool is designed to test a running instance of your Credential Issuer or Relying Party solution. Ensure you have the metadata URL for your service available before you begin.

### Configuration

The tool can be configured using a `config.ini` file or via command-line options. An example `config.example.ini` file is provided with standard values for settings like the data storage directory or Trust Certification Authority references. You can create your own `config.ini` file and specify it using the `--file-ini` option. Command-line options always override settings from the `config.ini` file.

Configuration Hierarchy:

- Command-Line Options (Highest priority)
- Custom .ini File (--file-ini)
- Default .ini File (Lowest priority)

If a mandatory attribute is not defined in either the `.ini` file or as a command-line option, the tool will raise an error.

Examples:

Override a specific value from the command line:

    wct test:issuance --credential-issuer-uri https://my-issuer.example.com

Use a custom configuration file:

    wct test:issuance --file-ini /path/to/my-config.ini

### Wallet Version

The `wallet_version` setting (under the `[wallet]` section) controls which version of the Italian IT Wallet technical specification the tool targets. Different versions define different data models, credential formats, and protocol behaviours. Supported values:

| Value  | Description |
|--------|-------------|
| `V1_0` | Targets the 1.0.x [specification](https://italia.github.io/eid-wallet-it-docs/releases/1.0.2/en/). |
| `V1_3` | Targets the 1.3.x [specification](https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/). |

Set it in your `config.ini`:

```ini
[wallet]
wallet_version = V1_3
```

> **Tip**: Use `V1_3` when testing against issuers or relying parties that implement the latest specification revision. Use `V1_0` for services that still target the first stable release.

### TLS Unsafe Mode

When testing against local services with self-signed certificates, you can disable TLS certificate verification. This is cross-platform (Windows, macOS, Linux) and disables TLS certificate verification for the entire Node.js process running this tool.

There are three equivalent ways to enable it, listed in priority order (highest first):

1. **CLI flag** (highest priority):

   ```bash
   wct test:issuance --unsafe-tls
   wct test:presentation --unsafe-tls
   ```

2. **Environment variable**:

   ```bash
   CONFIG_UNSAFE_TLS=true pnpm test:issuance
   ```

3. **`config.ini`** (lowest priority):

   ```ini
   [network]
   tls_reject_unauthorized = false
   ```


### Running Tests

The primary function of the tool is to run test suites for the main IT Wallet flows.

1. First rename `config.example.ini` to `config.ini`.

#### Testing the issuance Flow

To test the credential issuance flow, you will use the `test:issuance` command.

##### Using Configuration File

2. Configure your `config.ini` file with the credential issuer URL and credential types:

   ```ini
   [issuance]
   url = https://issuer.example.com
   credential_types[] = dc_sd_jwt_EuropeanDisabilityCard
   ```

3. Run the test command:

   ```bash
   wct test:issuance
   ```

##### Using Command-Line Options

2. Alternatively, bypass the configuration file and specify parameters directly:

   ```bash
   wct test:issuance --credential-issuer-uri https://issuer.example.com --credential-types dc_sd_jwt_EuropeanDisabilityCard
   ```

During the test, verbose logs will be printed to the console, informing you of progress and any anomalies.

The pre-configured happy flow tests and security tests validate the issuance of the `--credential-types` credential. To modify this default setting, refer to the instructions below.

> **Note**: By default, credentials generated during testing are not saved to disk. However, you can configure the tool to save them locally for presentation phase. You can configure that using `config.ini` with `save_credential = true` or using cli option `--save-credential`

**📖 For detailed test configuration and customization**, see the comprehensive [Internal Test Configuration Guide](./tests/docs/TEST-CONFIGURATION-GUIDE.md). If you want to create external test specs see the comprehensive [External Test Configuration Guide](./tests/docs/ISSUANCE-TESTING-GUIDE.md).  

These guides cover:

- Quick start with default configurations
- Custom credential types and multiple configurations
- Environment-based configuration
- Custom step classes and advanced options

#### Testing the Presentation Flow

##### Using Configuration File

2. Ensure your `.ini` file is configured with the correct URL for the credential identifier you wish to test, `config.ini`:

   ```ini
   [presentation]
   authorize_request_url = ...
   ```

3. Similarly, to test the presentation flow, you will use the `test:presentation` command:
   ```bash
   wct test:presentation [OPTIONS]
   ```

##### Using Command-Line Options

2. Alternatively, bypass the configuration file and specify parameters directly:

   ```bash
   wct test:presentation --presentation-authorize-uri https://rp.example.com
   ```

> **Note**:
> The credentials used during the presentation tests will include both the credentials saved during the issuance tests and the auto-generated PID (dc_sd_jwt_PersonIdentificationData).

#### Test Reports

Upon completion of a test suite, the tool generates a comprehensive report (e.g., an HTML file) summarizing the results. The report will clearly detail:

- Success Cases: Tests that passed validation.
- Failure Cases: Tests that failed, with details to help identify the root cause.
- Non-Executable Cases: Tests that were skipped and why.
- Additional Data: Verbose logs and other debugging information.

## 📋 Official Test Plans

The tests executed by this tool are a **subset of the official conformance tests** defined within the [IT Wallet Technical Specifications](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en). Specifically, they implement part of the test plans documented in the [Test Plans section](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans.html) of the official documentation. See [Test Execution Reference](./tests/docs/TEST-EXECUTION-REFERENCE.md) for more details.

This ensures that implementations validated by this tool are aligned with the requirements established by the Italian technical rules for the IT Wallet ecosystem.

## 🪪 Automatic Mock PID Generation

The tool **automatically generates a mock PID (Person Identification Data)** credential for testing purposes. This allows you to run conformance tests without needing a real credential from an official issuer.

> Currently, `dc_sd_jwt_PersonIdentificationData` (PID) is the only credential used for presentation in this project. Other credential types are not yet supported for presentation flows.

### How It Works

The mock PID is generated in the **SD-JWT VC** (Selective Disclosure JWT Verifiable Credential) format, which is the standard format used in the Italian IT Wallet ecosystem. All personal data fields are selectively disclosable, meaning they can be individually revealed during presentation flows.

The mock PID credential uses a **fictitious issuer** with the value `https://issuer.example.com`.

The credential is **signed with auto-generated mock keys** created locally by the tool. These keys are part of a **local Trust Anchor** federation setup, described in the section below.

> ⚠️ **Important**: The solution under test **must not** fetch issuer data from the `/.well-known/openid-federation` endpoint. Instead, it should perform verification using either:
>
> - The `trust_chain` claim in the credential header, or
> - The `x5c` (X.509 certificate chain) parameter
>
> Additionally, **Trust Anchor validity checks must be disabled** during testing, as the mock credentials use locally generated keys that are not part of a real trust infrastructure.

This ensures that your implementation correctly handles trust verification through the credential itself, rather than relying on external federation metadata lookups.

### What is Generated

When running tests, the tool creates a sample PID credential containing fictional Italian citizen data.

**Selectively disclosable claims** (included in the SD-JWT disclosure frame):

- **Personal Information**: Given name, family name, and birth date
- **Place of Birth**: Italian location
- **Nationality**: Italian (IT)
- **Administrative Number**: A sample personal administrative number
- **Validity**: The credential is set to expire one year from generation

**Non-selectively disclosable claims** (present in the JWT payload, not in disclosure frame):

- **`verification`**: An Italian domestic mandatory extension (per ARF HLR PID_06) asserting the identity verification method and assurance level:
  ```json
  {
    "trust_framework": "it_cie",
    "assurance_level": "high"
  }
  ```
  `trust_framework: "it_cie"` reflects that PID issuance is gated on the CIE identity infrastructure. `assurance_level: "high"` corresponds to LoA High (eIDAS High), the level required for PID issuance. Look under /dumps folder for more detail.

> **Note (V1_3 only)**: The `verification` claim is specific to the V1.3 data model. V1_0 uses a different PID data model and does not include this claim.

## 🔐 Local Federation Servers

The tool spins up several **local HTTPS servers** that provide OpenID Federation metadata used during conformance testing. Together they simulate a complete federation hierarchy — Trust Anchor → Wallet Provider → Credential Issuer — so that issuers and relying parties under test can resolve and validate entity configurations without any external dependency.

| Server | Hostname | Default Port | Purpose |
|---|---|---|---|
| **Trust Anchor** | `trust-anchor.wct.example.org` | `3001` | Root of trust — serves `openid-federation` and `/fetch` endpoints |
| **Wallet Provider** | `wallet-provider.wct.example.org` | `3002` | Exposes the Wallet Provider entity configuration and JWKS |
| **Credential Issuer** | `credential-issuer.wct.example.org` | `3003` | Exposes the mock PID issuer entity configuration |

### DNS Resolution Requirement

Because these servers listen on HTTPS (port 443 implied by the canonical URLs), the three hostnames **must resolve to `127.0.0.1`** on the machine where the tests run. This is required so that services under test can reach the federation endpoints advertised in credentials and entity configurations.

#### macOS / Linux

Add the following line to `/etc/hosts` (requires `sudo`):

```bash
sudo sh -c 'echo "127.0.0.1  trust-anchor.wct.example.org wallet-provider.wct.example.org credential-issuer.wct.example.org" >> /etc/hosts'
```

Or open the file manually:

```bash
sudo nano /etc/hosts
```

And append:

```
127.0.0.1  trust-anchor.wct.example.org wallet-provider.wct.example.org credential-issuer.wct.example.org
```

#### Windows

Open **Notepad** (or any text editor) **as Administrator**, then open the file:

```
C:\Windows\System32\drivers\etc\hosts
```

Append the following line and save:

```
127.0.0.1  trust-anchor.wct.example.org wallet-provider.wct.example.org credential-issuer.wct.example.org
```

> **Tip:** You can also run the following command in an **Administrator PowerShell** prompt:
>
> ```powershell
> Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "127.0.0.1  trust-anchor.wct.example.org wallet-provider.wct.example.org credential-issuer.wct.example.org"
> ```

### Automatic Startup

All three servers **automatically start when you run tests**. The global test setup handles the server lifecycle:

- Starts all servers before tests begin
- Stops all servers after all tests complete

No manual intervention is required when running test suites.

### Manual Startup

If you need to run the Trust Anchor server independently (e.g., for development or debugging), you can start it manually:

```bash
pnpm ta:server
```

The server will start on port `3001` by default.

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

1. Fork the Project
2. Create your Feature Branch (git checkout -b feature/AmazingFeature)
3. Commit your Changes (git commit -m 'Add some AmazingFeature')
4. Push to the Branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

Please see the CONTRIBUTING.md file for more details on our code of conduct and the process for submitting pull requests.
