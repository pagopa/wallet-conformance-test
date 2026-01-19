# wallet-conformance-test

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

Follow these steps to get the wallet-conformance-test tool running on your local machine.

### Prerequisites

You must have Node.js and pnpm installed on your system.

### Installation

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/pagopa/wallet-conformance-test
    ```

2. Navigate into the project directory:

    ```bash
    cd wallet-conformance-test
    ```

3. Install dependencies using npm:

    ```bash
    pnpm install 
    ```

4. Install the CLI globally using npm:

    ```bash
    pnpm install -g
    ```

This will make the `wct` command available system-wide. You can use this command or `pnpm` to launch test as described below.



### Command not found? 🤔
If you encounter an issue where the `wct` command is not available system-wide after installation, you can manually link it. From the root of the wallet-conformance-test directory, run the following commands:

2. Make the script executable:

    ```bash
    chmod +x ./bin/wct
    ```

3. Create a global symbolic link to the command::

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

The pre-configured happy flow test validates the issuance of the `--credential-types` credential. To modify this default setting, refer to the instructions below.

**📖 For detailed test configuration and customization**, see the comprehensive [Test Configuration Guide](./tests/TEST-CONFIGURATION-GUIDE.md). This guide covers:
- Quick start with default configurations
- Custom credential types and multiple configurations
- Environment-based configuration
- Custom step classes and advanced options

#### Testing the Presentation Flow

##### Using Configuration File

2. Ensure your `.ini` file is configured with the correct URL for the credential identifier you wish to test.

`config.ini`:
    ```bash
    [presentation]
    verifier = ...
    authorize_request_url = ...
    ```

3. Similarly, to test the presentation flow, you will use the `test:remote-presentation` command:
    ```bash
    wct test:remote-presentation [OPTIONS]
    ```

##### Using Command-Line Options

2. Alternatively, bypass the configuration file and specify parameters directly:

    ```bash
    wct test:issuance --presentation-authorize-uri https://rp.example.com
    ```

#### Test Reports

Upon completion of a test suite, the tool generates a comprehensive report (e.g., an HTML file) summarizing the results. The report will clearly detail:

- Success Cases: Tests that passed validation.
- Failure Cases: Tests that failed, with details to help identify the root cause.
- Non-Executable Cases: Tests that were skipped and why.
- Additional Data: Verbose logs and other debugging information.

## 📋 Official Test Plans

The tests executed by this tool are a **subset of the official conformance tests** defined within the [IT Wallet Technical Specifications](https://italia.github.io/eid-wallet-it-docs/releases/1.0.2/en). Specifically, they implement part of the test plans documented in the [Test Plans section](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans.html) of the official documentation.

This ensures that implementations validated by this tool are aligned with the requirements established by the Italian technical rules for the IT Wallet ecosystem.

## 🪪 Automatic Mock PID Generation

The tool **automatically generates a mock PID (Person Identification Data)** credential for testing purposes. This allows you to run conformance tests without needing a real credential from an official issuer.

> Currently, `dc_sd_jwt_PersonIdentificationData` (PID) is the only credential used for presentation in this project. Other credential types are not yet supported for presentation flows.

### How It Works

The mock PID is generated in the **SD-JWT VC** (Selective Disclosure JWT Verifiable Credential) format, which is the standard format used in the Italian IT Wallet ecosystem. All personal data fields are selectively disclosable, meaning they can be individually revealed during presentation flows.

The mock PID credential uses a **fictitious issuer** with the value `https://issuer.example.com`. 

The credential is **signed with auto-generated mock keys** created locally by the tool. These keys are part of a **local Trust Anchor** federation setup, described in the section below.

> ⚠️ **Important**: The solution under test **must not** fetch issuer data from the `/.well-known/openid-federation` endpoint. Instead, it should perform verification using either:
> - The `trust_chain` claim in the credential header, or
> - The `x5c` (X.509 certificate chain) parameter
>
> Additionally, **Trust Anchor validity checks must be disabled** during testing, as the mock credentials use locally generated keys that are not part of a real trust infrastructure.

This ensures that your implementation correctly handles trust verification through the credential itself, rather than relying on external federation metadata lookups.


### What is Generated

When running tests, the tool creates a sample PID credential containing fictional Italian citizen data:

- **Personal Information**: Given name, family name, and birth date
- **Place of Birth**: Italian location
- **Nationality**: Italian (IT)
- **Administrative Number**: A sample personal administrative number
- **Validity**: The credential is set to expire one year from generation

## 🔐 Trust Anchor Server
The tool provides a **local Trust Anchor server** for testing purposes. This server is a core component that provides OpenID Federation metadata for testing federation-based wallet interactions. It serves as the root of trust in the federation hierarchy.

### Automatic Startup

The Trust Anchor server **automatically starts when you run tests**. The global test setup handles the server lifecycle:
- Starts the server on `http://localhost:3001` before tests begin
- Stops the server after all tests complete

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

Please see the CONTRIBUTING.md file for more details on our code of conduct and the process for submitting pull requests.3

## ⚖️ License
Distributed under the MIT License. See LICENSE.md for more information.
Tool for the automated conformance testing of services integrating with the Italian IT Wallet ecosystem.