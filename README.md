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

You must have Node.js and npm installed on your system.

### Installation

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/pagopa/wallet-conformance-test
    ```

2. Navigate into the project directory:

    ```bash
    cd wallet-conformance-test
    ```

3. Install the CLI globally using npm:

    ```bash
    pnpm install -g
    ```

This will make the `wallet-conformance-test` command available system-wide. You can use this command or `pnpm` to launch test as described below.



### Command not found? 🤔
If you encounter an issue where the `wallet-conformance-test` command is not available system-wide after installation, you can manually link it. From the root of the wallet-conformance-test directory, run the following commands:

2. Make the script executable:

    ```bash
    chmod +x ./bin/wallet-conformance-test
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

The tool can be configured using a `.ini` file or via command-line options. A default `.ini` file is provided with standard values for settings like the data storage directory or Certification Authority references. You can create your own `.ini` file and specify it using the `--file-ini` option. Command-line options always override settings from the `.ini` file.

Configuration Hierarchy:
- Command-Line Options (Highest priority)
- Custom .ini File (--file-ini)
- Default .ini File (Lowest priority)

If a mandatory attribute is not defined in either the `.ini` file or as a command-line option, the tool will raise an error.

Examples:

Override a specific value from the command line:

    wallet-conformance-test test:issuance --credential-issuer-uri https://my-issuer.example.com


Use a custom configuration file:

    wallet-conformance-test test:issuance --file-ini /path/to/my-config.ini


### Running Tests

The primary function of the tool is to run test suites for the main IT Wallet flows.

#### Testing the issuance Flow

To test the credential issuance flow, you will use the `test:issuance` command. 

First, ensure your `.ini` file is configured with the correct URL for the credential identifier you wish to test (e.g., dc_sd_jwt_PersonIdentificationData).

Then, run the test command:

    wallet-conformance-test test:issuance --credential-type PersonIdentificationData


During the test, verbose logs will be printed to the console, informing you of progress and any anomalies.

#### Testing the Presentation Flow

Similarly, to test the presentation flow, you will use the `test:remote-presentation` command:

    wallet-conformance-test test:remote-presentation [OPTIONS]


#### Test Reports

Upon completion of a test suite, the tool generates a comprehensive report (e.g., an HTML file) summarizing the results. The report will clearly detail:

- Success Cases: Tests that passed validation.
- Failure Cases: Tests that failed, with details to help identify the root cause.
- Non-Executable Cases: Tests that were skipped and why.
- Additional Data: Verbose logs and other debugging information.

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