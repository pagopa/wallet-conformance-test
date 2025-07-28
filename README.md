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
    git clone [https://github.com/pagopa/wallet-conformance-test](https://github.com/pagopa/wallet-conformance-test)
    ```

2. Navigate into the project directory:

    ```bash
    cd wallet-conformance-test
    ```

3. Install the CLI globally using npm:

    ```bash
    pnpm install -g
    ```

This will make the wallet-conformance-test command available system-wide.

## 🐳 Docker Usage

If you prefer using Docker, you can pull the official image from the GitHub Container Registry or build it locally.

### Pull from Registry

Pull the latest image with the following command:

    docker pull ghcr.io/pagopa/wallet-conformance-test:latest

### Build Locally

Alternatively, you can build the Docker image from the source code:

    docker build --tag pagopa/wallet-conformance-test:latest .

### Run Container

To run the tests, create a local directory (e.g., data) to store configuration and reports. Then, launch the container, mounting your local directory as a volume:

1. Create a directory for your data

    mkdir data

2. Run the container

    docker run -v "$(pwd)/data:/wallet-conformance-test/data" pagopa/wallet-conformance-test:latest [COMMAND]


Replace [COMMAND] with the specific test command you want to run (e.g., test:issuing).

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

    wallet-conformance-test test:issuing --credential-issuer-uri https://my-issuer.example.com


Use a custom configuration file:

    wallet-conformance-test test:issuing --file-ini /path/to/my-config.ini


### Running Tests

The primary function of the tool is to run test suites for the main IT Wallet flows.

#### Testing the Issuing Flow

To test the credential issuing flow, you will use the `test:issuing` command. 

First, ensure your `.ini` file is configured with the correct URL for the credential identifier you wish to test (e.g., dc_sd_jwt_PersonIdentificationData).

Then, run the test command:

    wallet-conformance-test test:issuing --credential-type PersonIdentificationData


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
