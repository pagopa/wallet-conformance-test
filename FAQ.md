# Italiano

## FAQ: IT-Wallet Conformance Tool (Supporto Service Management)

Questo documento raccoglie le procedure di risoluzione problemi relative all'**IT-Wallet Conformance Tool**. È destinato al service management per fornire supporto di primo e secondo livello.

---

### 🚀 Installazione e Avvio Rapido

#### 1. Il comando `wct` non viene riconosciuto dal sistema. Cosa fare?
Se dopo l'installazione globale il comando `wct` non è disponibile, è necessario collegarlo manualmente. Dalla root del progetto, eseguire:
1. `chmod +x ./bin/wct`
2. `pnpm link --global`

#### 2. Quali sono i prerequisiti minimi?
Il tool richiede **Node.js >= 22.19.0** e **pnpm**. È possibile verificare la versione con `node -v` e `pnpm -v`.

---

### ⚙️ Configurazione e Versionamento

#### 3. Quale versione di IT-Wallet devo testare?
Il tool supporta due versioni delle specifiche tecniche, configurabili nel file `config.ini` sotto la sezione `[wallet]`:
- `V1_0`: Per servizi basati sulla specifica 1.0.x.
- `V1_3`: Per servizi basati sulla specifica 1.3.x (raccomandata per nuovi sviluppi).

#### 4. Come gestire i certificati TLS self-signed in ambiente di test?
Se il servizio sotto test usa certificati non validati da una CA pubblica, è possibile attivare la modalità "Unsafe TLS" in tre modi:
- Flag CLI: `--unsafe-tls`
- Variabile d'ambiente: `CONFIG_UNSAFE_TLS=true`
- In `config.ini`: `[network] tls_reject_unauthorized = false`

---

### 🌐 Networking e Federation Servers

#### 5. Perché i test falliscono nella risoluzione dei metadata della federazione?
Il tool avvia tre server locali che simulano la gerarchia di trust. È **obbligatorio** che gli hostnames risolvano su `127.0.0.1`.
Aggiungere al file `/etc/hosts` (o `C:\Windows\System32\drivers\etc\hosts` su Windows):
```text
127.0.0.1  trust-anchor.wct.example.org wallet-provider.wct.example.org credential-issuer.wct.example.org
```

#### 6. I server di federazione devono essere raggiungibili dall'esterno (es. Docker o rete locale)?
Di default i server ascoltano su `127.0.0.1`. Se il servizio sotto test deve contattare il tool dall'esterno (es. un container Docker separato), configurare il bind address su `0.0.0.0` nel `config.ini` o tramite variabile d'ambiente `OIDF_SERVERS_BIND_ADDRESS=0.0.0.0`.

---

### 🧪 Esecuzione dei Test e Customizzazione

#### 7. Come posso aggiungere nuovi test o suite personalizzate?
L'utente può estendere il tool senza modificare il core, aggiungendo file nelle directory configurate:
- **Issuance**: Aggiungere file `.issuance.spec.ts` nella directory definita da `env.CONFIG_ISSUANCE_TESTS_DIR` (o flag `--issuance-tests-dir`, default: `tests/conformance/issuance`).
- **Presentation**: Aggiungere file `.presentation.spec.ts` nella directory definita da `env.CONFIG_PRESENTATION_TESTS_DIR` (o flag `--presentation-tests-dir`, default: `tests/conformance/presentation`).

#### 8. Come posso modificare il comportamento di uno step specifico (es. per test negativi)?
È possibile mappare classi di step custom senza toccare il codice sorgente:
1. Creare una classe che estende lo step di default (es. `TokenRequestDefaultStep`).
2. Inserire il file in una cartella dedicata.
3. Mappare la cartella nel file `config.ini` sotto la sezione `[steps_mapping]`, associandola al nome della suite di test definita nel codice tramite la funzione `defineIssuanceTest` o `definePresentationTest`.

#### 9. Posso testare più tipi di credenziali contemporaneamente?
Sì. Nel file `config.ini`, alla voce `credential_types[]`, è possibile elencare più identificativi (es. `dc_sd_jwt_DrivingLicense`). Il tool eseguirà automaticamente una suite di test separata per ogni tipo inserito.

---

### 🔍 Debugging e Risultati

#### 10. Dove trovo i risultati dettagliati dei test?
Al termine dell'esecuzione, il tool genera un report HTML nella directory configurata (default `./data`). Il report evidenzia:
- **Successi**: Test validati correttamente.
- **Fallimenti**: Dettagli sull'errore per facilitare il debugging.
- **Non Applicabili**: Test saltati (es. batch issuance non supportata).

#### 11. Come interpretare i codici errore (es. CI_015, RPR003)?
Questi codici corrispondono alla **Test Matrix ufficiale** delle specifiche IT-Wallet. Una descrizione dettagliata di ogni controllo effettuato è disponibile nel file `TEST-EXECUTION-REFERENCE.md` all'interno della documentazione del tool.

---

### 🔐 Mock PID e Trust

#### 12. Il tool genera un PID di test?
Sì, il tool genera automaticamente un mock PID in formato SD-JWT VC. Note importanti:
- L'issuer fittizio è `https://issuer.example.com`.
- Il servizio sotto test **deve disabilitare il controllo di validità del Trust Anchor** o caricare le chiavi pubbliche fornite dal server locale del tool, poiché le chiavi sono generate dinamicamente e non appartengono a una catena di trust reale.

---

### 🛠️ Debugging e Risoluzione Avanzata (L3 Support)

#### 13. Come posso aumentare il livello di dettaglio dei log (Verbose/Debug)?
È possibile aumentare il livello di log per vedere i dettagli dello scambio di messaggi:
- **In `config.ini`**: Impostare `log_level = DEBUG` o `log_level = TRACE` nella sezione `[logging]`.
- **Via CLI**: Aggiungere il flag `--log-level DEBUG`.
- **Log su file**: Configurare `log_file = ./path/to/file.log` per salvare i log persistenti.

#### 14. Dove posso ispezionare i JWT scambiati (Richieste PAR, Token, Credenziali)?
I log a livello `DEBUG` stampano i payload e gli header dei JWT. Inoltre:
- Nel report HTML generato in `./data`, è presente una sezione di log dettagliata per ogni test.
- Se si sviluppano test custom, è possibile usare `orchestrator.getLog()` per stampare informazioni specifiche.

#### 15. Come funzionano esattamente i server di federazione locali?
Il tool avvia i seguenti processi su porte predefinite:
- **Trust Anchor (3001)**: Serve la Entity Configuration e l'endpoint `/fetch`.
- **Wallet Provider (3002)**: Simula il fornitore del Wallet.
- **Credential Issuer Mock (3003)**: Emette il mock PID.
Questi server usano chiavi generate all'avvio (o caricate da `./data/backup`). Per ispezionare il loro comportamento, è possibile avviarli singolarmente con `pnpm ta:server`, `pnpm wp:server` o `pnpm ci:server`.

#### 16. Posso simulare errori specifici nel protocollo per testare la resilienza del mio servizio?
Sì, tramite la mappatura degli step (`[steps_mapping]`):
1. Creare uno step custom (es. `MyTokenStep`) che altera il payload o la firma.
2. Mapparlo nel `config.ini`: `NomeTuoTest = path/to/custom/steps`.
3. Il tool userà la tua implementazione invece di quella standard per quel test specifico.

#### 17. Il tool fallisce nel risolvere gli hostname locali. Come verifico il networking?
Assicurarsi che:
1. Gli hostname in `/etc/hosts` siano corretti.
2. Se si usa Docker, `bind_address = 0.0.0.0` sia configurato in `config.ini` e gli hostname puntino all'IP dell'host.
3. Se necessario, usare `tls_reject_unauthorized = false` per ignorare problemi di certificati sui server locali.

---

# English

## FAQ: IT-Wallet Conformance Tool (Service Management Support)

This document gathers troubleshooting procedures related to the **IT-Wallet Conformance Tool**. It is intended for service management to provide first and second-level support.

---

### 🚀 Installation and Quick Start

#### 1. The `wct` command is not recognized by the system. What to do?
If the `wct` command is not available after global installation, it must be linked manually. From the project root, run:
1. `chmod +x ./bin/wct`
2. `pnpm link --global`

#### 2. What are the minimum prerequisites?
The tool requires **Node.js >= 22.19.0** and **pnpm**. You can verify the versions with `node -v` and `pnpm -v`.

---

### ⚙️ Configuration and Versioning

#### 3. Which IT-Wallet version should I test?
The tool supports two versions of the technical specifications, configurable in the `config.ini` file under the `[wallet]` section:
- `V1_0`: For services based on the 1.0.x specification.
- `V1_3`: For services based on the 1.3.x specification (recommended for new developments).

#### 4. How to handle self-signed TLS certificates in a test environment?
If the service under test uses certificates not validated by a public CA, you can enable "Unsafe TLS" mode in three ways:
- CLI Flag: `--unsafe-tls`
- Environment Variable: `CONFIG_UNSAFE_TLS=true`
- In `config.ini`: `[network] tls_reject_unauthorized = false`

---

### 🌐 Networking and Federation Servers

#### 5. Why do tests fail during federation metadata resolution?
The tool starts three local servers that simulate the trust hierarchy. It is **mandatory** that hostnames resolve to `127.0.0.1`.
Add to the `/etc/hosts` file (or `C:\Windows\System32\drivers\etc\hosts` on Windows):
```text
127.0.0.1  trust-anchor.wct.example.org wallet-provider.wct.example.org credential-issuer.wct.example.org
```

#### 6. Do federation servers need to be reachable from the outside (e.g., Docker or local network)?
By default, servers listen on `127.0.0.1`. If the service under test needs to contact the tool from the outside (e.g., a separate Docker container), configure the bind address to `0.0.0.0` in `config.ini` or via the `OIDF_SERVERS_BIND_ADDRESS=0.0.0.0` environment variable.

---

### 🧪 Test Execution and Customization

#### 7. How can I add new tests or custom suites?
Users can extend the tool without modifying the core by adding files to the configured directories:
- **Issuance**: Add `.issuance.spec.ts` files to the directory defined by `env.CONFIG_ISSUANCE_TESTS_DIR` (or `--issuance-tests-dir` flag, default: `tests/conformance/issuance`).
- **Presentation**: Add `.presentation.spec.ts` files to the directory defined by `env.CONFIG_PRESENTATION_TESTS_DIR` (or `--presentation-tests-dir` flag, default: `tests/conformance/presentation`).

#### 8. How can I modify the behavior of a specific step (e.g., for negative tests)?
You can map custom step classes without touching the source code:
1. Create a class that extends the default step (e.g., `TokenRequestDefaultStep`).
2. Place the file in a dedicated folder.
3. Map the folder in the `config.ini` file under the `[steps_mapping]` section, associating it with the test suite name defined in the code via the `defineIssuanceTest` or `definePresentationTest` function.

#### 9. Can I test multiple credential types simultaneously?
Yes. In the `config.ini` file, under the `credential_types[]` entry, you can list multiple identifiers (e.g., `dc_sd_jwt_DrivingLicense`). The tool will automatically run a separate test suite for each type entered.

---

### 🔍 Debugging and Results

#### 10. Where can I find detailed test results?
At the end of execution, the tool generates an HTML report in the configured directory (default `./data`). The report highlights:
- **Successes**: Correctly validated tests.
- **Fallimenti**: Error details to facilitate debugging.
- **Not Applicable**: Skipped tests (e.g., batch issuance not supported).

#### 11. How to interpret error codes (e.g., CI_015, RPR003)?
These codes correspond to the **official Test Matrix** of the IT-Wallet specifications. A detailed description of each check performed is available in the `TEST-EXECUTION-REFERENCE.md` file within the tool's documentation.

---

### 🔐 Mock PID and Trust

#### 12. Does the tool generate a test PID?
Yes, the tool automatically generates a mock PID in SD-JWT VC format. Important notes:
- The mock issuer is `https://issuer.example.com`.
- The service under test **must disable Trust Anchor validity checks** or load the public keys provided by the tool's local server, as keys are dynamically generated and do not belong to a real trust chain.

---

### 🛠️ Advanced Troubleshooting (L3 Support)

#### 13. How can I increase the log verbosity (Verbose/Debug)?
You can increase the log level to see protocol exchange details:
- **In `config.ini`**: Set `log_level = DEBUG` or `log_level = TRACE` under the `[logging]` section.
- **Via CLI**: Add the `--log-level DEBUG` flag.
- **File logging**: Configure `log_file = ./path/to/file.log` to save persistent logs.

#### 14. Where can I inspect the exchanged JWTs (PAR requests, Tokens, Credentials)?
`DEBUG` level logs print JWT payloads and headers. Additionally:
- The HTML report generated in `./data` includes a detailed log section for each test.
- If developing custom tests, you can use `orchestrator.getLog()` to print specific information.

#### 15. How do the local federation servers work exactly?
The tool starts the following processes on predefined ports:
- **Trust Anchor (3001)**: Serves Entity Configuration and the `/fetch` endpoint.
- **Wallet Provider (3002)**: Simulates the Wallet Provider.
- **Credential Issuer Mock (3003)**: Issues the mock PID.
These servers use keys generated at startup (or loaded from `./data/backup`). To inspect their behavior, you can start them individually with `pnpm ta:server`, `pnpm wp:server`, or `pnpm ci:server`.

#### 16. Can I simulate specific protocol errors to test my service's resilience?
Yes, using step mapping (`[steps_mapping]`):
1. Create a custom step (e.g., `MyTokenStep`) that alters the payload or signature.
2. Map it in `config.ini`: `YourTestName = path/to/custom/steps`.
3. The tool will use your implementation instead of the standard one for that specific test.

#### 17. The tool fails to resolve local hostnames. How do I verify networking?
Ensure that:
1. Hostnames in `/etc/hosts` are correct.
2. If using Docker, `bind_address = 0.0.0.0` is configured in `config.ini` and hostnames point to the host IP.
3. If necessary, use `tls_reject_unauthorized = false` to ignore certificate issues on local servers.
