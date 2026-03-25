import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";

import {
  buildCertPath,
  buildJwksPath,
  ensureDir,
  loadCertificate,
  loadJwks,
} from "@/logic";
import { Config, Credential } from "@/types";

import {
  buildMockMdlMdoc_V1_0,
  buildMockSdJwt_V1_0,
} from "./V1_0/mock-credentials";
import {
  buildMockMdlMdoc_V1_3,
  buildMockSdJwt_V1_3,
} from "./V1_3/mock-credentials";

export async function createMockMdlMdoc(
  subject: string,
  backupPath: string,
  credentialsPath: string,
  version: ItWalletSpecsVersion,
): Promise<Credential> {
  const issuerKeyPair = await loadJwks(backupPath, "issuer_mdl_mocked_jwks");

  const credentialIdentifier = "mso_mdoc_mDL";
  const { publicKey: deviceKey } = await loadJwks(
    backupPath,
    buildJwksPath(credentialIdentifier),
  );
  const issuerCertificate = await loadCertificate(
    backupPath,
    buildCertPath(credentialIdentifier),
    issuerKeyPair,
    subject,
  );

  const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000 * 365);
  let mockedMdoc: Credential;
  switch (version) {
    case ItWalletSpecsVersion.V1_0:
      mockedMdoc = await buildMockMdlMdoc_V1_0(
        expiration,
        deviceKey,
        issuerCertificate,
        issuerKeyPair,
      );
      break;
    case ItWalletSpecsVersion.V1_3:
      mockedMdoc = await buildMockMdlMdoc_V1_3(
        expiration,
        deviceKey,
        issuerCertificate,
        issuerKeyPair,
      );
      break;
    default:
      throw new Error("unimplemented IT-Wallet Specifications Version");
  }

  const pathVersion = `${credentialsPath}/${version}`;
  if (!existsSync(pathVersion))
    mkdirSync(pathVersion, {
      recursive: true,
    });

  writeFileSync(`${pathVersion}/${credentialIdentifier}`, mockedMdoc.compact);
  return mockedMdoc;
}

export async function createMockSdJwt(
  metadata: {
    iss: string;
    network: Config["network"];
    trust: Config["trust"];
    trustAnchor: Config["trust_anchor"];
  },
  backupPath: string,
  credentialsPath: string,
  version: ItWalletSpecsVersion,
): Promise<Credential> {
  const keyPair = await loadJwks(backupPath, "issuer_pid_mocked_jwks");

  const credentialIdentifier = "dc_sd_jwt_PersonIdentificationData";
  const { publicKey: unitKey } = await loadJwks(
    backupPath,
    buildJwksPath(credentialIdentifier),
  );

  const certificate = await loadCertificate(
    backupPath,
    "issuer_cert",
    keyPair,
    "CN=test_issuer",
  );

  const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000 * 365);
  let mockedSdjwt: Credential;
  switch (version) {
    case ItWalletSpecsVersion.V1_0:
      mockedSdjwt = await buildMockSdJwt_V1_0(
        metadata,
        expiration,
        unitKey,
        certificate,
        keyPair,
      );
      break;
    case ItWalletSpecsVersion.V1_3:
      mockedSdjwt = await buildMockSdJwt_V1_3(
        metadata,
        expiration,
        unitKey,
        certificate,
        keyPair,
      );
      break;
    default:
      throw new Error("unimplemented IT-Wallet Specifications Version");
  }

  const pathVersion = `${credentialsPath}/${version}`;
  ensureDir(pathVersion);

  writeFileSync(`${pathVersion}/${credentialIdentifier}`, mockedSdjwt.compact);
  return mockedSdjwt;
}
