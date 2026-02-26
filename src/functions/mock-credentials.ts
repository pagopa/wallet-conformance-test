import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";

import {
  buildCertPath,
  buildJwksPath,
  loadCertificate,
  loadJwks,
} from "@/logic";
import { Credential } from "@/types";

import {
  buildMockMdlMdoc_V1_0,
  buildMockSdJwt_V1_0,
} from "./v1_0/mock-credentials";
import {
  buildMockMdlMdoc_V1_3,
  buildMockSdJwt_V1_3,
} from "./v1_3/mock-credentials";

export async function createMockMdlMdoc(
  subject: string,
  backupPath: string,
  credentialsPath: string,
  version: ItWalletSpecsVersion = ItWalletSpecsVersion.V1_0,
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
  let retVal: Credential;
  switch (version) {
    case ItWalletSpecsVersion.V1_0:
      retVal = await buildMockMdlMdoc_V1_0(
        expiration,
        deviceKey,
        issuerCertificate,
        issuerKeyPair,
      );
      break;
    case ItWalletSpecsVersion.V1_3:
      retVal = await buildMockMdlMdoc_V1_3(
        expiration,
        deviceKey,
        issuerCertificate,
        issuerKeyPair,
      );
      break;
  }

  const pathVersion = `${credentialsPath}/${version}`;
  if (!existsSync(pathVersion)) {
    mkdirSync(pathVersion, {
      recursive: true,
    });
  }
  writeFileSync(`${pathVersion}/${credentialIdentifier}`, retVal.compact);
  return retVal;
}

export async function createMockSdJwt(
  metadata: {
    iss: string;
    trustAnchorBaseUrl: string;
    trustAnchorJwksPath: string;
  },
  backupPath: string,
  credentialsPath: string,
  version: ItWalletSpecsVersion = ItWalletSpecsVersion.V1_0,
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
  let retVal: Credential;
  switch (version) {
    case ItWalletSpecsVersion.V1_0:
      retVal = await buildMockSdJwt_V1_0(
        metadata,
        expiration,
        unitKey,
        certificate,
        keyPair,
      );
      break;
    case ItWalletSpecsVersion.V1_3:
      retVal = await buildMockSdJwt_V1_3(
        metadata,
        expiration,
        unitKey,
        certificate,
        keyPair,
      );
      break;
  }

  const pathVersion = `${credentialsPath}/${version}`;
  if (!existsSync(pathVersion)) {
    mkdirSync(pathVersion, {
      recursive: true,
    });
  }
  writeFileSync(`${pathVersion}/${credentialIdentifier}`, retVal.compact);
  return retVal;
}
