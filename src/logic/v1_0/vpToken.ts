import { CredentialWithKey, VpTokenOptions } from "@/types";

import { createVpTokenMdoc } from "../mdoc";
import { createVpTokenSdJwt } from "../sd-jwt";

export async function prepareCredentials_V1_0(
  validCredentials: { input_credential_index: number }[],
  credentialQueryId: string,
  credentials: CredentialWithKey[],
  options: Omit<VpTokenOptions, "credential" | "dpopJwk">,
): Promise<Record<string, string>> {
  const validCredential = validCredentials[0];
  if (!validCredential)
    throw new Error(
      `No valid credentials found for credential_query_id ${credentialQueryId}`,
    );

  const credentialIndex = validCredential.input_credential_index;
  const credential = credentials[credentialIndex];
  if (!credential)
    throw new Error(
      `Credential index ${credentialIndex} not found for credential_query_id ${credentialQueryId}`,
    );

  if (credential.typ === "dc+sd-jwt")
    return {
      [credentialQueryId]: await createVpTokenSdJwt({
        ...options,
        credential: credential.credential,
        dpopJwk: credential.dpopJwk,
      }),
    };
  else credential.typ === "mso_mdoc";
  return await createVpTokenMdoc({
    ...options,
    credential: credential.credential,
    dpopJwk: credential.dpopJwk,
  });
}
