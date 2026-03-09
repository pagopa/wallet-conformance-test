import { CredentialWithKey, VpTokenOptions } from "@/types";

import { createVpTokenMdoc } from "../mdoc";
import { createVpTokenSdJwt } from "../sd-jwt";

export async function prepareCredentials_V1_3(
  validCredentials: { input_credential_index: number }[],
  credentialQueryId: string,
  credentials: CredentialWithKey[],
  options: Omit<VpTokenOptions, "credential" | "dpopJwk">,
): Promise<Record<string, string[]>> {
  if (validCredentials.length < 1)
    throw new Error(
      `No valid credentials found for credential_query_id ${credentialQueryId}`,
    );

  const accumulator: string[] = [];
  for (const validCredential of validCredentials) {
    const credentialIndex = validCredential.input_credential_index;
    const credential = credentials[credentialIndex];
    if (!credential)
      throw new Error(
        `Credential index ${credentialIndex} not found for credential_query_id ${credentialQueryId}`,
      );

    if (credential.typ === "dc+sd-jwt")
      accumulator.push(
        await createVpTokenSdJwt({
          ...options,
          credential: credential.credential,
          dpopJwk: credential.dpopJwk,
        }),
      );

    if (credential.typ === "mso_mdoc") {
      const token = await createVpTokenMdoc({
        ...options,
        credential: credential.credential,
        dpopJwk: credential.dpopJwk,
      });

      if (token) accumulator.push(token);
    }
  }

  return {
    [credentialQueryId]: accumulator,
  };
}
