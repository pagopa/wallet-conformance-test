import { IssuerSignedDocument } from "@auth0/mdl";
import { Jwt } from "@sd-jwt/core";
import { DcqlQuery, DcqlQueryResult } from "dcql";

import { KeyPair, KeyPairJwk } from "./key-pair";

export interface Credential {
  compact: string;
  parsed: IssuerSignedDocument | Jwt;
  typ: "dc+sd-jwt" | "mso_mdoc";
}

export interface CredentialWithKey {
  credential: string;
  dpopJwk: KeyPairJwk;
  typ: "dc+sd-jwt" | "mso_mdoc";
}

export type DcqlMatchSuccess = Extract<
  DcqlQueryResult.CredentialMatch,
  { success: true }
>;

export interface VpTokenOptions {
  client_id: string;
  credential: string;
  dcqlQuery: DcqlQuery.Input;
  dpopJwk: KeyPair["privateKey"];
  nonce: string;
  responseUri: string;
}
