import { IssuerSignedDocument } from "@auth0/mdl";
import { SDJwt } from "@sd-jwt/core";
import z from "zod";
import { Jwt } from "@sd-jwt/core";
import { DcqlQuery, DcqlQueryResult } from "dcql";

import { KeyPair, KeyPairJwk } from "./key-pair";

export type Credential = {
  compact: string;
} & (
  | {
      parsed: Awaited<ReturnType<typeof SDJwt.decodeSDJwt>>;
      typ: "dc+sd-jwt";
    }
  | {
      parsed: IssuerSignedDocument;
      typ: "mso_mdoc";
    }
);

export const zTrustChain = z.string().array();
export const zX5c = z.string().array();

export interface CredentialWithKey {
  credential: string;
  dpopJwk: KeyPairJwk;
  id: string;
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
