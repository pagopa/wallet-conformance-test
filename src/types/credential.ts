import { IssuerSignedDocument } from "@auth0/mdl";
import { SDJwt } from "@sd-jwt/core";
import { DcqlQuery, DcqlQueryResult } from "dcql";
import z from "zod";

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

export type StatusClaim = StatusClaimV1_0 | StatusClaimV1_3;

export interface StatusClaimV1_0 {
  status_assertion: {
    credential_hash_alg: string;
  };
}

export interface StatusClaimV1_3 {
  status_list: {
    idx: number;
    uri: string;
  };
}

export interface VpTokenOptions {
  client_id: string;
  credential: string;
  dcqlQuery: DcqlQuery.Input;
  dpopJwk: KeyPair["privateKey"];
  nonce: string;
  responseUri: string;
}
