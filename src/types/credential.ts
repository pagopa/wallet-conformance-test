import { IssuerSignedDocument } from "@auth0/mdl";
import { SDJwt } from "@sd-jwt/core";
import z from "zod";

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
