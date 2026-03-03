import { IssuerSignedDocument } from "@auth0/mdl";
import { SDJwt } from "@sd-jwt/core";

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
