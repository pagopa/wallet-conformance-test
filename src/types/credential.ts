import { IssuerSignedDocument } from "@auth0/mdl";
import { Jwt } from "@sd-jwt/core";

export interface Credential {
  compact: string;
  parsed: IssuerSignedDocument | Jwt;
  typ: string;
}
