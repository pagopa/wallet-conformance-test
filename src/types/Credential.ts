import { IssuerSignedDocument } from "@auth0/mdl";
import { Jwt } from "@sd-jwt/core";

export interface Credential {
  credential: IssuerSignedDocument | Jwt;
  typ: string;
}
