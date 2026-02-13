import { IssuerSignedDocument } from "@auth0/mdl";
import { Jwt } from "@sd-jwt/core";

import { KeyPairJwk } from "./key-pair";

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
