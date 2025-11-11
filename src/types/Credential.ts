import { MDoc } from "@auth0/mdl";
import { Jwt } from "@sd-jwt/core";

export interface Credential {
  credential: Jwt | MDoc;
  typ: string;
}
