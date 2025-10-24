import { MDoc } from "@auth0/mdl";
import { Jwt } from "@sd-jwt/core";


export interface Credential {
  credential: MDoc | Jwt;
  typ: string;
}
