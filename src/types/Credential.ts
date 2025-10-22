import { SdJwt } from ".";

export interface Credential {
  credential: any | SdJwt;
  typ: string;
}
