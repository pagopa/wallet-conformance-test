import { MDoc } from "@auth0/mdl";
import { SdJwt } from ".";

export type Credential = MdocCredential | SdJwtCredential;

interface MdocCredential {
  credential: MDoc;
  subs: string[];
  typ: "mso_mdoc";
}

interface SdJwtCredential {
  credential: SdJwt;
  subs: string[];
  typ: "dc+sd-jwt";
}
