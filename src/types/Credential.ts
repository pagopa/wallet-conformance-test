import { MDoc } from "@auth0/mdl";

import { SdJwt } from ".";

export type Credential = MdocCredential | SdJwtCredential;

interface MdocCredential {
  credential: MDoc;
  typ: "mso_mdoc";
}

interface SdJwtCredential {
  credential: SdJwt;
  typ: "dc+sd-jwt";
}
