import { Credential, CredentialError, Mdoc, SdJwt } from "@/types";

export class CredentialsManager {
  private credentials: Record<string, Credential> = {};

  addMdoc(name: string, credential: Mdoc) {
    this.checkSub(name, ...credential.subs);

    this.credentials[name] = {
      credential: credential.document,
      subs: credential.subs,
      typ: "mso_mdoc",
    };
  }

  addSdJwt(name: string, credential: SdJwt) {
    this.checkSub(name, credential.payload.sub);

    this.credentials[name] = {
      credential: credential,
      subs: [credential.payload.sub],
      typ: "dc+sd-jwt",
    };
  }

  get(name: string): Credential | undefined {
    return this.credentials[name];
  }

  private checkSub(credName: string, ...subs: string[]) {
    for (const name in this.credentials)
      if (subs.find((sub) => subs.includes(sub)))
        throw new CredentialError(
          `duplicate 'sub' found between credentials ${name} and ${credName}`,
        );
  }
}
