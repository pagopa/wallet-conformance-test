import { Credential, Mdoc, SdJwt, CredentialError } from "@/types";

export class CredentialsManager {
  	private credentials: Record<string, Credential> = {};

	private checkSub(credName: string, ...subs: string[]) {
		for (const name in this.credentials)
			if (subs.find((sub) => subs.includes(sub)))
				throw new CredentialError(
					`duplicate 'sub' found between credentials ${name} and ${credName}`,
				);
	}

	addSdJwt(name: string, credential: SdJwt) {
		this.checkSub(name, credential.payload.sub);

		this.credentials[name] = {
			credential: credential,
			subs: [credential.payload.sub],
			typ: "dc+sd-jwt",
		};
	}

	addMdoc(name: string, credential: Mdoc) {
		this.checkSub(name, ...credential.subs);

		this.credentials[name] = {
			credential: credential.document,
			subs: credential.subs,
			typ: "mso_mdoc",
		};
	}

	get(name: string): Credential | undefined {
		return this.credentials[name];
	}
}