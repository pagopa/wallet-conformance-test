import { buildTamperedPopJwt } from "#/helpers/par-validation-helpers";

import type {
  TokenRequestResponse,
  TokenRequestStepOptions,
} from "@/step/issuance";

import { TokenRequestDefaultStep } from "@/step/issuance";

const wrongClientAttestationPopAudience = "https://attacker.example.com";

export function withInvalidClientAttestationPop(
  StepClass: typeof TokenRequestDefaultStep,
): typeof TokenRequestDefaultStep {
  return class extends StepClass {
    async run(options: TokenRequestStepOptions): Promise<TokenRequestResponse> {
      const invalidPop = await buildTamperedPopJwt({
        authorizationServer: options.accessTokenEndpoint,
        clientAttestation: options.walletAttestation.attestation,
        config: this.ioWalletSdkConfig,
        realUnitKey: options.walletAttestation.unitKey.privateKey,
        wrongAud: wrongClientAttestationPopAudience,
      });

      return super.run({
        ...options,
        popAttestation: invalidPop,
      });
    }
  } as typeof TokenRequestDefaultStep;
}
