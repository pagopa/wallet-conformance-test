import { KeyPair } from "./KeyPair";

export interface AttestationResponse {
  attestation: string;
  created: boolean;
  providerKey: KeyPair;
  unitKey: KeyPair;
}
