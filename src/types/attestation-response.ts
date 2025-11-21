import { KeyPair } from "./key-pair";

export interface AttestationResponse {
  attestation: string;
  created: boolean;
  providerKey: KeyPair;
  unitKey: KeyPair;
}
