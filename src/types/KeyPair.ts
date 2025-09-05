import type { JWK } from "jose";

export interface KeyPair {
	privateKey: JWK,
	publicKey: JWK
};