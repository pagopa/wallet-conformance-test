export {
  createSodCmsSignedData,
  signMrtdChallenge,
} from "@/logic/pid-mrtd/cms";
export {
  getSimulatedConsentState,
  isConsentGranted,
  resetSimulatedConsentState,
  setSimulatedConsentState,
  type SimulatedConsentState,
} from "@/logic/pid-mrtd/consent";
export {
  buildDg1,
  buildDg11,
  sha256Digest,
  TD1_MRZ_BYTE_LENGTH,
  wrapDg1Container,
} from "@/logic/pid-mrtd/dg";
export { bytesToBase64Url, utf8ToBase64Url } from "@/logic/pid-mrtd/encoding";
export {
  defaultPidMrtdFixtureDir,
  type PidMrtdFixturePaths,
  resolvePidMrtdFixtureDir,
  resolvePidMrtdFixturePaths,
} from "@/logic/pid-mrtd/fixture-paths";
export {
  ensurePidMrtdFixtures,
  generatePidMrtdFixtures,
  MOCK_CSCA_SUBJECT,
  MOCK_DSC_SUBJECT,
} from "@/logic/pid-mrtd/generate-fixtures";
export {
  type DataGroupHashEntry,
  encodeLdsSecurityObject,
  OID_ICAO_LDS_SECURITY_OBJECT,
  OID_SHA256,
} from "@/logic/pid-mrtd/lds-security-object";
export {
  ACR_CIE_HIGH,
  ACR_SPID_SUBSTANTIAL,
  buildMrtdPopInitUrl,
  buildMrtdPopVerifyUrl,
  getMockIdpPublicJwk,
  mintHighIdToken,
  mintMrtdProofJwt,
  type MintMrtdProofJwtParams,
  mintSubstantialIdToken,
  MOCK_IDP_ISSUER,
  type MockIdpSignOptions,
  resetMockIdpKeyCache,
} from "@/logic/pid-mrtd/mock-idp";
export {
  createEphemeralIasPki,
  type EphemeralIasPki,
  type LoadedPidMrtdPki,
  loadPersistedPidMrtdPki,
  MOCK_IAS_SUBJECT,
} from "@/logic/pid-mrtd/pki";
export {
  type MockIdTokenPayload,
  mockIdTokenPayloadSchema,
  MRTD_IAS_POP_JWT_TYP,
  MRTD_PROOF_JWT_TYP,
  MRTD_VALIDATION_JWT_TYP,
  type MrtdIasPopJwtPayload,
  mrtdIasPopJwtPayloadSchema,
  type MrtdPopVerifyResponse,
  mrtdPopVerifyResponseSchema,
  type MrtdProofJwtPayload,
  mrtdProofJwtPayloadSchema,
  type MrtdValidationJwtClaims,
  type MrtdValidationJwtIasBlock,
  mrtdValidationJwtIasBlockSchema,
  type MrtdValidationJwtMrtdBlock,
  mrtdValidationJwtMrtdBlockSchema,
  mrtdValidationJwtClaimsSchema,
  parseMrtdIasPopJwtPayload,
  parseMrtdPopVerifyResponse,
  parseMrtdProofJwtPayload,
  parseMrtdValidationJwtClaims,
} from "@/logic/pid-mrtd/schemas";
export {
  assembleMrtdValidationJwtClaims,
  type AssembleMrtdValidationJwtParams,
  buildMrtdDocumentArtifacts,
  type BuildMrtdDocumentArtifactsParams,
  type MrtdDocumentArtifacts,
  signMrtdValidationJwt,
  type SignMrtdValidationJwtParams,
} from "@/logic/pid-mrtd/validation-jwt";
export { verifyCscaDscChain } from "@/logic/pid-mrtd/verify-csca-dsc-chain";
