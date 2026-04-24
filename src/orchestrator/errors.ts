export class OrchestratorError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "OrchestratorError";
    this.code = code;
  }
}

export class CredentialConfigurationError extends OrchestratorError {
  readonly availableIds: string[];
  readonly reason: "not_in_offer" | "unsupported_by_issuer";
  readonly requestedId: string;

  constructor(
    requestedId: string,
    reason: "not_in_offer" | "unsupported_by_issuer",
    availableIds: string[],
  ) {
    const context =
      reason === "unsupported_by_issuer"
        ? `not supported by the issuer. Supported IDs: ${availableIds.join(", ")}`
        : `not included in the credential offer. Offer IDs: ${availableIds.join(", ")}`;
    super(
      `Credential configuration '${requestedId}' is ${context}. ` +
        `Fix: update config.ini → credential_types[] = <id>  or  --credential-types <types>.`,
      "CREDENTIAL_CONFIGURATION_MISMATCH",
    );
    this.name = "CredentialConfigurationError";
    this.requestedId = requestedId;
    this.reason = reason;
    this.availableIds = availableIds;
  }
}

export class IssuerMetadataError extends OrchestratorError {
  readonly missingField: string;
  readonly parentObject: string;
  readonly requiredFor: string;

  constructor(missingField: string, parentObject: string, requiredFor: string) {
    super(
      `Issuer metadata is missing '${missingField}' in '${parentObject}'. ` +
        `Cannot perform ${requiredFor}.`,
      "ISSUER_METADATA_MISSING_FIELD",
    );
    this.name = "IssuerMetadataError";
    this.missingField = missingField;
    this.parentObject = parentObject;
    this.requiredFor = requiredFor;
  }
}

export class StepOutputError extends OrchestratorError {
  readonly missingField: string;
  readonly stepTag: string;

  constructor(stepTag: string, missingField: string) {
    super(
      `Step '${stepTag}' did not return expected field '${missingField}'. ` +
        `Check the step implementation and issuer response logs.`,
      "STEP_OUTPUT_MISSING",
    );
    this.name = "StepOutputError";
    this.stepTag = stepTag;
    this.missingField = missingField;
  }
}
