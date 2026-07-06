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

export class DeferredIssuancePreconditionError extends OrchestratorError {
  constructor() {
    super(
      "Deferred Issuance Flow requires both a deferred refresh token and a transaction id. " +
        "Set 'refresh_token_deferred' and 'transaction_id_deferred' under [issuance] in config.ini or " +
        "pass --refresh-token-deferred <token> --transaction-id <id>.",
      "DEFERRED_ISSUANCE_PRECONDITION_FAILED",
    );
    this.name = "DeferredIssuancePreconditionError";
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

export class ReissuanceCredentialConfigurationError extends OrchestratorError {
  constructor() {
    super(
      "Re-Issuance Flow requires a different credential configuration ID than the main issuance flow and it must be stored in local credentials. " +
        "Set 'credential_configuration_id_reissuance' under [issuance] in config.ini or pass --credential-configuration-id-reissuance <id>.",
      "REISSUANCE_CREDENTIAL_CONFIGURATION_MISMATCH",
    );
    this.name = "ReissuanceCredentialConfigurationError";
  }
}

export class ReissuancePreconditionError extends OrchestratorError {
  constructor() {
    super(
      "Re-Issuance Flow requires a refresh token. " +
        "Set 'refresh_token_reissuance' under [issuance] in config.ini or pass --refresh-token-reissuance <token>.",
      "REISSUANCE_PRECONDITION_FAILED",
    );
    this.name = "ReissuancePreconditionError";
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
