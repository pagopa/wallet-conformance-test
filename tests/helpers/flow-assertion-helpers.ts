import type {
  DeferredIssuanceFlowResponse,
  IssuanceFlowResponse,
  ReissuanceFlowResponse,
} from "@/types";
import type { PresentationFlowResponse } from "@/types";

/**
 * Asserts that a deferred issuance flow completed successfully.
 * Narrows the type so all step responses are non-optional.
 */
export function assertDeferredIssuanceFlowSuccess(
  result: DeferredIssuanceFlowResponse,
): asserts result is Required<Omit<DeferredIssuanceFlowResponse, "error">> & {
  success: true;
} {
  if (!result.success) {
    throw new Error(
      `Deferred issuance flow failed: ${result.error?.message ?? "unknown error"}`,
    );
  }
}

/**
 * Asserts that an issuance flow completed successfully.
 * Narrows the type so all step responses are non-optional.
 */
export function assertIssuanceFlowSuccess(
  result: IssuanceFlowResponse,
): asserts result is Required<Omit<IssuanceFlowResponse, "error">> & {
  success: true;
} {
  if (!result.success) {
    throw new Error(
      `Issuance flow failed: ${result.error?.message ?? "unknown error"}`,
    );
  }
}

/**
 * Asserts that a presentation flow completed successfully.
 * Narrows the type so all step responses are non-optional.
 */
export function assertPresentationFlowSuccess(
  result: PresentationFlowResponse,
): asserts result is Required<Omit<PresentationFlowResponse, "error">> & {
  success: true;
} {
  if (!result.success) {
    throw new Error(
      `Presentation flow failed: ${result.error?.message ?? "unknown error"}`,
    );
  }
}

/**
 * Asserts that a re-issuance flow completed successfully.
 * Narrows the type so all step responses are non-optional.
 */
export function assertReissuanceFlowSuccess(
  result: ReissuanceFlowResponse,
): asserts result is Required<Omit<ReissuanceFlowResponse, "error">> & {
  success: true;
} {
  if (!result.success) {
    throw new Error(
      `Re-issuance flow failed: ${result.error?.message ?? "unknown error"}`,
    );
  }
}
