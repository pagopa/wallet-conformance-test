/**
 * In-process consent simulation for CI_052 (REQ-03.6 / REQ-10).
 * Defaults to granted so the happy-path L2+ flow can proceed without UI.
 */

export type SimulatedConsentState = "denied" | "granted" | "pending";

let consentState: SimulatedConsentState = "granted";

export function getSimulatedConsentState(): SimulatedConsentState {
  return consentState;
}

export function isConsentGranted(): boolean {
  return consentState === "granted";
}

export function resetSimulatedConsentState(): void {
  consentState = "granted";
}

export function setSimulatedConsentState(state: SimulatedConsentState): void {
  consentState = state;
}
