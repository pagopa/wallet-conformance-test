/**
 * A custom error class for signaling failures during a verification process.
 *
 * This error should be thrown when a credential, token, or other piece of data fails a
 * validation check, such as a signature verification or a structural check. It allows for
 * specific-error handling, distinguishing verification failures from other types of runtime
 * errors.
 */
export class VerificationError extends Error {}
