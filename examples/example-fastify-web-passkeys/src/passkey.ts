import {
  isMfaRequiredError,
  MissingRequiredArgumentError,
  MissingTransactionError,
  PasskeyGetTokenError,
  SessionExpiredError,
} from '@auth0/auth0-fastify';
import type {
  PasskeyCredentialResponse,
  PasskeyDeliveryMethod,
  PasskeyVerificationCodes,
  PasskeyVerificationIdentifier,
} from '@auth0/auth0-fastify';

// What the browser may send. Fastify checks `request.body` against these JSON schemas before a handler runs. Its
// default setup also removes every property that a schema with `additionalProperties: false` does not list, so the
// browser can never choose the `realm`, the `organization`, `userMetadata`, the scopes or any other option, and
// Auth0 never receives a credential field it rejects.

export type SignupBody = {
  name?: string;
  deliveryMethod?: PasskeyDeliveryMethod;
} & ({ email: string; phoneNumber?: string } | { phoneNumber: string; email?: string });

export const signupBody = {
  type: 'object',
  additionalProperties: false,
  properties: {
    email: { type: 'string', format: 'email', maxLength: 254 },
    phoneNumber: { type: 'string', pattern: '^\\+[1-9]\\d{6,14}$' }, // E.164
    name: { type: 'string', minLength: 1, maxLength: 100 },
    deliveryMethod: { type: 'string', enum: ['text', 'voice'] },
  },
  anyOf: [{ required: ['email'] }, { required: ['phoneNumber'] }],
} as const;

export interface CompleteBody {
  credential: PasskeyCredentialResponse;
  verification?: PasskeyVerificationCodes;
}

export const completeBody = {
  type: 'object',
  required: ['credential'],
  additionalProperties: false,
  properties: {
    credential: {
      type: 'object',
      required: ['id', 'rawId', 'type', 'response'],
      additionalProperties: false,
      properties: {
        id: { type: 'string' },
        rawId: { type: 'string' },
        type: { type: 'string' },
        authenticatorAttachment: { type: 'string' },
        clientExtensionResults: { type: 'object' },
        response: {
          type: 'object',
          required: ['clientDataJSON'],
          additionalProperties: false,
          properties: {
            clientDataJSON: { type: 'string' },
            attestationObject: { type: 'string' },
            authenticatorData: { type: 'string' },
            signature: { type: 'string' },
            userHandle: { type: 'string' },
          },
        },
      },
    },
    // One code per identifier, at most 10 characters (Auth0 rejects longer ones).
    verification: {
      type: 'object',
      additionalProperties: false,
      properties: {
        email: { type: 'string', minLength: 1, maxLength: 10 },
        phone: { type: 'string', minLength: 1, maxLength: 10 },
      },
    },
  },
} as const;

export interface CompleteFailure {
  httpStatus: number;
  body: {
    status: 'retry' | 'invalid' | 'wait' | 'mfa_required' | 'session_expired' | 'restart' | 'failed';
    message?: string;
    verificationRequired?: PasskeyVerificationIdentifier[];
    retryAfterSeconds?: number;
  };
}

/**
 * Maps an error thrown by `passkey.complete()` to the answer the browser acts on. It follows the table in the
 * "Login and Signup using Passkeys" section of the SDK's EXAMPLES.md. The SDK has already kept or cleared the flow.
 */
export function completeFailure(error: unknown): CompleteFailure {
  if (isMfaRequiredError(error)) {
    // The passkey (and the codes) were accepted, but the user must complete MFA, which this example does not include.
    // Never send `error.cause.mfa_token` to the browser.
    return { httpStatus: 200, body: { status: 'mfa_required' } };
  }
  if (error instanceof SessionExpiredError) {
    // The passkey was accepted, but the ID token says the session has already expired, so no session was created.
    // The SDK has already deleted the flow: the user signs in again.
    return { httpStatus: 400, body: { status: 'session_expired' } };
  }
  if (error instanceof PasskeyGetTokenError && error.isRetryable) {
    // A wrong code. Ask again for the identifiers still listed, and send the same credential.
    return { httpStatus: 400, body: { status: 'retry', verificationRequired: error.verificationRequired ?? [] } };
  }
  if (error instanceof PasskeyGetTokenError && error.statusCode === 429) {
    // Auth0 checks its rate limit before it uses the attempt, so the same request can be sent again later.
    const retryAfter = Number(error.headers?.get('retry-after'));
    return { httpStatus: 429, body: { status: 'wait', ...(retryAfter > 0 && { retryAfterSeconds: retryAfter }) } };
  }
  if (
    error instanceof MissingRequiredArgumentError ||
    (error instanceof PasskeyGetTokenError && error.cause?.error === 'invalid_request')
  ) {
    // An incomplete or invalid request, for example a missing code. The flow is still open.
    return { httpStatus: 400, body: { status: 'invalid', message: describeError(error) } };
  }
  if (error instanceof MissingTransactionError) {
    // No flow to complete: none was started, it expired, or a newer start replaced it. Auth0 was not called.
    return { httpStatus: 400, body: { status: 'restart' } };
  }
  // Usually the end of the attempt (too many wrong codes, the time ran out). After a server or network error the SDK
  // keeps the flow, so the browser sends the same request once more before it starts again. A session store that
  // throws also lands here, but the flow is gone by then: the second request answers `restart`.
  return { httpStatus: 400, body: { status: 'failed', message: describeError(error) } };
}

/**
 * A short description of an error that is safe to log or show: the Auth0 error description and code when there is
 * one, else the message. A server or network failure has no Auth0 error, so the reason comes from `cause.message`
 * (for example "Failed to fetch"). Never log or return the whole error: the `cause` of a passkey error can hold an
 * `mfa_token`.
 */
export function describeError(error: unknown): string {
  if (!(error instanceof Error)) {
    return 'Unknown error';
  }
  const { cause } = error as { cause?: Record<string, unknown> };
  const detail = [cause?.error, cause?.code, cause?.message].find(
    (value): value is string => typeof value === 'string' && value !== ''
  );
  const description =
    typeof cause?.error_description === 'string' && cause.error_description ? cause.error_description : error.message;
  return detail ? `${description} (${detail})` : description;
}
