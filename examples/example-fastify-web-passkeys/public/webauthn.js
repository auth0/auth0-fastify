// The WebAuthn steps every passkey page needs. These are pure functions: they only convert data.

// Auth0 sends binary values as base64url strings. The WebAuthn API wants ArrayBuffers.
export function fromBase64url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0)).buffer;
}

export function toBase64url(buffer) {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const decodeIds = (descriptors) =>
  descriptors.map((descriptor) => ({ ...descriptor, id: fromBase64url(descriptor.id) }));

// `authnParamsPublicKey` from the signup start route, ready for `navigator.credentials.create({ publicKey })`.
export function creationOptions(options) {
  return {
    ...options,
    challenge: fromBase64url(options.challenge),
    user: { ...options.user, id: fromBase64url(options.user.id) },
    ...(options.excludeCredentials && { excludeCredentials: decodeIds(options.excludeCredentials) }),
  };
}

// `authnParamsPublicKey` from the login start route, ready for `navigator.credentials.get({ publicKey })`.
export function requestOptions(options) {
  return {
    ...options,
    challenge: fromBase64url(options.challenge),
    ...(options.allowCredentials && { allowCredentials: decodeIds(options.allowCredentials) }),
  };
}

// The credential the browser made, as the JSON the complete route takes. Send only these fields:
// do not send `credential.toJSON()`, because Auth0 rejects its extra fields.
export function serialize(credential) {
  const raw = credential.response;
  const response = { clientDataJSON: toBase64url(raw.clientDataJSON) };
  if (raw.attestationObject) response.attestationObject = toBase64url(raw.attestationObject);
  if (raw.authenticatorData) response.authenticatorData = toBase64url(raw.authenticatorData);
  if (raw.signature) response.signature = toBase64url(raw.signature);
  if (raw.userHandle) response.userHandle = toBase64url(raw.userHandle);
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    ...(credential.authenticatorAttachment && { authenticatorAttachment: credential.authenticatorAttachment }),
    response,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

// A sentence for an error that `navigator.credentials.create()` or `.get()` threw.
export function webauthnMessage(error) {
  switch (error?.name) {
    case 'NotAllowedError':
      return 'The passkey prompt was closed or timed out.';
    case 'InvalidStateError':
      return 'This device already has a passkey for this account.';
    case 'SecurityError':
      return 'The browser refused the passkey: the page origin does not fit its RP ID (your custom domain).';
    default:
      return `The passkey prompt failed: ${error?.message ?? error}`;
  }
}
