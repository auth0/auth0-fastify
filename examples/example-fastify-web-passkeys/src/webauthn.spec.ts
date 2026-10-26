import { describe, expect, test } from 'vitest';
import {
  creationOptions,
  fromBase64url,
  requestOptions,
  serialize,
  toBase64url,
  webauthnMessage,
  // @ts-expect-error The browser module is plain JavaScript without type declarations.
} from '../public/webauthn.js';

const bytes = (...values: number[]) => new Uint8Array(values).buffer;
const toArray = (buffer: ArrayBuffer) => [...new Uint8Array(buffer)];

describe('base64url', () => {
  test('round trips bytes, including the characters that differ from base64', () => {
    const data = bytes(251, 255, 190, 0, 1, 2, 3);
    const encoded = toBase64url(data);

    expect(encoded).toBe('-_--AAECAw'); // "+/++" becomes "-_--", and there is no "=" padding
    expect(toArray(fromBase64url(encoded))).toEqual(toArray(data));
  });

  test('decodes values with and without padding', () => {
    expect(toArray(fromBase64url('YQ'))).toEqual([97]);
    expect(toArray(fromBase64url('YWI'))).toEqual([97, 98]);
    expect(toArray(fromBase64url('YWJj'))).toEqual([97, 98, 99]);
  });
});

describe('creationOptions', () => {
  test('decodes the challenge, the user id and the excluded credential ids', () => {
    const options = creationOptions({
      challenge: 'YWJj',
      rp: { id: 'login.example.com', name: 'Example' },
      user: { id: 'dXNlcg', name: 'jane', displayName: 'Jane' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ type: 'public-key', id: 'YQ' }],
      timeout: 60000,
    });

    expect(toArray(options.challenge)).toEqual([97, 98, 99]);
    expect(toArray(options.user.id)).toEqual([117, 115, 101, 114]);
    expect(toArray(options.excludeCredentials[0].id)).toEqual([97]);
    expect(options.rp).toEqual({ id: 'login.example.com', name: 'Example' });
    expect(options.timeout).toBe(60000);
  });

  test('does not add excludeCredentials when Auth0 sends none', () => {
    const options = creationOptions({ challenge: 'YQ', user: { id: 'YQ', name: 'a', displayName: 'a' } });

    expect(options).not.toHaveProperty('excludeCredentials');
  });
});

describe('requestOptions', () => {
  test('decodes the challenge and the allowed credential ids', () => {
    const options = requestOptions({
      challenge: 'YWJj',
      rpId: 'login.example.com',
      allowCredentials: [{ type: 'public-key', id: 'YQ' }],
    });

    expect(toArray(options.challenge)).toEqual([97, 98, 99]);
    expect(toArray(options.allowCredentials[0].id)).toEqual([97]);
    expect(options.rpId).toBe('login.example.com');
  });

  test('does not add allowCredentials for a discoverable login', () => {
    expect(requestOptions({ challenge: 'YQ', rpId: 'login.example.com' })).not.toHaveProperty('allowCredentials');
  });
});

describe('serialize', () => {
  const credential = (response: Record<string, ArrayBuffer | null>, extra: Record<string, unknown> = {}) => ({
    id: 'cred-id',
    rawId: bytes(1, 2, 3),
    type: 'public-key',
    response,
    getClientExtensionResults: () => ({ credProps: { rk: true } }),
    toJSON: () => ({ id: 'cred-id', extra: 'Auth0 rejects this' }),
    ...extra,
  });

  test('a signup credential has the attestation and nothing else', () => {
    const serialized = serialize(
      credential(
        { clientDataJSON: bytes(123, 125), attestationObject: bytes(4, 5) },
        { authenticatorAttachment: 'platform' }
      )
    );

    expect(serialized).toEqual({
      id: 'cred-id',
      rawId: 'AQID',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: { clientDataJSON: 'e30', attestationObject: 'BAU' },
      clientExtensionResults: { credProps: { rk: true } },
    });
  });

  test('a login credential has the assertion fields, and leaves out a null userHandle', () => {
    const serialized = serialize(
      credential({
        clientDataJSON: bytes(123, 125),
        authenticatorData: bytes(1),
        signature: bytes(2),
        userHandle: null,
      })
    );

    expect(serialized.response).toEqual({ clientDataJSON: 'e30', authenticatorData: 'AQ', signature: 'Ag' });
    expect(serialized).not.toHaveProperty('authenticatorAttachment');
  });

  test('never copies credential.toJSON() or other extra fields', () => {
    const serialized = serialize(credential({ clientDataJSON: bytes(123, 125), attestationObject: bytes(4, 5) }));

    expect(Object.keys(serialized).sort()).toEqual(['clientExtensionResults', 'id', 'rawId', 'response', 'type']);
  });
});

describe('webauthnMessage', () => {
  test.each([
    ['NotAllowedError', /closed or timed out/],
    ['InvalidStateError', /already has a passkey/],
    ['SecurityError', /RP ID/],
    ['SomethingElse', /failed: boom/],
  ])('explains %s', (name, expected) => {
    expect(webauthnMessage({ name, message: 'boom' })).toMatch(expected);
  });
});
