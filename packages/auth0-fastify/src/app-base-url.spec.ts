import { describe, expect, test } from 'vitest';
import { InvalidConfigurationError } from './errors/index.js';
import { normalizeAppBaseUrl, resolveAppBaseUrl } from './app-base-url.js';

// Minimal stand-in for the parts of FastifyRequest the module reads.
function fakeRequest(host: string | undefined, protocol: string) {
  return { host, protocol } as unknown as Parameters<typeof resolveAppBaseUrl>[1];
}

describe('normalizeAppBaseUrl', () => {
  test('string returns static mode', () => {
    expect(normalizeAppBaseUrl('https://app.example.com')).toEqual({
      mode: 'static',
      value: 'https://app.example.com',
    });
  });

  test('undefined returns dynamic mode', () => {
    expect(normalizeAppBaseUrl(undefined)).toEqual({ mode: 'dynamic' });
  });

  test('non-absolute string throws', () => {
    expect(() => normalizeAppBaseUrl('not-a-url')).toThrow(InvalidConfigurationError);
  });
});

describe('resolveAppBaseUrl (static + dynamic)', () => {
  test('static returns configured value regardless of request', () => {
    const config = normalizeAppBaseUrl('https://app.example.com');
    expect(resolveAppBaseUrl(config, fakeRequest('other.example.com', 'http'))).toBe(
      'https://app.example.com'
    );
  });

  test('dynamic infers from request host and protocol', () => {
    const config = normalizeAppBaseUrl(undefined);
    expect(resolveAppBaseUrl(config, fakeRequest('app.example.com', 'https'))).toBe(
      'https://app.example.com'
    );
  });

  test('dynamic throws when host is missing', () => {
    const config = normalizeAppBaseUrl(undefined);
    expect(() => resolveAppBaseUrl(config, fakeRequest(undefined, 'https'))).toThrow(
      InvalidConfigurationError
    );
  });
});
