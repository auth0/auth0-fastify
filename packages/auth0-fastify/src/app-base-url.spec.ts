import { describe, expect, test } from 'vitest';
import { InvalidConfigurationError } from './errors/index.js';
import { normalizeAppBaseUrl, resolveAppBaseUrl, resolveSecureCookie } from './app-base-url.js';

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

describe('normalizeAppBaseUrl (allow-list)', () => {
  test('array returns allowlist mode with normalized origins', () => {
    const config = normalizeAppBaseUrl(['https://a.example.com', 'https://b.example.com/ignored-path']);
    expect(config.mode).toBe('allowlist');
    if (config.mode !== 'allowlist') throw new Error('expected allowlist');
    expect([...config.origins].sort()).toEqual(['https://a.example.com', 'https://b.example.com']);
  });

  test('empty array throws', () => {
    expect(() => normalizeAppBaseUrl([])).toThrow(InvalidConfigurationError);
  });

  test('array with a non-absolute entry throws', () => {
    expect(() => normalizeAppBaseUrl(['https://a.example.com', 'nope'])).toThrow(
      InvalidConfigurationError
    );
  });
});

describe('resolveAppBaseUrl (allow-list)', () => {
  test('returns inferred origin when it matches the allow-list', () => {
    const config = normalizeAppBaseUrl(['https://a.example.com', 'https://b.example.com']);
    expect(resolveAppBaseUrl(config, fakeRequest('b.example.com', 'https'))).toBe(
      'https://b.example.com'
    );
  });

  test('throws when inferred origin is not in the allow-list', () => {
    const config = normalizeAppBaseUrl(['https://a.example.com']);
    expect(() => resolveAppBaseUrl(config, fakeRequest('evil.example.com', 'https'))).toThrow(
      InvalidConfigurationError
    );
  });
});

describe('resolveSecureCookie', () => {
  const dynamic = { mode: 'dynamic' } as const;
  const stat = { mode: 'static', value: 'https://app.example.com' } as const;

  test('dynamic + unset defaults to true', () => {
    expect(resolveSecureCookie(dynamic, undefined, false)).toBe(true);
  });

  test('dynamic + explicit false in production throws', () => {
    expect(() => resolveSecureCookie(dynamic, false, true)).toThrow(InvalidConfigurationError);
  });

  test('dynamic + explicit false outside production is honored', () => {
    expect(resolveSecureCookie(dynamic, false, false)).toBe(false);
  });

  test('dynamic + explicit true is honored', () => {
    expect(resolveSecureCookie(dynamic, true, true)).toBe(true);
  });

  test('static returns the configured value unchanged (undefined)', () => {
    expect(resolveSecureCookie(stat, undefined, true)).toBeUndefined();
  });

  test('static returns the configured value unchanged (false in production)', () => {
    expect(resolveSecureCookie(stat, false, true)).toBe(false);
  });
});
