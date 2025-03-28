import { expect, test, vi } from 'vitest';
import { CookieTransactionStore } from './cookie-transaction-store.js';
import type { StoreOptions } from '../types.js';
import { decrypt, encrypt } from './test-utils.js';

test('get - should throw when no storeOptions provided', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' });

  await expect(store.get('<identifier>')).rejects.toThrowError(
    'The store options are missing, making it impossible to interact with the store.'
  );
});

test('get - should read cookie from request', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' });
  const cookieValue = { codeVerifier: '<code_verifier>' };
  const storeOptions = {
    request: {
      cookies: {
        '<identifier>': await encrypt(cookieValue, '<secret>', '<identifier>', Date.now() / 1000),
      },
    },
    reply: {
      setCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  const value = await store.get('<identifier>', storeOptions);
  expect(value).toStrictEqual(expect.objectContaining(cookieValue));
});

test('set - should throw when no storeOptions provided', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' });

  await expect(store.set('<identifier>', { codeVerifier: '<code_verifier>' })).rejects.toThrowError(
    'The store options are missing, making it impossible to interact with the store.'
  );
});

test('set - should call reply to set the cookie', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' });
  const cookieValue = { codeVerifier: '<code_verifier>' };
  const setCookieMock = vi.fn();
  const storeOptions = {
    request: {},
    reply: {
      setCookie: setCookieMock,
    },
  } as unknown as StoreOptions;

  await store.set('<identifier>', cookieValue, false, storeOptions);

  const args = setCookieMock.mock.calls[0];
  const retrievedCookieValue = await decrypt(args![1], '<secret>', '<identifier>');

  expect(args![0]).toBe('<identifier>');
  expect(retrievedCookieValue).toStrictEqual(expect.objectContaining(cookieValue));
  expect(args![2]).toMatchObject(
    expect.objectContaining({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 3600,
    })
  );
});

test('delete - should throw when no storeOptions provided', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' });

  await expect(store.delete('<identifier>')).rejects.toThrowError(
    'The store options are missing, making it impossible to interact with the store.'
  );
});

test('delete - should call reply to clear the cookie', async () => {
  const store = new CookieTransactionStore({ secret: '<secret>' });
  const storeOptions = {
    request: {},
    reply: {
      clearCookie: vi.fn(),
    },
  } as unknown as StoreOptions;

  await store.delete('<identifier>', storeOptions);
  expect(storeOptions.reply.clearCookie).toHaveBeenCalledWith('<identifier>');
});
