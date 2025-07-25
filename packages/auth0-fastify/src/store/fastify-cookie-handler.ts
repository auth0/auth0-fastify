import { CookieHandler, CookieSerializeOptions } from '@auth0/auth0-server-js';
import { StoreOptions } from '../types.js';
import { MissingStoreOptionsError } from '../errors/index.js';

export class FastifyCookieHandler implements CookieHandler<StoreOptions> {
  setCookie(
    name: string,
    value: string,
    options?: CookieSerializeOptions,
    storeOptions?: StoreOptions,
  ): void {
    if (!storeOptions) {
      throw new MissingStoreOptionsError();
    }

    storeOptions.reply.setCookie(name, value, options || {});
  }

  getCookie(name: string, storeOptions?: StoreOptions): string | undefined {
    if (!storeOptions) {
      throw new MissingStoreOptionsError();
    }

    return storeOptions.request.cookies?.[name];
  }

  getCookies(storeOptions?: StoreOptions): Record<string, string> {
    if (!storeOptions) {
      throw new MissingStoreOptionsError();
    }

    return storeOptions.request.cookies as Record<string, string>;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions): void {
    if (!storeOptions) {
      throw new MissingStoreOptionsError();
    }

    storeOptions.reply.clearCookie(name);
  }
}
