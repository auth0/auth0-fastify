import { CookieHandler, CookieSerializeOptions } from '@auth0/auth0-server-js';
import type { RawServerBase, RawRequestDefaultExpression, RawReplyDefaultExpression, RawServerDefault } from 'fastify';
import { StoreOptions } from '../types.js';
import { MissingStoreOptionsError } from '../errors/index.js';

export class FastifyCookieHandler<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
> implements CookieHandler<StoreOptions<RawServer, RawRequest, RawReply>>
{
  setCookie(
    name: string,
    value: string,
    options?: CookieSerializeOptions,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ): void {
    if (!storeOptions) {
      throw new MissingStoreOptionsError();
    }

    storeOptions.reply.setCookie(name, value, options || {});
  }

  getCookie(name: string, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>): string | undefined {
    if (!storeOptions) {
      throw new MissingStoreOptionsError();
    }

    return storeOptions.request.cookies?.[name];
  }

  getCookies(storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>): Record<string, string> {
    if (!storeOptions) {
      throw new MissingStoreOptionsError();
    }

    return storeOptions.request.cookies as Record<string, string>;
  }

  deleteCookie(name: string, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>): void {
    if (!storeOptions) {
      throw new MissingStoreOptionsError();
    }

    storeOptions.reply.clearCookie(name);
  }
}
