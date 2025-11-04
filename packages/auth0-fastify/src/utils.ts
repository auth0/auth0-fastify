import {
  AccessTokenForConnectionOptions,
  LoginBackchannelOptions,
  LogoutOptions,
  ServerClient,
  StartInteractiveLoginOptions,
  StartLinkUserOptions,
  StartUnlinkUserOptions,
} from '@auth0/auth0-server-js';
import {
  RawReplyDefaultExpression,
  RawRequestDefaultExpression,
  RawServerBase,
  RawServerDefault,
} from 'fastify';
import { StoreOptions } from './types.js';
import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Ensures the value has a trailing slash.
 * If it does not, it will append one.
 * @param value The value to ensure has a trailing slash.
 * @returns The value with a trailing slash.
 */
function ensureTrailingSlash(value: string) {
  return value && !value.endsWith('/') ? `${value}/` : value;
}

/**
 * Ensures the value does not have a leading slash.
 * If it does, it will trim it.
 * @param value The value to ensure has no leading slash.
 * @returns The value without a leading slash.
 */
function ensureNoLeadingSlash(value: string) {
  return value && value.startsWith('/') ? value.substring(1, value.length) : value;
}

/**
 * Utility function to ensure Route URLs are created correctly when using both the root and subpath as base URL.
 * @param url The URL to use.
 * @param base The base URL to use.
 * @returns A URL object, combining the base and url.
 */
export function createRouteUrl(url: string, base: string) {
  return new URL(ensureNoLeadingSlash(url), ensureTrailingSlash(base));
}

/**
 * Function to ensure a redirect URL is safe to use, as in, it has the same origin as the safeBaseUrl.
 * @param dangerousRedirect The redirect URL to check.
 * @param safeBaseUrl The base URL to check against.
 * @returns A safe redirect URL or undefined if the redirect URL is not safe.
 */
export function toSafeRedirect(dangerousRedirect: string, safeBaseUrl: string): string | undefined {
  let url: URL;

  try {
    url = createRouteUrl(dangerousRedirect, safeBaseUrl);
  } catch {
    return undefined;
  }

  if (url.origin === new URL(safeBaseUrl).origin) {
    return url.toString();
  }

  return undefined;
}

/**
 * Converts a ServerClient to a FastifyInstance-bound client.
 *
 * This allows using the client methods without explicitly passing StoreOptions,
 * as they will be automatically retrieved from the FastifyInstance's AsyncLocalStorage context (`requestContext`).
 * @param serverClient The server client.
 * @param requestContext The AsyncLocalStorage context holding the StoreOptions.
 * @returns The FastifyInstance-bound client.
 */
export function toFastifyInstance<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
>(
  serverClient: ServerClient<StoreOptions<RawServer, RawRequest, RawReply>>,
  requestContext: AsyncLocalStorage<StoreOptions<RawServer, RawRequest, RawReply>>
) {
  return {
    startInteractiveLogin: (
      options?: StartInteractiveLoginOptions,
      storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
    ) => {
      return serverClient?.startInteractiveLogin(options, storeOptions ?? requestContext.getStore());
    },
    completeInteractiveLogin: <TAppState>(url: URL, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.completeInteractiveLogin<TAppState>(
        url,
        storeOptions ?? requestContext.getStore()
      );
    },
    getUser: (storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.getUser(storeOptions ?? requestContext.getStore());
    },
    getSession: (storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.getSession(storeOptions ?? requestContext.getStore());
    },
    getAccessToken: (storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.getAccessToken(storeOptions ?? requestContext.getStore());
    },
    getAccessTokenForConnection: (
      options: AccessTokenForConnectionOptions,
      storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
    ) => {
      return serverClient?.getAccessTokenForConnection(
        options,
        storeOptions ?? requestContext.getStore()
      );
    },
    loginBackchannel: (
      options: LoginBackchannelOptions,
      storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
    ) => {
      return serverClient?.loginBackchannel(options, storeOptions ?? requestContext.getStore());
    },
    logout: (options: LogoutOptions, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.logout(options, storeOptions ?? requestContext.getStore());
    },
    handleBackchannelLogout: (logoutToken: string, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.handleBackchannelLogout(
        logoutToken,
        storeOptions ?? requestContext.getStore()
      );
    },
    startLinkUser: (options: StartLinkUserOptions, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient.startLinkUser(options, storeOptions ?? requestContext.getStore());
    },
    completeLinkUser: <TAppState>(url: URL, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient.completeLinkUser<TAppState>(url, storeOptions ?? requestContext.getStore());
    },
    startUnlinkUser: (
      options: StartUnlinkUserOptions,
      storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
    ) => {
      return serverClient.startUnlinkUser(options, storeOptions ?? requestContext.getStore());
    },
    completeUnlinkUser: <TAppState>(url: URL, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient.completeUnlinkUser<TAppState>(url, storeOptions ?? requestContext.getStore());
    },
  };
}
