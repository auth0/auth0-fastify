import type {
  FastifyInstance,
  FastifyRequest,
  RouteGenericInterface,
  RawServerBase,
  RawRequestDefaultExpression,
  RawReplyDefaultExpression,
  RawServerDefault,
} from 'fastify';
import fp from 'fastify-plugin';
import { CookieTransactionStore, ServerClient, StatelessStateStore, StatefulStateStore } from '@auth0/auth0-server-js';
import type { DomainResolver } from '@auth0/auth0-server-js';
import type { DiscoveryCacheOptions, SessionConfiguration, SessionStore, StoreOptions } from './types.js';
import { createRouteUrl, toSafeRedirect } from './utils.js';
import { FastifyCookieHandler } from './store/fastify-cookie-handler.js';
import { normalizeAppBaseUrl, resolveAppBaseUrl, resolveSecureCookie } from './app-base-url.js';
import { InvalidConfigurationError } from './errors/index.js';

export * from './types.js';
export type { DomainResolver } from '@auth0/auth0-server-js';
export type {
  LoginWithCustomTokenExchangeOptions,
  CustomTokenExchangeOptions,
  LoginWithCustomTokenExchangeResult,
  TokenResponse,
  ActClaim,
} from '@auth0/auth0-server-js';
export { CookieTransactionStore } from '@auth0/auth0-server-js';
export { TokenExchangeError, MissingClientAuthError } from '@auth0/auth0-server-js';
export { InvalidConfigurationError } from './errors/index.js';

declare module 'fastify' {
  /**
   * FastifyInstance is a generic interface, whose generics represent the underlying server, request and reply types.
   * By extending the interface with the same generics, we ensure that the `auth0Client` property is aware
   * of the underlying server type (e.g., HTTP/1.1, HTTP/2, etc.).
   *
   * @remark The generics default to the values used by a standard Fastify instance.
   */
  interface FastifyInstance<
    RawServer extends RawServerBase = RawServerDefault,
    RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
    RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
  > {
    /**
     * The Auth0 Server Client instance attached to the Fastify instance.
     * This client is used to interact with Auth0 for authentication and session management.
     *
     * We pass-through the FastifyInstance generics to ensure compatibility with different server types.
     */
    auth0Client: ServerClient<StoreOptions<RawServer, RawRequest, RawReply>> | undefined;
  }
}

type Auth0FastifyCommonOptions<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
> = {
  clientId: string;
  clientSecret?: string;
  clientAssertionSigningKey?: string | CryptoKey;
  clientAssertionSigningAlg?: string;
  audience?: string;

  pushedAuthorizationRequests?: boolean;

  sessionSecret: string;
  sessionStore?: SessionStore<RawServer, RawRequest, RawReply>;
  sessionConfiguration?: SessionConfiguration;
  /**
   * Whether to mount the default routes for login, logout, callback and profile.
   * Defaults to true.
   */
  mountRoutes?: boolean;
  /**
   * Whether to mount the routes for account linking and unlinking.
   * Defaults to false.
   */
  mountConnectRoutes?: boolean;
  /**
   * Optional, custom Fetch implementation to use.
   */
  customFetch?: typeof fetch;
  /**
   * Optional discovery cache configuration for OIDC metadata and JWKS fetchers.
   * TTL is in seconds. Defaults to the ServerClient defaults when omitted.
   */
  discoveryCache?: DiscoveryCacheOptions;

  routes?: {
    login?: string;
    callback?: string;
    logout?: string;
    backchannelLogout?: string;
    connect?: string;
    connectCallback?: string;
    unconnect?: string;
    unconnectCallback?: string;
  };
};

export type Auth0FastifyOptions<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
> = Auth0FastifyCommonOptions<RawServer, RawRequest, RawReply> & {
  domain: string | DomainResolver<StoreOptions<RawServer, RawRequest, RawReply>>;
  /**
   * The base URL(s) of the application, used for redirects and callbacks.
   *
   * - `string`: a static base URL (existing behavior).
   * - `string[]`: an allow-list. The base URL is inferred per request and must
   *   match one of these origins, otherwise the request is rejected with HTTP 500.
   * - omitted: inferred per request from `request.host`/`request.protocol`.
   *
   * When omitted or an array and running behind a proxy, configure Fastify's
   * `trustProxy` so `request.host`/`request.protocol` are derived from the
   * forwarded headers your proxy sets.
   */
  appBaseUrl?: string | string[];
};

export default fp(async function auth0Fastify<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
>(
  fastify: FastifyInstance<RawServer, RawRequest, RawReply>,
  options: Auth0FastifyOptions<RawServer, RawRequest, RawReply>
) {
  const callbackPath = options.routes?.callback ?? '/auth/callback';
  const appBaseUrlConfig = normalizeAppBaseUrl(options.appBaseUrl);
  const staticRedirectUri =
    appBaseUrlConfig.mode === 'static' ? createRouteUrl(callbackPath, appBaseUrlConfig.value) : undefined;

  const isProduction = process.env.NODE_ENV === 'production';
  const resolvedSecure = resolveSecureCookie(
    appBaseUrlConfig,
    options.sessionConfiguration?.cookie?.secure,
    isProduction
  );

  const resolveBaseUrl = (request: FastifyRequest<RouteGenericInterface, RawServer, RawRequest>): string =>
    resolveAppBaseUrl(appBaseUrlConfig, request);

  const resolveOr500 = (
    request: FastifyRequest<RouteGenericInterface, RawServer, RawRequest>,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    reply: any
  ): string | undefined => {
    try {
      return resolveBaseUrl(request);
    } catch (e) {
      if (e instanceof InvalidConfigurationError) {
        reply.code(500).send(e.message);
        return undefined;
      }
      throw e;
    }
  };

  const auth0Client = new ServerClient<StoreOptions<RawServer, RawRequest, RawReply>>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    clientAssertionSigningKey: options.clientAssertionSigningKey,
    clientAssertionSigningAlg: options.clientAssertionSigningAlg,
    authorizationParams: {
      audience: options.audience,
      ...(staticRedirectUri ? { redirect_uri: staticRedirectUri.toString() } : {}),
    },
    discoveryCache: options.discoveryCache,
    transactionStore: new CookieTransactionStore(
      { secret: options.sessionSecret },
      new FastifyCookieHandler<RawServer, RawRequest, RawReply>()
    ),
    stateStore: options.sessionStore
      ? new StatefulStateStore(
          {
            ...options.sessionConfiguration,
            cookie: { ...options.sessionConfiguration?.cookie, secure: resolvedSecure },
            secret: options.sessionSecret,
            store: options.sessionStore,
          },
          new FastifyCookieHandler<RawServer, RawRequest, RawReply>()
        )
      : new StatelessStateStore(
          {
            ...options.sessionConfiguration,
            cookie: { ...options.sessionConfiguration?.cookie, secure: resolvedSecure },
            secret: options.sessionSecret,
          },
          new FastifyCookieHandler<RawServer, RawRequest, RawReply>()
        ),
    stateIdentifier: options.sessionConfiguration?.cookie?.name,
    customFetch: options.customFetch,
  });

  if (!fastify.hasReplyDecorator('cookie')) {
    fastify.register(import('@fastify/cookie'));
  }

  const shouldMountRoutes = options.mountRoutes ?? true;

  if (shouldMountRoutes) {
    fastify.get(
      options.routes?.login ?? '/auth/login',
      async (
        request: FastifyRequest<
          {
            Querystring: { returnTo?: string };
          },
          RawServer,
          RawRequest
        >,
        reply
      ) => {
        const appBaseUrl = resolveOr500(request, reply);
        if (!appBaseUrl) return;
        const dangerousReturnTo = request.query.returnTo;
        const sanitizedReturnTo = toSafeRedirect(dangerousReturnTo || '/', appBaseUrl);
        const redirectUri = createRouteUrl(callbackPath, appBaseUrl);

        const authorizationUrl = await auth0Client.startInteractiveLogin(
          {
            pushedAuthorizationRequests: options.pushedAuthorizationRequests,
            appState: { returnTo: sanitizedReturnTo },
            authorizationParams: {
              redirect_uri: redirectUri.toString(),
            },
          },
          { request, reply }
        );

        reply.redirect(authorizationUrl.href);
      }
    );

    fastify.get(options.routes?.callback ?? '/auth/callback', async (request, reply) => {
      const appBaseUrl = resolveOr500(request, reply);
      if (!appBaseUrl) return;
      const { appState } = await auth0Client.completeInteractiveLogin<{ returnTo: string } | undefined>(
        createRouteUrl(request.url, appBaseUrl),
        { request, reply }
      );

      reply.redirect(appState?.returnTo ?? appBaseUrl);
    });

    fastify.get(options.routes?.logout ?? '/auth/logout', async (request, reply) => {
      const appBaseUrl = resolveOr500(request, reply);
      if (!appBaseUrl) return;
      const logoutUrl = await auth0Client.logout({ returnTo: appBaseUrl.toString() }, { request, reply });

      reply.redirect(logoutUrl.href);
    });

    fastify.post(
      options.routes?.backchannelLogout ?? '/auth/backchannel-logout',
      async (
        request: FastifyRequest<
          {
            Body: { logout_token?: string };
          },
          RawServer,
          RawRequest
        >,
        reply
      ) => {
        const logoutToken = request.body.logout_token;

        if (!logoutToken) {
          reply.code(400).send('Missing `logout_token` in the request body.');

          return;
        }

        try {
          await auth0Client.handleBackchannelLogout(logoutToken, { request, reply });
          reply.code(204).send(null);
        } catch (e) {
          reply.code(400).send((e as Error).message);
        }
      }
    );

    const shouldMountConnectRoutes = options.mountConnectRoutes ?? false;

    if (shouldMountConnectRoutes) {
      fastify.get(
        options.routes?.connect ?? '/auth/connect',
        async (
          request: FastifyRequest<
            {
              Querystring: { connection: string; connectionScope: string; returnTo?: string };
            },
            RawServer,
            RawRequest
          >,
          reply
        ) => {
          const { connection, connectionScope, returnTo } = request.query;
          const dangerousReturnTo = returnTo;

          if (!connection) {
            return reply.code(400).send({
              error: 'invalid_request',
              error_description: 'connection is required',
            });
          }

          const appBaseUrl = resolveOr500(request, reply);
          if (!appBaseUrl) return;
          const sanitizedReturnTo = toSafeRedirect(dangerousReturnTo || '/', appBaseUrl);
          const callbackPath = options.routes?.connectCallback ?? '/auth/connect/callback';
          const redirectUri = createRouteUrl(callbackPath, appBaseUrl);
          const linkUserUrl = await fastify.auth0Client!.startLinkUser(
            {
              connection: connection,
              connectionScope: connectionScope,
              authorizationParams: {
                redirect_uri: redirectUri.toString(),
              },
              appState: {
                returnTo: sanitizedReturnTo,
              },
            },
            { request, reply }
          );

          reply.redirect(linkUserUrl.href);
        }
      );

      fastify.get(options.routes?.connectCallback ?? '/auth/connect/callback', async (request, reply) => {
        const appBaseUrl = resolveOr500(request, reply);
        if (!appBaseUrl) return;
        const { appState } = await fastify.auth0Client!.completeLinkUser<{ returnTo: string }>(
          createRouteUrl(request.url, appBaseUrl),
          {
            request,
            reply,
          }
        );

        reply.redirect(appState?.returnTo ?? appBaseUrl);
      });

      fastify.get(
        options.routes?.unconnect ?? '/auth/unconnect',
        async (
          request: FastifyRequest<
            {
              Querystring: { connection: string; returnTo?: string };
            },
            RawServer,
            RawRequest
          >,
          reply
        ) => {
          const { connection, returnTo } = request.query;
          const dangerousReturnTo = returnTo;

          if (!connection) {
            return reply.code(400).send({
              error: 'invalid_request',
              error_description: 'connection is required',
            });
          }

          const appBaseUrl = resolveOr500(request, reply);
          if (!appBaseUrl) return;
          const sanitizedReturnTo = toSafeRedirect(dangerousReturnTo || '/', appBaseUrl);
          const callbackPath = options.routes?.unconnectCallback ?? '/auth/unconnect/callback';
          const redirectUri = createRouteUrl(callbackPath, appBaseUrl);
          const linkUserUrl = await fastify.auth0Client!.startUnlinkUser(
            {
              connection: connection,
              authorizationParams: {
                redirect_uri: redirectUri.toString(),
              },
              appState: {
                returnTo: sanitizedReturnTo,
              },
            },
            { request, reply }
          );

          reply.redirect(linkUserUrl.href);
        }
      );

      fastify.get(options.routes?.unconnectCallback ?? '/auth/unconnect/callback', async (request, reply) => {
        const appBaseUrl = resolveOr500(request, reply);
        if (!appBaseUrl) return;
        const { appState } = await fastify.auth0Client!.completeUnlinkUser<{ returnTo: string }>(
          createRouteUrl(request.url, appBaseUrl),
          {
            request,
            reply,
          }
        );

        reply.redirect(appState?.returnTo ?? appBaseUrl);
      });
    }
  }

  fastify.decorate('auth0Client', auth0Client);
});
