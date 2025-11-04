import type {
  FastifyInstance,
  FastifyRequest,
  RawServerBase,
  RawRequestDefaultExpression,
  RawReplyDefaultExpression,
  RawServerDefault,
} from 'fastify';
import fp from 'fastify-plugin';
import {
  CookieTransactionStore,
  ServerClient,
  StatelessStateStore,
  StatefulStateStore,
  StartInteractiveLoginOptions,
  AccessTokenForConnectionOptions,
  LoginBackchannelOptions,
  LogoutOptions,
  UserClaims,
  SessionData,
  LoginBackchannelResult,
  ConnectionTokenSet,
  TokenSet,
  StartLinkUserOptions,
  StartUnlinkUserOptions,
} from '@auth0/auth0-server-js';
import type { SessionConfiguration, SessionStore, StoreOptions } from './types.js';
import { createRouteUrl, toSafeRedirect } from './utils.js';
import { FastifyCookieHandler } from './store/fastify-cookie-handler.js';

export * from './types.js';
export { CookieTransactionStore } from '@auth0/auth0-server-js';
import type { AuthorizationDetails } from '@auth0/auth0-auth-js';
import { AsyncLocalStorage } from 'node:async_hooks';

export interface Auth0Client<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
> {
  /**
   * Starts an interactive login flow by generating the authorization URL and storing the necessary transaction data.
   * @param options Options for starting the interactive login flow.
   * @deprecated @param storeOptions
   * @returns
   */
  startInteractiveLogin: (
    options?: StartInteractiveLoginOptions,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<URL>;
  completeInteractiveLogin: <TAppState = unknown>(
    url: URL,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<{
    appState?: TAppState;
    authorizationDetails?: AuthorizationDetails[];
  }>;
  getUser(storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>): Promise<UserClaims | undefined>;
  getSession(storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>): Promise<SessionData | undefined>;
  getAccessToken(storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>): Promise<TokenSet>;
  getAccessTokenForConnection: (
    options: AccessTokenForConnectionOptions,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<ConnectionTokenSet>;
  loginBackchannel: (
    options: LoginBackchannelOptions,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<LoginBackchannelResult>;
  logout: (options: LogoutOptions, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => Promise<URL>;
  handleBackchannelLogout: (
    logoutToken: string,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<void>;

  startLinkUser: (
    options: StartLinkUserOptions,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<URL>;
  completeLinkUser: <TAppState = unknown>(
    url: URL,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<{
    appState?: TAppState;
  }>;
  startUnlinkUser: (
    options: StartUnlinkUserOptions,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<URL>;
  completeUnlinkUser: <TAppState = unknown>(
    url: URL,
    storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
  ) => Promise<{
    appState?: TAppState;
  }>;
}
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
    auth0Client: Auth0Client<RawServer, RawRequest, RawReply>| undefined;

  }
}

export interface Auth0FastifyOptions<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
> {
  domain: string;
  clientId: string;
  clientSecret?: string;
  clientAssertionSigningKey?: string | CryptoKey;
  clientAssertionSigningAlg?: string;
  audience?: string;
  appBaseUrl: string;

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
}

function toFastifyInstance<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
>(
  fastify: FastifyInstance<RawServer, RawRequest, RawReply>,
  serverClient: ServerClient<StoreOptions<RawServer, RawRequest, RawReply>>
) {
  return {
    startInteractiveLogin: (
      options?: StartInteractiveLoginOptions,
      storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
    ) => {
      return serverClient?.startInteractiveLogin(options, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    completeInteractiveLogin: <TAppState>(url: URL, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.completeInteractiveLogin<TAppState>(
        url,
        storeOptions ?? fastify.__auth0RequestContext.getStore()
      );
    },
    getUser: (storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.getUser(storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    getSession: (storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.getSession(storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    getAccessToken: (storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.getAccessToken(storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    getAccessTokenForConnection: (
      options: AccessTokenForConnectionOptions,
      storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
    ) => {
      return serverClient?.getAccessTokenForConnection(options, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    loginBackchannel: (
      options: LoginBackchannelOptions,
      storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
    ) => {
      return serverClient?.loginBackchannel(options, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    logout: (options: LogoutOptions, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.logout(options, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    handleBackchannelLogout: (logoutToken: string, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient?.handleBackchannelLogout(logoutToken, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    startLinkUser: (options: StartLinkUserOptions, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient.startLinkUser(options, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    completeLinkUser: <TAppState>(url: URL, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient.completeLinkUser<TAppState>(url, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    startUnlinkUser: (
      options: StartUnlinkUserOptions,
      storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>
    ) => {
      return serverClient.startUnlinkUser(options, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
    completeUnlinkUser: <TAppState>(url: URL, storeOptions?: StoreOptions<RawServer, RawRequest, RawReply>) => {
      return serverClient.completeUnlinkUser<TAppState>(url, storeOptions ?? fastify.__auth0RequestContext.getStore());
    },
  };
}

export default fp(async function auth0Fastify<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
>(
  fastify: FastifyInstance<RawServer, RawRequest, RawReply>,
  options: Auth0FastifyOptions<RawServer, RawRequest, RawReply>
) {
  const callbackPath = options.routes?.callback ?? '/auth/callback';
  const redirectUri = createRouteUrl(callbackPath, options.appBaseUrl);

  const auth0Client = new ServerClient<StoreOptions<RawServer, RawRequest, RawReply>>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    clientAssertionSigningKey: options.clientAssertionSigningKey,
    clientAssertionSigningAlg: options.clientAssertionSigningAlg,
    authorizationParams: {
      audience: options.audience,
      redirect_uri: redirectUri.toString(),
    },
    transactionStore: new CookieTransactionStore(
      { secret: options.sessionSecret },
      new FastifyCookieHandler<RawServer, RawRequest, RawReply>()
    ),
    stateStore: options.sessionStore
      ? new StatefulStateStore(
          {
            ...options.sessionConfiguration,
            secret: options.sessionSecret,
            store: options.sessionStore,
          },
          new FastifyCookieHandler<RawServer, RawRequest, RawReply>()
        )
      : new StatelessStateStore(
          {
            ...options.sessionConfiguration,
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
        const dangerousReturnTo = request.query.returnTo;
        const sanitizedReturnTo = toSafeRedirect(dangerousReturnTo || '/', options.appBaseUrl);

        const authorizationUrl = await auth0Client.startInteractiveLogin(
          {
            pushedAuthorizationRequests: options.pushedAuthorizationRequests,
            appState: { returnTo: sanitizedReturnTo },
          },
          { request, reply }
        );

        reply.redirect(authorizationUrl.href);
      }
    );

    fastify.get(options.routes?.callback ?? '/auth/callback', async (request, reply) => {
      const { appState } = await auth0Client.completeInteractiveLogin<{ returnTo: string } | undefined>(
        createRouteUrl(request.url, options.appBaseUrl),
        { request, reply }
      );

      reply.redirect(appState?.returnTo ?? options.appBaseUrl);
    });

    fastify.get(options.routes?.logout ?? '/auth/logout', async (request, reply) => {
      const returnTo = options.appBaseUrl;
      const logoutUrl = await auth0Client.logout({ returnTo: returnTo.toString() }, { request, reply });

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

          const sanitizedReturnTo = toSafeRedirect(dangerousReturnTo || '/', options.appBaseUrl);
          const callbackPath = options.routes?.connectCallback ?? '/auth/connect/callback';
          const redirectUri = createRouteUrl(callbackPath, options.appBaseUrl);
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
        const { appState } = await fastify.auth0Client!.completeLinkUser<{ returnTo: string }>(
          createRouteUrl(request.url, options.appBaseUrl),
          {
            request,
            reply,
          }
        );

        reply.redirect(appState?.returnTo ?? options.appBaseUrl);
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

          const sanitizedReturnTo = toSafeRedirect(dangerousReturnTo || '/', options.appBaseUrl);
          const callbackPath = options.routes?.unconnectCallback ?? '/auth/unconnect/callback';
          const redirectUri = createRouteUrl(callbackPath, options.appBaseUrl);
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
        const { appState } = await fastify.auth0Client!.completeUnlinkUser<{ returnTo: string }>(
          createRouteUrl(request.url, options.appBaseUrl),
          {
            request,
            reply,
          }
        );

        reply.redirect(appState?.returnTo ?? options.appBaseUrl);
      });
    }
  }

  
  // We rely on AsyncLocalStorage to store `FastifyRequest` and `FastifyReply` objects per request.
  // This ensures we simplify the public API, as consumers no longer need to pass these instances to the methods.
  const auth0RequestContext = new AsyncLocalStorage<StoreOptions<RawServer, RawRequest, RawReply>>();

  fastify.addHook('onRequest', (request, reply, done) => {
    // Create the store object for this specific request
    const store = {
      request: request,
      reply: reply,
    };

    // Run the rest of the request lifecycle (all subsequent hooks,
    // handlers, and replies) inside the AsyncLocalStorage context.
    auth0RequestContext.run(store, () => {
      done();
    });
  });

  fastify.decorate('auth0Client', toFastifyInstance(fastify, auth0Client));
  fastify.decorate('__auth0RequestContext', auth0RequestContext);
});
