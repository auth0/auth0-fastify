import type {
  FastifyReply,
  FastifyRequest,
  RawServerBase,
  RawRequestDefaultExpression,
  RawReplyDefaultExpression,
  RawServerDefault,
  RouteGenericInterface,
} from 'fastify';
import {
  AccessTokenForConnectionOptions,
  ConnectionTokenSet,
  LoginBackchannelOptions,
  LoginBackchannelResult,
  LogoutOptions,
  LogoutTokenClaims,
  SessionData,
  StartInteractiveLoginOptions,
  StartLinkUserOptions,
  StartUnlinkUserOptions,
  StateData,
  TokenSet,
  UserClaims,
} from '@auth0/auth0-server-js';

import { AuthorizationDetails } from '@auth0/auth0-auth-js';

/**
 * Options for accessing the Fastify request and reply objects.
 * These are used in store implementations to interact with cookies and sessions.
 * 
 * FastifyInstance is a generic interface itself, whose generics represent the underlying server, request and reply types.
 * By including these in the StoreOptions generics, we ensure that the `StoreOptions` aware of the underlying server type (e.g., HTTP/1.1, HTTP/2, etc.).
 * 
 * @remark The generics default to the values used by a standard Fastify instance.
 */
export interface StoreOptions<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
> {
  request: FastifyRequest<RouteGenericInterface, RawServer, RawRequest>;
  reply: FastifyReply<RouteGenericInterface, RawServer, RawRequest, RawReply>;
}

export interface SessionStore<
  RawServer extends RawServerBase = RawServerDefault,
  RawRequest extends RawRequestDefaultExpression<RawServer> = RawRequestDefaultExpression<RawServer>,
  RawReply extends RawReplyDefaultExpression<RawServer> = RawReplyDefaultExpression<RawServer>
> {
  delete(identifier: string): Promise<void>;
  set(identifier: string, stateData: StateData): Promise<void>;
  get(identifier: string): Promise<StateData | undefined>;
  deleteByLogoutToken(
    claims: LogoutTokenClaims,
    options?: StoreOptions<RawServer, RawRequest, RawReply> | undefined
  ): Promise<void>;
}

export interface SessionCookieOptions {
  /**
   * The name of the session cookie.
   *
   * Default: `__a0_session`.
   */
  name?: string;
  /**
   * The sameSite attribute of the session cookie.
   *
   * Default: `lax`.
   */
  sameSite?: 'strict' | 'lax' | 'none';
  /**
   * The secure attribute of the session cookie.
   *
   * Default: depends on the protocol of the application's base URL. If the protocol is `https`, then `true`, otherwise `false`.
   */
  secure?: boolean;
}

export interface SessionConfiguration {
  /**
   * A boolean indicating whether rolling sessions should be used or not.
   *
   * When enabled, the session will continue to be extended as long as it is used within the inactivity duration.
   * Once the upper bound, set via the `absoluteDuration`, has been reached, the session will no longer be extended.
   *
   * Default: `true`.
   */
  rolling?: boolean;
  /**
   * The absolute duration after which the session will expire. The value must be specified in seconds..
   *
   * Once the absolute duration has been reached, the session will no longer be extended.
   *
   * Default: 3 days.
   */
  absoluteDuration?: number;
  /**
   * The duration of inactivity after which the session will expire. The value must be specified in seconds.
   *
   * The session will be extended as long as it was active before the inactivity duration has been reached.
   *
   * Default: 1 day.
   */
  inactivityDuration?: number;

  /**
   * The options for the session cookie.
   */
  cookie?: SessionCookieOptions;
}

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
