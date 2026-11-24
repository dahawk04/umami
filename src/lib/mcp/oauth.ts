import crypto from 'node:crypto';
import { secret } from '@/lib/crypto';
import { getBaseUrl } from '@/lib/get-base-url';
import { createSecureToken, parseSecureToken } from '@/lib/jwt';

/**
 * Minimal, stateless OAuth 2.1 authorization server for the remote MCP endpoint.
 *
 * MCP clients that only support OAuth (for example Claude custom connectors) discover these
 * endpoints, register themselves, and send the user to /oauth/authorize. There the user pastes
 * one of their Umami API keys. The key becomes the OAuth access token, so /mcp keeps
 * authenticating with the existing API-key check and needs no new storage.
 *
 * Client IDs, authorization codes and refresh tokens are encrypted, signed tokens built from
 * the app secret, so nothing is written to the database.
 */

export const OAUTH_CODE_TTL_SECONDS = 300;

const CLIENT_TYPE = 'mcp-oauth-client';
const CODE_TYPE = 'mcp-oauth-code';
const REFRESH_TYPE = 'mcp-oauth-refresh';
const MAX_REDIRECT_URIS = 10;
const MAX_CLIENT_NAME_LENGTH = 200;

export interface OAuthClient {
  redirectUris: string[];
  clientName?: string;
}

export interface AuthorizeParams {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  scope?: string;
  resource?: string;
}

/** The redirect URI is trusted: report the error back to the client. */
export interface AuthorizeRedirectFailure {
  ok: false;
  redirect: true;
  redirectUri: string;
  state?: string;
  error: string;
  description: string;
}

/** The client or redirect URI cannot be trusted: show the error, never redirect. */
export interface AuthorizePageFailure {
  ok: false;
  redirect: false;
  error: string;
}

export type AuthorizeFailure = AuthorizeRedirectFailure | AuthorizePageFailure;

export type AuthorizeValidation =
  | { ok: true; params: AuthorizeParams; client: OAuthClient }
  | AuthorizeFailure;

export function isMcpEnabled() {
  return process.env.MCP_ENABLED === '1';
}

export function getIssuer(headers?: Pick<Headers, 'get'>) {
  const baseUrl = getBaseUrl(headers).toString().replace(/\/+$/, '');
  const basePath = (process.env.BASE_PATH ?? '').replace(/\/+$/, '');

  return `${baseUrl}${basePath}`;
}

export function getProtectedResourceMetadataUrl(issuer: string) {
  return `${issuer}/.well-known/oauth-protected-resource`;
}

export function getProtectedResourceMetadata(issuer: string) {
  return {
    resource: `${issuer}/mcp`,
    authorization_servers: [issuer],
    bearer_methods_supported: ['header'],
    resource_name: 'Umami',
  };
}

export function getAuthorizationServerMetadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    authorization_response_iss_parameter_supported: true,
  };
}

function toBase64Url(value: string) {
  return Buffer.from(value, 'base64').toString('base64url');
}

function fromBase64Url(value: string) {
  return Buffer.from(value, 'base64url').toString('base64');
}

function seal(payload: object, options?: object) {
  return toBase64Url(createSecureToken(payload, secret(), options));
}

function unseal(token: unknown, type: string): any {
  if (typeof token !== 'string' || !token || token.length > 8192) {
    return null;
  }

  const payload: any = parseSecureToken(fromBase64Url(token), secret());

  return payload?.type === type ? payload : null;
}

function fingerprint(value: string) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

function safeEqual(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);

  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

/** Redirect URIs must be absolute https URLs, or http on a loopback host. No fragments. */
export function isValidRedirectUri(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048) {
    return false;
  }

  try {
    const url = new URL(value);

    if (url.hash) {
      return false;
    }

    if (url.protocol === 'https:') {
      return true;
    }

    return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  } catch {
    return false;
  }
}

export interface RegistrationSuccess {
  ok: true;
  body: Record<string, unknown>;
}

export interface RegistrationFailure {
  ok: false;
  error: string;
  description: string;
}

export type RegistrationResult = RegistrationSuccess | RegistrationFailure;

/** RFC 7591 dynamic client registration. The client ID carries its own redirect URIs. */
export function registerClient(metadata: any): RegistrationResult {
  const redirectUris = metadata?.redirect_uris;

  if (
    !Array.isArray(redirectUris) ||
    redirectUris.length === 0 ||
    redirectUris.length > MAX_REDIRECT_URIS ||
    !redirectUris.every(isValidRedirectUri)
  ) {
    return {
      ok: false,
      error: 'invalid_redirect_uri',
      description: 'redirect_uris must list https URLs (or http loopback URLs).',
    };
  }

  const authMethod = metadata?.token_endpoint_auth_method ?? 'none';

  if (authMethod !== 'none') {
    return {
      ok: false,
      error: 'invalid_client_metadata',
      description: 'Only public clients (token_endpoint_auth_method "none") are supported.',
    };
  }

  const clientName =
    typeof metadata?.client_name === 'string'
      ? metadata.client_name.slice(0, MAX_CLIENT_NAME_LENGTH)
      : undefined;

  const clientId = seal({ type: CLIENT_TYPE, ru: redirectUris, cn: clientName });

  return {
    ok: true,
    body: {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: clientName,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    },
  };
}

export function parseClientId(clientId: unknown): OAuthClient | null {
  const payload = unseal(clientId, CLIENT_TYPE);

  if (!payload || !Array.isArray(payload.ru)) {
    return null;
  }

  return { redirectUris: payload.ru, clientName: payload.cn };
}

function readParam(params: URLSearchParams, name: string) {
  const value = params.get(name);

  return value === null || value === '' ? undefined : value;
}

export function validateAuthorizeParams(params: URLSearchParams): AuthorizeValidation {
  const clientId = readParam(params, 'client_id');
  const client = parseClientId(clientId);

  if (!clientId || !client) {
    return { ok: false, redirect: false, error: 'Unknown or invalid client_id.' };
  }

  const redirectUri =
    readParam(params, 'redirect_uri') ??
    (client.redirectUris.length === 1 ? client.redirectUris[0] : undefined);

  if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
    return { ok: false, redirect: false, error: 'redirect_uri is not registered for this client.' };
  }

  const state = readParam(params, 'state');
  const fail = (error: string, description: string): AuthorizeValidation => ({
    ok: false,
    redirect: true,
    redirectUri,
    state,
    error,
    description,
  });

  if (params.get('response_type') !== 'code') {
    return fail('unsupported_response_type', 'Only response_type=code is supported.');
  }

  const codeChallenge = readParam(params, 'code_challenge');

  if (!codeChallenge || !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) {
    return fail('invalid_request', 'A PKCE code_challenge is required.');
  }

  if (params.get('code_challenge_method') !== 'S256') {
    return fail('invalid_request', 'code_challenge_method must be S256.');
  }

  return {
    ok: true,
    client,
    params: {
      clientId,
      redirectUri,
      codeChallenge,
      state,
      scope: readParam(params, 'scope'),
      resource: readParam(params, 'resource'),
    },
  };
}

export function buildRedirect(redirectUri: string, values: Record<string, string | undefined>) {
  const url = new URL(redirectUri);

  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
}

export function createAuthorizationCode(params: AuthorizeParams, apiKey: string) {
  return seal(
    {
      type: CODE_TYPE,
      cid: fingerprint(params.clientId),
      ru: params.redirectUri,
      cc: params.codeChallenge,
      k: apiKey,
    },
    { expiresIn: OAUTH_CODE_TTL_SECONDS },
  );
}

export function createRefreshToken(clientId: string, apiKey: string) {
  return seal({ type: REFRESH_TYPE, cid: fingerprint(clientId), k: apiKey });
}

export interface TokenSuccess {
  ok: true;
  apiKey: string;
  clientId: string;
}

export interface TokenFailure {
  ok: false;
  status: number;
  error: string;
  description: string;
}

export type TokenExchange = TokenSuccess | TokenFailure;

function tokenError(error: string, description: string, status = 400): TokenExchange {
  return { ok: false, status, error, description };
}

/** Validates a token request and returns the API key it grants. */
export function exchangeToken(params: URLSearchParams): TokenExchange {
  const grantType = params.get('grant_type');
  const clientId = readParam(params, 'client_id');

  if (!clientId || !parseClientId(clientId)) {
    return tokenError('invalid_client', 'Unknown or invalid client_id.', 401);
  }

  if (grantType === 'authorization_code') {
    const payload = unseal(params.get('code'), CODE_TYPE);

    if (!payload || !safeEqual(payload.cid, fingerprint(clientId))) {
      return tokenError('invalid_grant', 'The authorization code is invalid or expired.');
    }

    if (params.get('redirect_uri') !== payload.ru) {
      return tokenError('invalid_grant', 'redirect_uri does not match the authorization request.');
    }

    const verifier = params.get('code_verifier');

    if (
      !verifier ||
      !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
      !safeEqual(fingerprint(verifier), payload.cc)
    ) {
      return tokenError('invalid_grant', 'PKCE verification failed.');
    }

    return { ok: true, apiKey: payload.k, clientId };
  }

  if (grantType === 'refresh_token') {
    const payload = unseal(params.get('refresh_token'), REFRESH_TYPE);

    if (!payload || !safeEqual(payload.cid, fingerprint(clientId))) {
      return tokenError('invalid_grant', 'The refresh token is invalid.');
    }

    return { ok: true, apiKey: payload.k, clientId };
  }

  return tokenError('unsupported_grant_type', 'Use authorization_code or refresh_token.');
}

export const OAUTH_CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': '*',
  'access-control-max-age': '86400',
};

export function oauthJson(body: unknown, status = 200) {
  return Response.json(body, {
    status,
    headers: { ...OAUTH_CORS_HEADERS, 'cache-control': 'no-store' },
  });
}

export function oauthOptions() {
  return new Response(null, { status: 204, headers: OAUTH_CORS_HEADERS });
}

export function notFound() {
  return new Response(null, { status: 404 });
}
