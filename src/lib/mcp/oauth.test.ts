import crypto from 'node:crypto';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import {
  createAuthorizationCode,
  createRefreshToken,
  exchangeToken,
  getAuthorizationServerMetadata,
  getProtectedResourceMetadata,
  isValidRedirectUri,
  parseClientId,
  registerClient,
  validateAuthorizeParams,
} from './oauth';

const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const API_KEY = 'umami_abcdefghijklmnopqrstuvwxyz123456';

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

  return { verifier, challenge };
}

function register(redirectUris = [REDIRECT]) {
  const result = registerClient({ redirect_uris: redirectUris, client_name: 'Claude' });

  if (!result.ok) {
    throw new Error('registration failed');
  }

  return result.body.client_id as string;
}

function authorizeParams(clientId: string, challenge: string, extra: Record<string, string> = {}) {
  return new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'xyz',
    ...extra,
  });
}

beforeEach(() => {
  vi.unstubAllEnvs();
  vi.stubEnv('APP_SECRET', 'test-secret-for-oauth');
});

describe('metadata', () => {
  test('points the resource at /mcp and the endpoints at the issuer', () => {
    expect(getProtectedResourceMetadata('https://a.example')).toMatchObject({
      resource: 'https://a.example/mcp',
      authorization_servers: ['https://a.example'],
    });
    expect(getAuthorizationServerMetadata('https://a.example')).toMatchObject({
      issuer: 'https://a.example',
      authorization_endpoint: 'https://a.example/oauth/authorize',
      token_endpoint: 'https://a.example/oauth/token',
      registration_endpoint: 'https://a.example/oauth/register',
      code_challenge_methods_supported: ['S256'],
    });
  });
});

describe('registerClient', () => {
  test('issues a URL-safe client_id that carries the redirect URIs', () => {
    const clientId = register();

    expect(clientId).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(parseClientId(clientId)).toEqual({ redirectUris: [REDIRECT], clientName: 'Claude' });
  });

  test.each([
    [{}],
    [{ redirect_uris: [] }],
    [{ redirect_uris: ['http://evil.example/cb'] }],
    [{ redirect_uris: ['https://a.example/cb#frag'] }],
    [{ redirect_uris: ['javascript:alert(1)'] }],
  ])('rejects bad redirect URIs %j', metadata => {
    expect(registerClient(metadata)).toMatchObject({ ok: false, error: 'invalid_redirect_uri' });
  });

  test('rejects confidential clients', () => {
    expect(
      registerClient({
        redirect_uris: [REDIRECT],
        token_endpoint_auth_method: 'client_secret_post',
      }),
    ).toMatchObject({ ok: false, error: 'invalid_client_metadata' });
  });

  test('allows loopback http redirect URIs', () => {
    expect(isValidRedirectUri('http://localhost:3334/callback')).toBe(true);
    expect(isValidRedirectUri('http://127.0.0.1/callback')).toBe(true);
  });

  test('rejects forged client IDs', () => {
    expect(parseClientId('not-a-client')).toBeNull();
    expect(parseClientId(createRefreshToken(register(), API_KEY))).toBeNull();
  });
});

describe('validateAuthorizeParams', () => {
  test('accepts a valid request', () => {
    const clientId = register();
    const result = validateAuthorizeParams(authorizeParams(clientId, pkce().challenge));

    expect(result).toMatchObject({
      ok: true,
      params: { clientId, redirectUri: REDIRECT, state: 'xyz' },
    });
  });

  test('never redirects to an unregistered redirect URI', () => {
    const clientId = register();
    const result = validateAuthorizeParams(
      authorizeParams(clientId, pkce().challenge, { redirect_uri: 'https://evil.example/cb' }),
    );

    expect(result).toMatchObject({ ok: false, redirect: false });
  });

  test('never redirects for an unknown client', () => {
    expect(validateAuthorizeParams(authorizeParams('bogus', pkce().challenge))).toMatchObject({
      ok: false,
      redirect: false,
    });
  });

  test('requires S256 PKCE', () => {
    const clientId = register();

    expect(
      validateAuthorizeParams(
        authorizeParams(clientId, pkce().challenge, { code_challenge_method: 'plain' }),
      ),
    ).toMatchObject({ ok: false, redirect: true, error: 'invalid_request', state: 'xyz' });

    const missing = authorizeParams(clientId, '');
    expect(validateAuthorizeParams(missing)).toMatchObject({ ok: false, redirect: true });
  });

  test('requires response_type=code', () => {
    const clientId = register();

    expect(
      validateAuthorizeParams(
        authorizeParams(clientId, pkce().challenge, { response_type: 'token' }),
      ),
    ).toMatchObject({ ok: false, redirect: true, error: 'unsupported_response_type' });
  });
});

describe('exchangeToken', () => {
  function issueCode() {
    const clientId = register();
    const { verifier, challenge } = pkce();
    const validation = validateAuthorizeParams(authorizeParams(clientId, challenge));

    if (!validation.ok) {
      throw new Error('invalid authorize params');
    }

    return { clientId, verifier, code: createAuthorizationCode(validation.params, API_KEY) };
  }

  function exchange(values: Record<string, string>) {
    return exchangeToken(new URLSearchParams(values));
  }

  test('exchanges a code for the approved API key', () => {
    const { clientId, verifier, code } = issueCode();

    expect(
      exchange({
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }),
    ).toEqual({ ok: true, apiKey: API_KEY, clientId });
  });

  test('rejects a wrong PKCE verifier', () => {
    const { clientId, code } = issueCode();

    expect(
      exchange({
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: REDIRECT,
        code_verifier: pkce().verifier,
      }),
    ).toMatchObject({ ok: false, error: 'invalid_grant' });
  });

  test('rejects a code redeemed by another client', () => {
    const { verifier, code } = issueCode();

    expect(
      exchange({
        grant_type: 'authorization_code',
        client_id: register(),
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }),
    ).toMatchObject({ ok: false, error: 'invalid_grant' });
  });

  test('rejects a mismatched redirect_uri', () => {
    const { clientId, verifier, code } = issueCode();

    expect(
      exchange({
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: 'https://claude.ai/other',
        code_verifier: verifier,
      }),
    ).toMatchObject({ ok: false, error: 'invalid_grant' });
  });

  test('rejects expired codes', () => {
    vi.useFakeTimers();
    try {
      const { clientId, verifier, code } = issueCode();
      vi.advanceTimersByTime(301_000);

      expect(
        exchange({
          grant_type: 'authorization_code',
          client_id: clientId,
          code,
          redirect_uri: REDIRECT,
          code_verifier: verifier,
        }),
      ).toMatchObject({ ok: false, error: 'invalid_grant' });
    } finally {
      vi.useRealTimers();
    }
  });

  test('refreshes with a refresh token bound to the client', () => {
    const clientId = register();
    const refreshToken = createRefreshToken(clientId, API_KEY);

    expect(
      exchange({ grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshToken }),
    ).toEqual({ ok: true, apiKey: API_KEY, clientId });

    expect(
      exchange({ grant_type: 'refresh_token', client_id: register(), refresh_token: refreshToken }),
    ).toMatchObject({ ok: false, error: 'invalid_grant' });
  });

  test('rejects unknown clients and grant types', () => {
    expect(exchange({ grant_type: 'authorization_code', client_id: 'bogus' })).toMatchObject({
      ok: false,
      status: 401,
      error: 'invalid_client',
    });
    expect(exchange({ grant_type: 'password', client_id: register() })).toMatchObject({
      ok: false,
      error: 'unsupported_grant_type',
    });
  });

  test('does not accept a code as a refresh token', () => {
    const { clientId, code } = issueCode();

    expect(
      exchange({ grant_type: 'refresh_token', client_id: clientId, refresh_token: code }),
    ).toMatchObject({ ok: false, error: 'invalid_grant' });
  });
});
