import crypto from 'node:crypto';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { checkApiKeyAuth } from '@/lib/auth';
import { registerClient } from '@/lib/mcp/oauth';
import { POST as token } from '../token/route';
import { GET, POST } from './route';

vi.mock('@/lib/auth', () => ({ checkApiKeyAuth: vi.fn() }));

const checkApiKeyAuthMock = vi.mocked(checkApiKeyAuth);
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const API_KEY = 'umami_abcdefghijklmnopqrstuvwxyz123456';
const BASE = 'https://analytics.example.com';

function setup() {
  const registration = registerClient({ redirect_uris: [REDIRECT], client_name: 'Claude <b>' });

  if (!registration.ok) {
    throw new Error('registration failed');
  }

  const clientId = registration.body.client_id as string;
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'abc',
  });

  return { clientId, verifier, params };
}

function submit(params: URLSearchParams, apiKey: string) {
  const body = new URLSearchParams(params);
  body.set('api_key', apiKey);

  return POST(
    new Request(`${BASE}/oauth/authorize`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        host: 'analytics.example.com',
      },
      body: body.toString(),
    }),
  );
}

beforeEach(() => {
  vi.unstubAllEnvs();
  vi.stubEnv('APP_SECRET', 'test-secret-for-oauth');
  vi.stubEnv('MCP_ENABLED', '1');
  vi.stubEnv('CLOUD_MODE', '');
  checkApiKeyAuthMock.mockReset();
});

describe('/oauth/authorize', () => {
  test('is hidden when MCP is disabled', async () => {
    vi.stubEnv('MCP_ENABLED', '');
    const { params } = setup();

    expect((await GET(new Request(`${BASE}/oauth/authorize?${params}`))).status).toBe(404);
  });

  test('renders the consent form with the client name escaped', async () => {
    const { params } = setup();
    const response = await GET(new Request(`${BASE}/oauth/authorize?${params}`));
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(html).toContain('Claude &lt;b&gt;');
    expect(html).toContain('name="api_key"');
    expect(response.headers.get('x-frame-options')).toBe('DENY');
  });

  test('shows an error page, without redirecting, for an unregistered redirect URI', async () => {
    const { params } = setup();
    params.set('redirect_uri', 'https://evil.example/cb');
    const response = await GET(new Request(`${BASE}/oauth/authorize?${params}`));

    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
  });

  test('re-renders the form for an unknown API key', async () => {
    checkApiKeyAuthMock.mockResolvedValue(null);
    const { params } = setup();
    const response = await submit(params, API_KEY);

    expect(response.status).toBe(400);
    expect(await response.text()).toContain('not recognized');
  });

  test('rejects values that are not API keys without a lookup', async () => {
    const { params } = setup();
    const response = await submit(params, 'password123');

    expect(response.status).toBe(400);
    expect(checkApiKeyAuthMock).not.toHaveBeenCalled();
  });

  test('completes the full code flow and refresh', async () => {
    checkApiKeyAuthMock.mockResolvedValue({ user: { id: 'user-1' } } as any);
    const { clientId, verifier, params } = setup();

    const response = await submit(params, ` ${API_KEY} `);
    expect(response.status).toBe(303);

    const location = new URL(response.headers.get('location') as string);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT);
    expect(location.searchParams.get('state')).toBe('abc');
    expect(location.searchParams.get('iss')).toBe(BASE);

    const code = location.searchParams.get('code') as string;
    const tokenResponse = await token(
      new Request(`${BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          code,
          redirect_uri: REDIRECT,
          code_verifier: verifier,
        }).toString(),
      }),
    );
    const tokens = await tokenResponse.json();

    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.headers.get('cache-control')).toBe('no-store');
    expect(tokens).toMatchObject({ access_token: API_KEY, token_type: 'Bearer' });

    const refreshResponse = await token(
      new Request(`${BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: clientId,
          refresh_token: tokens.refresh_token,
        }).toString(),
      }),
    );

    expect(refreshResponse.status).toBe(200);
    expect((await refreshResponse.json()).access_token).toBe(API_KEY);
  });

  test('token endpoint rejects a key that was deleted after approval', async () => {
    checkApiKeyAuthMock.mockResolvedValueOnce({ user: { id: 'user-1' } } as any);
    const { clientId, verifier, params } = setup();
    const location = new URL((await submit(params, API_KEY)).headers.get('location') as string);

    checkApiKeyAuthMock.mockResolvedValueOnce(null);
    const response = await token(
      new Request(`${BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          code: location.searchParams.get('code') as string,
          redirect_uri: REDIRECT,
          code_verifier: verifier,
        }).toString(),
      }),
    );

    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe('invalid_grant');
  });
});
